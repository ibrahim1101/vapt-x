"""Opt-in, explicitly linked OIDC code flow; local MFA and admission stay authoritative."""
import asyncio
import base64
import hashlib
import json
import os
import logging
import secrets
import time
from datetime import timedelta
from urllib.parse import urlencode
import httpx
import jwt
from fastapi import APIRouter,Depends,HTTPException,Request,Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel,Field
from pymongo.errors import DuplicateKeyError
from core import db,now,iso,clean,new_id,sha256_hex,get_current_user
from auth import establish_session,local_cookie_mode,charge_auth_attempt,account_event,renew_credentials
from mfa import Reauthenticate,reauthenticate,consume,version_query
from scanners import resolve_public
from oidc_config import configuration,endpoint

router=APIRouter(prefix='/api/auth/oidc')
SLOTS=asyncio.Semaphore(3)
COOKIE_PATH='/api/auth/oidc'

def config():
    result=configuration(os.environ)
    if result is None:raise HTTPException(503,'Identity provider sign-in is not configured')
    return result

def digest(value):return sha256_hex(value.encode())

def cookie(response,name,value,age=600):
    response.set_cookie(name,value,max_age=age,httponly=True,secure=not local_cookie_mode(),samesite='lax',path=COOKIE_PATH)

def clear_cookie(response,name):response.delete_cookie(name,path=COOKIE_PATH,secure=not local_cookie_mode(),samesite='lax')

async def request_json(url,form=None,limit=262144):
    """Fixed public HTTPS, pinned DNS/Host/SNI, bounded bytes/time, no proxies/redirects."""
    parsed=endpoint(url)
    address=await asyncio.wait_for(resolve_public(parsed.hostname),5)
    address='['+address+']' if ':' in address else address
    target='https://'+address+':443'+(parsed.path or '/')
    async with httpx.AsyncClient(timeout=10,follow_redirects=False,trust_env=False) as client:
        async with client.stream('POST' if form is not None else 'GET',target,data=form,
            headers={'Host':parsed.netloc,'Accept':'application/json'},extensions={'sni_hostname':parsed.hostname}) as response:
            if response.status_code!=200:raise ValueError('Identity provider request failed')
            body=bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body)>limit:raise ValueError('Identity provider response exceeds limit')
    value=json.loads(body)
    if not isinstance(value,dict):raise ValueError('Identity provider response must be an object')
    return value

async def exchange(config,item,code):
    verifier=config['cipher'].decrypt(item['verifier'].encode(),ttl=600).decode()
    tokens=await request_json(config['token_url'],{'grant_type':'authorization_code','code':code,
        'redirect_uri':config['redirect_uri'],'client_id':config['client_id'],'client_secret':config['client_secret'],'code_verifier':verifier},65536)
    raw=tokens.get('id_token')
    if not isinstance(raw,str) or len(raw)>16384:raise ValueError('Missing or oversized ID token')
    keys=await request_json(config['jwks_url'])
    return validate_id_token(raw,keys,config,item['nonce'])

def validate_id_token(raw,jwks,config,nonce):
    header=jwt.get_unverified_header(raw)
    algorithm=header.get('alg')
    if algorithm not in {'RS256','ES256'} or header.get('crit'):raise ValueError('Unsupported ID token algorithm')
    keys=jwks.get('keys')
    if not isinstance(keys,list) or len(keys)>50:raise ValueError('Invalid signing key set')
    matches=[key for key in keys if isinstance(key,dict) and key.get('kid')==header.get('kid')
        and key.get('use','sig')=='sig' and key.get('alg',algorithm)==algorithm and 'verify' in key.get('key_ops',['verify'])]
    if not header.get('kid') or len(matches)!=1:raise ValueError('No unique signing key')
    jwk=matches[0]
    if algorithm=='RS256' and jwk.get('kty')!='RSA':raise ValueError('Wrong signing key type')
    if algorithm=='ES256' and (jwk.get('kty')!='EC' or jwk.get('crv')!='P-256'):raise ValueError('Wrong signing curve')
    key=jwt.PyJWK.from_dict(jwk,algorithm=algorithm).key
    if algorithm=='RS256' and key.key_size<2048:raise ValueError('Weak signing key')
    claims=jwt.decode(raw,key,algorithms=[algorithm],issuer=config['issuer'],audience=config['client_id'],
        options={'require':['iss','sub','aud','exp','iat','nonce']},leeway=30)
    if not isinstance(claims['sub'],str) or not 1<=len(claims['sub'])<=255:raise ValueError('Invalid subject')
    if not isinstance(claims['nonce'],str) or not secrets.compare_digest(claims['nonce'],nonce):raise ValueError('Nonce mismatch')
    audiences=claims['aud']
    if isinstance(audiences,list) and len(audiences)>1 and claims.get('azp')!=config['client_id']:raise ValueError('Authorized party required')
    if 'azp' in claims and claims['azp']!=config['client_id']:raise ValueError('Wrong authorized party')
    if any(isinstance(claims[name],bool) or not isinstance(claims[name],(int,float)) for name in ('iat','exp')):raise ValueError('Invalid token times')
    if not isinstance(claims['iat'],(int,float)) or claims['iat']<time.time()-600:raise ValueError('Stale ID token')
    return claims

@router.get('')
async def availability():return {'enabled':configuration(os.environ) is not None}

@router.get('/link')
async def linked(user=Depends(get_current_user)):
    if user.get('_token_scopes') is not None:raise HTTPException(403,'Use a browser session')
    return {'enabled':configuration(os.environ) is not None,'linked':bool(user.get('oidc_identity')),
        'linked_at':(user.get('oidc_identity') or {}).get('linked_at')}

async def begin(response,user=None):
    cfg=config()
    # Validate the browser destination as well; nothing is sent at startup.
    await asyncio.wait_for(resolve_public(endpoint(cfg['authorization_url']).hostname),5)
    state=secrets.token_urlsafe(32);browser=secrets.token_urlsafe(32);verifier=secrets.token_urlsafe(48);nonce=secrets.token_urlsafe(32)
    await db.oidc_flows.insert_one({'_id':digest(state),'browser_hash':digest(browser),'nonce':nonce,
        'verifier':cfg['cipher'].encrypt(verifier.encode()).decode(),'revision':cfg['revision'],
        'expires_at':now()+timedelta(minutes=10),'used':False,'purpose':'link' if user else 'login',
        'user_id':str(user['_id']) if user else None,'sid':user.get('_sid') if user else None,
        'credential_version':user.get('credential_version',0) if user else None})
    cookie(response,'oidc_browser',browser)
    challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    return {'authorization_url':cfg['authorization_url']+'?'+urlencode({'client_id':cfg['client_id'],
        'redirect_uri':cfg['redirect_uri'],'response_type':'code','scope':'openid','state':state,'nonce':nonce,
        'code_challenge':challenge,'code_challenge_method':'S256','prompt':'select_account'})}

@router.post('/start')
async def start(request:Request,response:Response):
    await charge_auth_attempt('oidc-start',digest(request.client.host if request.client else 'unknown'))
    try:return await begin(response)
    except HTTPException:raise
    except Exception:raise HTTPException(503,'Identity provider sign-in could not start') from None

@router.post('/link/start')
async def link_start(body:Reauthenticate,response:Response,user=Depends(get_current_user)):
    document=await reauthenticate(body,user,require_mfa=bool(user.get('mfa_enabled')))
    if document.get('oidc_identity'):raise HTTPException(409,'Remove the current identity link before linking another')
    document['_sid']=user['_sid']
    try:return await begin(response,document)
    except HTTPException:raise
    except Exception:raise HTTPException(503,'Identity linking could not start') from None

async def fresh_linker(item):
    session=await db.sessions.find_one({'_id':item['sid'],'user_id':item['user_id'],'revoked':False,'expires_at':{'$gt':iso()}})
    user=await db.users.find_one({'_id':item['user_id'],'disabled':{'$ne':True}})
    if not session or not user or session.get('credential_version',0)!=item['credential_version'] or user.get('credential_version',0)!=item['credential_version']:
        raise ValueError('Linking authority changed')
    return user

@router.get('/callback')
async def callback(request:Request):
    response=RedirectResponse(os.environ['FRONTEND_URL'].rstrip('/')+'/#oidc_result=failed',status_code=303)
    clear_cookie(response,'oidc_browser')
    try:
        cfg=config();params=request.query_params
        if any(len(params.getlist(key))!=1 for key in ('state','code')) or params.get('error'):raise ValueError('Invalid callback')
        if 'iss' in params and (len(params.getlist('iss'))!=1 or params['iss']!=cfg['issuer']):raise ValueError('Wrong response issuer')
        state=params['state'];code=params['code'];browser=request.cookies.get('oidc_browser','')
        if not 32<=len(state)<=128 or not 1<=len(code)<=2048 or not 32<=len(browser)<=128:raise ValueError('Invalid correlation')
        item=await db.oidc_flows.find_one_and_update({'_id':digest(state),'browser_hash':digest(browser),
            'revision':cfg['revision'],'used':False,'expires_at':{'$gt':now()}},{'$set':{'used':True}})
        if not item:raise ValueError('Invalid or consumed flow')
        await asyncio.wait_for(SLOTS.acquire(),1)
        try:claims=await asyncio.wait_for(exchange(cfg,item,code),25)
        finally:SLOTS.release()
        if item['purpose']=='link':
            user=await fresh_linker(item)
            identity={'issuer':cfg['issuer'],'subject':claims['sub'],'id':new_id(),'linked_at':iso()}
            changed=await db.users.find_one_and_update({'_id':user['_id'],'disabled':{'$ne':True},
                'oidc_identity':{'$exists':False},**version_query(user)},
                {'$set':{'oidc_identity':identity},'$inc':{'credential_version':1}})
            if not changed:raise ValueError('Identity already linked or credentials changed')
            user['oidc_identity']=identity;user['credential_version']=user.get('credential_version',0)+1
            await renew_credentials(user,response)
            await account_event(str(user['_id']),'identity.linked')
            result='linked'
        else:
            user=await db.users.find_one({'oidc_identity.issuer':cfg['issuer'],'oidc_identity.subject':claims['sub'],'disabled':{'$ne':True}})
            if not user:raise ValueError('Identity is not explicitly linked')
            raw=secrets.token_urlsafe(32)
            await db.oidc_challenges.insert_one({'_id':digest(raw),'user_id':str(user['_id']),
                'identity_id':user['oidc_identity']['id'],'credential_version':user.get('credential_version',0),
                'revision':cfg['revision'],'used':False,'expires_at':now()+timedelta(minutes=5)})
            cookie(response,'oidc_pending',raw,300)
            response.set_cookie('csrf',secrets.token_urlsafe(32),max_age=604800,httponly=False,
                secure=not local_cookie_mode(),samesite='lax',path='/')
            result='pending'
        response.headers['location']=os.environ['FRONTEND_URL'].rstrip('/')+'/#oidc_result='+result
    except Exception:
        # Never echo provider errors, codes, tokens, subjects, client secrets or PII.
        pass
    return response

async def pending(request):
    cfg=config();raw=request.cookies.get('oidc_pending','')
    if not 32<=len(raw)<=128:raise HTTPException(401,'Identity sign-in expired. Start again.')
    item=await db.oidc_challenges.find_one({'_id':digest(raw),'used':False,'revision':cfg['revision'],'expires_at':{'$gt':now()}})
    if not item:raise HTTPException(401,'Identity sign-in expired. Start again.')
    user=await db.users.find_one({'_id':item['user_id'],'disabled':{'$ne':True},'oidc_identity.id':item['identity_id']})
    if not user or user.get('credential_version',0)!=item['credential_version']:raise HTTPException(401,'Account credentials changed. Start again.')
    return item,user

@router.get('/pending')
async def pending_status(request:Request):
    _,user=await pending(request)
    return {'email':user['email'],'mfa_required':bool(user.get('mfa_enabled'))}

class Completion(BaseModel):mfa_code:str=Field(default='',max_length=64)

@router.post('/complete')
async def complete(body:Completion,request:Request,response:Response):
    item,user=await pending(request)
    await charge_auth_attempt('oidc-complete',str(user['_id']))
    if user.get('mfa_enabled'):
        user=await consume(user,body.mfa_code)
        if not user:raise HTTPException(401,'A valid, unused authenticator or recovery code is required')
    claimed=await db.oidc_challenges.find_one_and_update({'_id':item['_id'],'used':False,'expires_at':{'$gt':now()}},{'$set':{'used':True}})
    if not claimed:raise HTTPException(401,'Identity sign-in already completed. Start again.')
    clear_cookie(response,'oidc_pending')
    await account_event(str(user['_id']),'identity.signed_in')
    return await establish_session(clean(user),response)

@router.post('/unlink')
async def unlink(body:Reauthenticate,response:Response,user=Depends(get_current_user)):
    document=await reauthenticate(body,user,require_mfa=bool(user.get('mfa_enabled')))
    if not document.get('oidc_identity'):raise HTTPException(409,'No identity is linked')
    changed=await db.users.find_one_and_update({'_id':document['_id'],'disabled':{'$ne':True},
        'oidc_identity.id':document['oidc_identity']['id'],**version_query(document)},
        {'$unset':{'oidc_identity':''},'$inc':{'credential_version':1}})
    if not changed:raise HTTPException(409,'Credentials changed. Reload before retrying.')
    document.pop('oidc_identity');document['credential_version']=document.get('credential_version',0)+1
    await account_event(str(document['_id']),'identity.unlinked')
    await renew_credentials(document,response)
    return {'ok':True}


class CallbackLogFilter(logging.Filter):
    def filter(self,record):
        # Uvicorn's access args contain (client, method, path, version, status).
        if isinstance(record.args,tuple) and len(record.args)==5 and isinstance(record.args[2],str) and record.args[2].split('?',1)[0]=='/api/auth/oidc/callback':
            args=list(record.args);args[2]='/api/auth/oidc/callback';record.args=tuple(args)
        return True

logging.getLogger('uvicorn.access').addFilter(CallbackLogFilter())
