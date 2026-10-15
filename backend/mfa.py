"""Opt-in RFC 6238 TOTP with encrypted secrets and atomic one-use claims."""
import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from datetime import timedelta
from urllib.parse import quote, urlencode
from cryptography.fernet import Fernet, MultiFernet
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field, field_validator
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError
from core import db, get_current_user, iso, now, clean, sha256_hex, verify_password

router = APIRouter(prefix='/api/auth/mfa')

def cipher():
    keys=[key.strip() for key in os.environ.get('MFA_ENCRYPTION_KEYS','').split(',') if key.strip()]
    if not keys: raise ValueError('MFA encryption is not configured')
    return MultiFernet([Fernet(key.encode()) for key in keys])

def configured():
    try: cipher(); return True
    except (ValueError, TypeError): return False

def totp(secret, counter, digits=6):
    """RFC 4226 dynamic truncation; RFC 6238 uses floor(unix_time/30)."""
    key=base64.b32decode(secret, casefold=True)
    digest=hmac.new(key, struct.pack('>Q',counter), hashlib.sha1).digest()
    offset=digest[-1]&15
    value=struct.unpack('>I',digest[offset:offset+4])[0]&0x7fffffff
    return str(value % 10**digits).zfill(digits)

def matching_counter(secret, code, timestamp=None):
    if len(code)!=6 or not code.isascii() or not code.isdigit(): return None
    current=int(time.time() if timestamp is None else timestamp)//30
    for counter in (current,current-1,current+1):
        if counter>=0 and hmac.compare_digest(totp(secret,counter),code): return counter
    return None

def version_query(document):
    version=document.get('credential_version',0)
    return {'credential_version':version} if version else {'$or':[{'credential_version':0},{'credential_version':{'$exists':False}}]}

def recovery_codes():
    codes=[secrets.token_hex(16) for _ in range(10)]
    return codes,[sha256_hex(code.encode()) for code in codes]

async def consume(document, code, charged=False):
    """Return post-claim user; replay/concurrent losers cannot mint a session."""
    if not charged: await charge_attempt(str(document['_id']))
    code=code.strip()
    query={'_id':document['_id'],'mfa_enabled':True,'mfa_secret':document.get('mfa_secret'),**version_query(document)}
    if len(code)==32 and all(c in '0123456789abcdefABCDEF' for c in code):
        digest=sha256_hex(code.lower().encode())
        query['mfa_recovery_hashes']=digest
        return await db.users.find_one_and_update(query,{'$pull':{'mfa_recovery_hashes':digest}},return_document=ReturnDocument.AFTER)
    try: secret=cipher().decrypt(document['mfa_secret'].encode()).decode()
    except Exception: raise HTTPException(503,'Authenticator key unavailable. Use a recovery code or contact your operator.')
    counter=matching_counter(secret,code)
    if counter is None or counter<=document.get('mfa_last_counter',-1): return None
    query['mfa_last_counter']=document.get('mfa_last_counter',-1)
    return await db.users.find_one_and_update(query,{'$set':{'mfa_last_counter':counter}},return_document=ReturnDocument.AFTER)

class Reauthenticate(BaseModel):
    current_password:str=Field(min_length=10,max_length=72)
    mfa_code:str=Field(default='',max_length=64)
    @field_validator('current_password')
    @classmethod
    def byte_limit(cls,value):
        if len(value.encode())>72: raise ValueError('Password must not exceed 72 UTF-8 bytes')
        return value
class Confirmation(BaseModel):
    code:str=Field(min_length=6,max_length=6,pattern=r'^[0-9]{6}$')

async def charge_attempt(user_id):
    # Atomic fixed-window budget, including parallel requests and multiple API workers.
    instant=now()
    claimed=await db.mfa_attempts.find_one_and_update(
        {'_id':user_id,'expires_at':{'$gt':instant},'count':{'$lt':10}},
        {'$inc':{'count':1}},return_document=ReturnDocument.AFTER)
    if claimed: return
    try:
        await db.mfa_attempts.find_one_and_update(
            {'_id':user_id,'expires_at':{'$lte':instant}},
            {'$set':{'count':1,'expires_at':instant+timedelta(minutes=15)}},upsert=True)
    except DuplicateKeyError:
        raise HTTPException(429,'Too many attempts. Try again in 15 minutes.')


async def reauthenticate(body,user,require_mfa=False):
    if user.get('_token_scopes') is not None: raise HTTPException(403,'Use a browser session to manage MFA')
    await charge_attempt(user['id'])
    document=await db.users.find_one({'_id':user['id']})
    if not document or document.get('credential_version',0)!=user.get('credential_version',0):
        raise HTTPException(401,'Credentials changed. Sign in again.')
    if not verify_password(body.current_password,document['password_hash']): raise HTTPException(403,'Invalid current password or authentication code')
    if require_mfa:
        if not document.get('mfa_enabled'): raise HTTPException(409,'MFA is not enabled')
        document=await consume(document,body.mfa_code,charged=True)
        if not document: raise HTTPException(403,'Invalid or already-used authentication code')
    return document

@router.get('')
async def state(user=Depends(get_current_user)):
    if user.get('_token_scopes') is not None: raise HTTPException(403,'Use a browser session to manage MFA')
    document=await db.users.find_one({'_id':user['id']})
    if not document: raise HTTPException(401,'Account unavailable')
    return {'configured':configured(),'enabled':bool(document.get('mfa_enabled')),
        'recovery_codes_remaining':len(document.get('mfa_recovery_hashes',[]))}

@router.post('/setup')
async def setup(body:Reauthenticate,user=Depends(get_current_user)):
    document=await reauthenticate(body,user)
    if document.get('mfa_enabled'): raise HTTPException(409,'MFA is already enabled')
    if not configured(): raise HTTPException(503,'Operator must configure MFA_ENCRYPTION_KEYS before enrollment')
    secret=base64.b32encode(secrets.token_bytes(20)).decode()
    pending={'secret':cipher().encrypt(secret.encode()).decode(),'session_id':user['_sid'],
        'expires_at':iso(now()+timedelta(minutes=10))}
    result=await db.users.update_one({'_id':document['_id'],'password_hash':document['password_hash'],
        'mfa_enabled':{'$ne':True},**version_query(document)}, {'$set':{'mfa_pending':pending}})
    if not result.matched_count: raise HTTPException(409,'Credentials changed; start setup again')
    uri='otpauth://totp/'+quote('VAPT-X:'+document['email'],safe='')+'?'+urlencode({'secret':secret,'issuer':'VAPT-X','algorithm':'SHA1','digits':6,'period':30})
    return {'secret':secret,'otpauth_uri':uri,'expires_at':pending['expires_at'],
        'notice':'Add the manual key to your authenticator, then confirm a code within 10 minutes. Enrollment is not active yet.'}

@router.post('/confirm')
async def confirm(body:Confirmation,response:Response,user=Depends(get_current_user)):
    if user.get('_token_scopes') is not None: raise HTTPException(403,'Use a browser session to manage MFA')
    await charge_attempt(user['id'])
    document=await db.users.find_one({'_id':user['id']})
    pending=(document or {}).get('mfa_pending',{})
    if not document or document.get('credential_version',0)!=user.get('credential_version',0) or document.get('mfa_enabled') or pending.get('session_id')!=user['_sid'] or pending.get('expires_at','')<=iso():
        raise HTTPException(409,'Setup expired or changed. Start again.')
    try: secret=cipher().decrypt(pending['secret'].encode()).decode()
    except Exception: raise HTTPException(503,'Authenticator encryption key unavailable')
    counter=matching_counter(secret,body.code)
    if counter is None: raise HTTPException(403,'Invalid authentication code')
    codes,hashes=recovery_codes()
    changed=await db.users.find_one_and_update({'_id':document['_id'],'mfa_pending':pending,
        'mfa_enabled':{'$ne':True},**version_query(document)},
        {'$set':{'mfa_enabled':True,'mfa_secret':pending['secret'],'mfa_last_counter':counter,
                 'mfa_recovery_hashes':hashes,'mfa_enabled_at':iso()},'$unset':{'mfa_pending':''},'$inc':{'credential_version':1}},
        return_document=ReturnDocument.AFTER)
    if not changed: raise HTTPException(409,'Setup changed. Start again.')
    await finish(changed,response,'mfa.enabled')
    return {'enabled':True,'recovery_codes':codes,'notice':'Save these one-use recovery codes now. Previous sessions and API tokens are invalidated. Wait for a new authenticator code before using it again.'}

async def finish(document,response,action):
    from auth import renew_credentials, account_event
    await renew_credentials(document,response)
    await db.mfa_attempts.delete_one({'_id':str(document['_id'])})
    await account_event(str(document['_id']),action)

@router.post('/disable')
async def disable(body:Reauthenticate,response:Response,user=Depends(get_current_user)):
    document=await reauthenticate(body,user,True)
    changed=await db.users.find_one_and_update({'_id':document['_id'],'mfa_secret':document['mfa_secret'],
        'mfa_enabled':True,**version_query(document)},
        {'$set':{'mfa_enabled':False},'$unset':{'mfa_secret':'','mfa_pending':'','mfa_recovery_hashes':'','mfa_last_counter':''},'$inc':{'credential_version':1}},return_document=ReturnDocument.AFTER)
    if not changed: raise HTTPException(409,'Credentials changed; reload settings')
    await finish(changed,response,'mfa.disabled')
    return {'enabled':False,'notice':'MFA disabled. Previous sessions and API tokens are invalidated.'}

@router.post('/recovery-codes')
async def regenerate(body:Reauthenticate,response:Response,user=Depends(get_current_user)):
    document=await reauthenticate(body,user,True)
    codes,hashes=recovery_codes()
    changed=await db.users.find_one_and_update({'_id':document['_id'],'mfa_secret':document['mfa_secret'],
        'mfa_enabled':True,**version_query(document)},
        {'$set':{'mfa_recovery_hashes':hashes},'$inc':{'credential_version':1}},return_document=ReturnDocument.AFTER)
    if not changed: raise HTTPException(409,'Credentials changed; reload settings')
    await finish(changed,response,'mfa.recovery_codes_replaced')
    return {'enabled':True,'recovery_codes':codes,'notice':'Shown once. All previous recovery codes, sessions and API tokens are invalidated.'}
