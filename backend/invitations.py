"""Optional email-bound invitations coordinated by renewable Mongo membership leases."""
import asyncio
import logging
import os
import re
import secrets
from datetime import timedelta,timezone
from typing import Literal
from urllib.parse import urlencode
from fastapi import APIRouter,Depends,HTTPException,Query
from pydantic import BaseModel,EmailStr,Field
from pymongo import ReturnDocument
from pymongo.errors import PyMongoError
from core import db,get_ctx,get_current_user,Ctx,new_id,now,iso,sha256_hex,audit
from auth import membership_lock,charge_auth_attempt,account_event
from account_recovery import mail_configuration,send_message,MAIL_SLOTS
from repository import Repository

router=APIRouter(prefix='/api')
INVALID='Invitation is invalid, expired, revoked or no longer authorized. Ask the organization administrator for a new invitation.'

def configuration():
    try:return mail_configuration('ORG_INVITATIONS_ENABLED')
    except ValueError:return None

def require_configuration():
    config=configuration()
    if config is None:raise HTTPException(503,'Organization invitations are not configured. Contact your operator.')
    return config

async def administrator(ctx):
    ctx.require('members')
    if ctx.scopes is not None:raise HTTPException(403,'Use a browser session to manage invitations')
    membership=await db.memberships.find_one({'org_id':ctx.org_id,'user_id':ctx.uid,'role':'org_admin'})
    user=await db.users.find_one({'_id':ctx.uid,'disabled':{'$ne':True}})
    if not membership or not user or user.get('credential_version',0)!=ctx.user.get('credential_version',0):
        raise HTTPException(403,'Administrator authority changed; reload your workspace')
    return membership,user

def metadata(row):
    result={key:row.get(key) for key in ('id','email','role','status','created_at','expires_at','accepted_at')}
    expiry=row.get('expires_at')
    if result['status']=='pending' and expiry and expiry.replace(tzinfo=timezone.utc)<=now():result['status']='expired'
    return result

def send_invitation_mail(config,recipient,link):
    send_message(config,recipient,'VAPT-X organization invitation',
        'An organization administrator invited this email address to VAPT-X. '
        'Sign in or register with this address, then explicitly accept the invitation within seven days. '
        'Existing memberships and MFA are preserved.\n\n'+link+'\n\nIf unexpected, ignore this email. No access is granted until acceptance.')

class InvitationInput(BaseModel):
    email:EmailStr
    role:Literal['org_admin','security_lead','analyst','auditor','viewer']='viewer'
class Acceptance(BaseModel):
    token:str=Field(min_length=32,max_length=128)

@router.get('/auth/invitations')
async def invitation_status(user=Depends(get_current_user)):
    if user.get('_token_scopes') is not None:raise HTTPException(403,'Use a browser session to manage invitations')
    return {'enabled':configuration() is not None}

@router.get('/invitations')
async def list_invitations(search:str=Query(default='',max_length=120),
    status:Literal['pending','expired','accepting','accepted','revoked','failed']|None=None,
    offset:int=Query(default=0,ge=0,le=1_000_000),limit:int=Query(default=25,ge=1,le=100),ctx=Depends(get_ctx)):
    await administrator(ctx)
    filters={}
    if search.strip():filters['email']={'$regex':re.escape(search.strip()),'$options':'i'}
    if status:
        filters['status']='pending' if status=='expired' else status
        if status in {'pending','expired'}:filters['expires_at']={'$gt' if status=='pending' else '$lte':now()}
    allowed=('email','role','status','created_at','expires_at','accepted_at','org_id','created_by')
    page=await Repository(ctx).page('invitations',filters,offset=offset,limit=limit,projection={key:1 for key in allowed})
    return {**page,'items':[metadata(row) for row in page['items']],'enabled':configuration() is not None,
            'notice':'Invitations expire after seven days and require the issuing administrator’s current authority. Existing roles are never overwritten by acceptance.'}

@router.post('/invitations',status_code=202)
async def create_invitation(body:InvitationInput,ctx=Depends(get_ctx)):
    ctx.require('members');config=require_configuration()
    await charge_auth_attempt('invitation-send',ctx.uid)
    async with membership_lock(ctx.org_id):
        member,issuer=await administrator(ctx)
        recipient=str(body.email).lower()
        target=await db.users.find_one({'email':recipient})
        if target and await db.memberships.find_one({'org_id':ctx.org_id,'user_id':str(target['_id'])}):
            raise HTTPException(409,'This account already belongs to the organization; use membership management for role changes')
        token=secrets.token_urlsafe(32)
        item=await Repository(ctx).add('invitations',{'email':recipient,'role':body.role,'status':'pending',
            'token_hash':sha256_hex(token.encode()),'issuer_membership_id':str(member['_id']),
            'issuer_credential_version':issuer.get('credential_version',0),'expires_at':now()+timedelta(days=7)},log=False)
    acquired=False
    try:
        await asyncio.wait_for(MAIL_SLOTS.acquire(),timeout=1);acquired=True
        await asyncio.to_thread(send_invitation_mail,config,recipient,os.environ['FRONTEND_URL'].rstrip('/')+'/#'+urlencode({'invite_token':token}))
    except Exception:
        await db.invitations.update_one({'_id':item['id'],'org_id':ctx.org_id,'status':'pending'},{'$set':{'status':'failed'}})
        logging.getLogger(__name__).warning('Invitation mail delivery failed')
        raise HTTPException(503,'Invitation mail could not be sent. Try creating a new invitation later.') from None
    finally:
        if acquired:MAIL_SLOTS.release()
    await audit(ctx,'invitation.created','invitations',item['id'],{'role':body.role})
    return metadata(item)

@router.post('/invitations/{invitation_id}/revoke')
async def revoke_invitation(invitation_id:str,ctx=Depends(get_ctx)):
    async with membership_lock(ctx.org_id):
        await administrator(ctx)
        item=await Repository(ctx).get('invitations',invitation_id)
        if item['status']!='pending':raise HTTPException(409,'Only pending invitations can be revoked')
        changed=await db.invitations.update_one({'_id':invitation_id,'org_id':ctx.org_id,'status':'pending'},{'$set':{'status':'revoked','revoked_at':iso()}})
        if not changed.modified_count:raise HTTPException(409,'Invitation state changed; reload the register')
        await audit(ctx,'invitation.revoked','invitations',invitation_id)
    return {'notice':'Invitation revoked. Its link cannot grant access.'}

async def valid_invitation(body,user):
    item=await db.invitations.find_one({'token_hash':sha256_hex(body.token.encode()),'status':'pending','expires_at':{'$gt':now()}})
    if not item:raise HTTPException(400,INVALID)
    if item['email']!=user['email']:raise HTTPException(403,'Sign in with the email address that received this invitation')
    recipient=await db.users.find_one({'_id':user['id'],'email':item['email'],'disabled':{'$ne':True}})
    issuer=await db.users.find_one({'_id':item['created_by'],'disabled':{'$ne':True}})
    authority=await db.memberships.find_one({'_id':item['issuer_membership_id'],'org_id':item['org_id'],'user_id':item['created_by'],'role':'org_admin'})
    if not recipient or recipient.get('credential_version',0)!=user.get('credential_version',0) or not issuer or not authority or issuer.get('credential_version',0)!=item['issuer_credential_version']:
        raise HTTPException(400,INVALID)
    organization=await db.organizations.find_one({'_id':item['org_id']})
    if not organization:raise HTTPException(400,INVALID)
    return item,organization

@router.post('/auth/invitations/preview')
async def preview_invitation(body:Acceptance,user=Depends(get_current_user)):
    if user.get('_token_scopes') is not None:raise HTTPException(403,'Use a browser session to inspect invitations')
    require_configuration()
    await charge_auth_attempt('invitation-preview',user['id'])
    item,organization=await valid_invitation(body,user)
    return {'organization_name':organization['name'],'role':item['role'],'email':item['email'],'expires_at':item['expires_at']}

@router.post('/auth/invitations/accept')
async def accept_invitation(body:Acceptance,user=Depends(get_current_user)):
    if user.get('_token_scopes') is not None:raise HTTPException(403,'Use a browser session to accept invitations')
    require_configuration()
    await charge_auth_attempt('invitation-accept',user['id'])
    hint,_=await valid_invitation(body,user)
    async with membership_lock(hint['org_id']):
        item,organization=await valid_invitation(body,user)
        existing=await db.memberships.find_one({'org_id':item['org_id'],'user_id':user['id']})
        claimed=await db.invitations.find_one_and_update({'_id':item['_id'],'status':'pending','expires_at':{'$gt':now()}},
            {'$set':{'status':'accepting','used_at':now()}},return_document=ReturnDocument.AFTER)
        if not claimed:raise HTTPException(400,INVALID)
        try:
            if not existing:await db.memberships.insert_one({'_id':new_id(),'org_id':item['org_id'],'user_id':user['id'],'role':item['role']})
            await db.invitations.update_one({'_id':item['_id']},{'$set':{'status':'accepted','accepted_at':iso()}})
        except PyMongoError:
            logging.getLogger(__name__).warning('Invitation membership write incomplete; administrator review required')
            raise HTTPException(503,'Membership write could not be confirmed. Reload your account and contact the administrator.') from None
        ctx=Ctx(user,item['org_id'],existing['role'] if existing else item['role'])
        await audit(ctx,'invitation.accepted','invitations',str(item['_id']),{'role':ctx.role,'existing_membership':bool(existing)})
        await account_event(user['id'],'invitation.accepted')
    return {'org_id':item['org_id'],'notice':'Organization access is available. Existing membership roles were preserved.'}
