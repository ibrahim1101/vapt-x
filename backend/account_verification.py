"""Optional proof of registered-email control; no sign-in or role grant."""
import asyncio
import logging
import os
import secrets
from datetime import timedelta
from urllib.parse import urlencode
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from pymongo import ReturnDocument
from core import db, get_current_user, now, iso, sha256_hex
from auth import charge_auth_attempt, account_event
from mfa import version_query
from account_recovery import mail_configuration, send_message, MAIL_SLOTS

router=APIRouter(prefix='/api/auth/email-verification')
INVALID='The email verification link is invalid, expired or already used. Request a new link.'

def configuration():
    try: return mail_configuration('EMAIL_VERIFICATION_ENABLED')
    except ValueError: return None

def require_configuration():
    config=configuration()
    if config is None: raise HTTPException(503,'Email verification is not configured. Contact your operator.')
    return config

def verified(document):
    return bool(document.get('email_verified_at') and document.get('email_verified_address')==document.get('email'))

def browser_only(user):
    if user.get('_token_scopes') is not None: raise HTTPException(403,'Use a browser session to manage email verification')

def send_verification_mail(config,recipient,link):
    send_message(config,recipient,'Verify your VAPT-X email address',
        'Use this one-time link within 24 hours to verify your registered email address. '
        'This does not sign you in or change your permissions.\n\n'+link+
        '\n\nIf you did not request this, ignore this email.')

@router.get('')
async def status(user=Depends(get_current_user)):
    browser_only(user)
    return {'email':user['email'],'verified':verified(user),'enabled':configuration() is not None,
            'notice':'Verification records control of your registered email. It does not change organization roles or enforce a new sign-in policy.'}

@router.post('/request',status_code=202)
async def request_verification(user=Depends(get_current_user)):
    browser_only(user)
    config=require_configuration()
    await charge_auth_attempt('email-verification-request',user['id'])
    if verified(user): return {'notice':'Your registered email is already verified.'}
    token=secrets.token_urlsafe(32);digest=sha256_hex(token.encode())
    await db.email_verifications.insert_one({'token_hash':digest,'user_id':user['id'],'email':user['email'],
        'credential_version':user.get('credential_version',0),'expires_at':now()+timedelta(hours=24),'used_at':None})
    link=os.environ['FRONTEND_URL'].rstrip('/')+'/#'+urlencode({'verify_email_token':token})
    acquired=False
    try:
        await asyncio.wait_for(MAIL_SLOTS.acquire(),timeout=1);acquired=True
        await asyncio.to_thread(send_verification_mail,config,user['email'],link)
    except Exception:
        await db.email_verifications.delete_one({'token_hash':digest})
        logging.getLogger(__name__).warning('Verification mail delivery failed')
        raise HTTPException(503,'Verification mail could not be sent. Try again later.') from None
    finally:
        if acquired: MAIL_SLOTS.release()
    return {'notice':'Verification instructions were sent to your registered email. Check your inbox and spam folder.'}

class Confirmation(BaseModel):
    token:str=Field(min_length=32,max_length=128)

@router.post('/confirm')
async def confirm_verification(body:Confirmation):
    require_configuration()
    digest=sha256_hex(body.token.encode())
    token=await db.email_verifications.find_one({'token_hash':digest,'used_at':None,'expires_at':{'$gt':now()}})
    if not token: raise HTTPException(400,INVALID)
    await charge_auth_attempt('email-verification-confirm',digest)
    user=await db.users.find_one({'_id':token['user_id'],'email':token['email'],'disabled':{'$ne':True}})
    if not user or user.get('credential_version',0)!=token['credential_version']:raise HTTPException(400,INVALID)
    claimed=await db.email_verifications.find_one_and_update(
        {'token_hash':digest,'used_at':None,'expires_at':{'$gt':now()}},{'$set':{'used_at':now()}},return_document=ReturnDocument.AFTER)
    if not claimed: raise HTTPException(400,INVALID)
    changed=await db.users.find_one_and_update(
        {'_id':token['user_id'],'email':token['email'],'disabled':{'$ne':True},**version_query(user)},
        {'$set':{'email_verified_address':token['email'],'email_verified_at':iso()}},return_document=ReturnDocument.AFTER)
    if not changed: raise HTTPException(409,INVALID)
    await account_event(token['user_id'],'email.verified')
    return {'notice':'Email verified. Sign in normally to continue; organization permissions are unchanged.'}
