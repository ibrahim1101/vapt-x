"""Opt-in password recovery; raw reset tokens exist only in memory and delivery."""
import asyncio
import logging
import os
import secrets
import smtplib
import ssl
from datetime import timedelta
from email.message import EmailMessage
from urllib.parse import urlencode
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr, Field, TypeAdapter, field_validator
from pymongo import ReturnDocument
from pymongo.errors import PyMongoError
from core import db, now, iso, sha256_hex, hash_password, verify_password
from auth import charge_auth_attempt, account_event
from mfa import consume, version_query

router = APIRouter(prefix='/api/auth/recovery')
NOTICE = 'If an eligible account matches that email, recovery instructions will be sent. Check your inbox and spam folder.'
MAIL_SLOTS = asyncio.Semaphore(3)
INVALID = 'The recovery link is invalid, expired or already used. Request a new link.'

def mail_configuration():
    if os.environ.get('ACCOUNT_RECOVERY_ENABLED') != '1': return None
    host = os.environ.get('RECOVERY_SMTP_HOST','').strip()
    mode = os.environ.get('RECOVERY_SMTP_MODE','ssl')
    if not host or any(c.isspace() for c in host) or mode not in {'ssl','starttls'}:
        raise ValueError('Recovery SMTP requires a host and ssl or starttls mode')
    try:
        port = int(os.environ.get('RECOVERY_SMTP_PORT','465' if mode=='ssl' else '587'))
        sender = str(TypeAdapter(EmailStr).validate_python(os.environ.get('RECOVERY_SMTP_FROM','')))
        if not 1 <= port <= 65535: raise ValueError()
    except (ValueError,TypeError): raise ValueError('Recovery SMTP requires a valid port and sender address') from None
    username = os.environ.get('RECOVERY_SMTP_USERNAME','')
    password = os.environ.get('RECOVERY_SMTP_PASSWORD','')
    if bool(username) != bool(password): raise ValueError('Recovery SMTP username and password must be configured together')
    return {'host':host,'port':port,'mode':mode,'sender':sender,'username':username,'password':password}

def require_configuration():
    try: config = mail_configuration()
    except ValueError: config = None
    if config is None: raise HTTPException(503,'Password recovery is not configured. Contact your operator.')
    return config

def send_mail(config, recipient, link):
    message = EmailMessage()
    message['From'] = config['sender'];message['To'] = recipient
    message['Subject'] = 'VAPT-X password recovery'
    message.set_content('Use this one-time link within 15 minutes to choose a new password. '
                        'An enabled authenticator or recovery code is still required.\n\n'+link+
                        '\n\nIf you did not request this, ignore this email. No password has changed.')
    context = ssl.create_default_context()
    connection = smtplib.SMTP_SSL(config['host'],config['port'],timeout=10,context=context) if config['mode']=='ssl' else smtplib.SMTP(config['host'],config['port'],timeout=10)
    with connection as smtp:
        if config['mode']=='starttls': smtp.ehlo();smtp.starttls(context=context);smtp.ehlo()
        if config['username']: smtp.login(config['username'],config['password'])
        smtp.send_message(message)

class RecoveryRequest(BaseModel):
    email: EmailStr

class RecoveryCompletion(BaseModel):
    token: str = Field(min_length=32,max_length=128)
    new_password: str = Field(min_length=10,max_length=72)
    mfa_code: str = Field(default='',max_length=64)
    @field_validator('new_password')
    @classmethod
    def byte_limit(cls,value):
        if len(value.encode())>72: raise ValueError('Password must not exceed 72 UTF-8 bytes')
        return value

@router.get('')
async def availability():
    try: enabled = mail_configuration() is not None
    except ValueError: enabled = False
    return {'enabled':enabled,'notice':'Recovery requires configured TLS mail delivery and preserves enabled MFA. It does not sign you in automatically.'}

@router.post('/request',status_code=202)
async def request_recovery(body: RecoveryRequest):
    config = require_configuration()
    email = str(body.email).lower()
    await charge_auth_attempt('recovery-request',sha256_hex(email.encode()))
    user = await db.users.find_one({'email':email,'disabled':{'$ne':True}})
    if user:
        token = secrets.token_urlsafe(32)
        digest = sha256_hex(token.encode())
        await db.account_recovery.insert_one({'token_hash':digest,'user_id':str(user['_id']),
            'email':email,'credential_version':user.get('credential_version',0),
            'expires_at':now()+timedelta(minutes=15),'used_at':None})
        link = os.environ['FRONTEND_URL'].rstrip('/')+'/#'+urlencode({'reset_token':token})
        acquired = False
        try:
            await asyncio.wait_for(MAIL_SLOTS.acquire(),timeout=1)
            acquired = True
            await asyncio.to_thread(send_mail,config,email,link)
        except Exception:
            # Never log recipient, body, token, SMTP credentials or provider exception text.
            await db.account_recovery.delete_one({'token_hash':digest})
            logging.getLogger(__name__).warning('Recovery mail delivery failed')
        finally:
            if acquired: MAIL_SLOTS.release()
    return {'notice':NOTICE}

@router.post('/complete')
async def complete_recovery(body: RecoveryCompletion):
    require_configuration()
    digest = sha256_hex(body.token.encode())
    token = await db.account_recovery.find_one({'token_hash':digest,'used_at':None,'expires_at':{'$gt':now()}})
    if not token: raise HTTPException(400,INVALID)
    await charge_auth_attempt('recovery-complete',digest)
    user = await db.users.find_one({'_id':token['user_id'],'email':token['email'],'disabled':{'$ne':True}})
    if not user or user.get('credential_version',0)!=token['credential_version']: raise HTTPException(400,INVALID)
    if verify_password(body.new_password,user['password_hash']): raise HTTPException(422,'Choose a different password')
    if user.get('mfa_enabled'):
        user = await consume(user,body.mfa_code)
        if not user: raise HTTPException(403,'A valid, unused authenticator or recovery code is required')
    claimed = await db.account_recovery.find_one_and_update(
        {'token_hash':digest,'used_at':None,'expires_at':{'$gt':now()}},
        {'$set':{'used_at':now()}},return_document=ReturnDocument.AFTER)
    if not claimed: raise HTTPException(400,INVALID)
    changed = await db.users.find_one_and_update(
        {'_id':token['user_id'],'email':token['email'],'disabled':{'$ne':True},
         'password_hash':user['password_hash'],**version_query(user)},
        {'$set':{'password_hash':hash_password(body.new_password),'password_changed_at':iso()},
         '$inc':{'credential_version':1}},return_document=ReturnDocument.AFTER)
    if not changed: raise HTTPException(409,INVALID)
    # Epoch checks invalidate even credentials inserted by requests already in flight.
    old = {'$or':[{'credential_version':{'$exists':False}},{'credential_version':{'$lt':changed['credential_version']}}]}
    try:
        await db.sessions.update_many({'user_id':token['user_id'],'revoked':False,**old},{'$set':{'revoked':True}})
        await db.api_tokens.update_many({'created_by':token['user_id'],'revoked':False,**old},{'$set':{'revoked':True,'revoked_at':iso()}})
    except PyMongoError: logging.getLogger(__name__).warning('Recovery credential cleanup deferred; epoch invalidation remains authoritative')
    await account_event(token['user_id'],'password.reset')
    return {'notice':'Password reset. Previous sessions and API tokens are invalidated. Sign in with your new password and MFA if enabled.'}
