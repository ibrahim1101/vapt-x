"""Explicit deployment admission policy; defaults preserve existing deployments."""
import hashlib
import os
from datetime import datetime,timezone
from fastapi import HTTPException

LIMITED_ACCOUNT_PATHS={
    '/api/auth/me','/api/auth/logout','/api/auth/password','/api/auth/security-events',
    '/api/auth/email-verification','/api/auth/email-verification/request',
    '/api/auth/invitations','/api/auth/invitations/preview',
}

def validate_environment(env):
    mode=env.get('REGISTRATION_MODE','open')
    required=env.get('REQUIRE_VERIFIED_EMAIL','0')
    if mode not in {'open','invite_only','closed'}:raise ValueError('REGISTRATION_MODE must be open, invite_only or closed')
    if required not in {'0','1'}:raise ValueError('REQUIRE_VERIFIED_EMAIL must be 0 or 1')
    if mode=='invite_only' and env.get('ORG_INVITATIONS_ENABLED')!='1':raise ValueError('Invite-only registration requires ORG_INVITATIONS_ENABLED=1')
    if required=='1' and env.get('EMAIL_VERIFICATION_ENABLED')!='1':raise ValueError('Required email verification requires EMAIL_VERIFICATION_ENABLED=1')

def policy():
    return {'registration_mode':os.environ.get('REGISTRATION_MODE','open'),
            'require_verified_email':os.environ.get('REQUIRE_VERIFIED_EMAIL','0')=='1'}

def email_verified(user):
    return bool(user.get('email_verified_at') and user.get('email_verified_address')==user.get('email'))

def enforce_workspace_policy(user,path):
    if not policy()['require_verified_email'] or email_verified(user):return
    # Unverified browser sessions can only reach their own recovery/verification
    # controls. They cannot enroll MFA, mint tokens, create/join organizations or
    # access platform/domain data. Existing bearer tokens do not bypass policy.
    safe=path in LIMITED_ACCOUNT_PATHS or path=='/api/auth/sessions' or path.startswith('/api/auth/sessions/')
    if user.get('_token_scopes') is None and safe:return
    raise HTTPException(403,{'code':'email_verification_required','message':'Verify your registered email before accessing this workspace.'})

async def allow_registration(database,email,invitation_token):
    mode=policy()['registration_mode']
    if mode=='open':return
    if mode=='closed':raise HTTPException(403,'Self-registration is closed. Contact your operator.')
    if mode!='invite_only':raise HTTPException(503,'Registration policy is not configured correctly')
    if os.environ.get('ORG_INVITATIONS_ENABLED')!='1' or not invitation_token:
        raise HTTPException(403,'Registration requires a valid invitation for this email address')
    item=await database.invitations.find_one({'token_hash':hashlib.sha256(invitation_token.encode()).hexdigest(),
        'email':email,'status':'pending','expires_at':{'$gt':datetime.now(timezone.utc)}})
    if not item:raise HTTPException(403,'Registration requires a valid invitation for this email address')
    issuer=await database.users.find_one({'_id':item['created_by'],'disabled':{'$ne':True}})
    membership=await database.memberships.find_one({'_id':item['issuer_membership_id'],'org_id':item['org_id'],
        'user_id':item['created_by'],'role':'org_admin'})
    if not issuer or not membership or issuer.get('credential_version',0)!=item['issuer_credential_version']:
        raise HTTPException(403,'Invitation authority changed. Request a new invitation.')
    if not await database.organizations.find_one({'_id':item['org_id']}):raise HTTPException(403,'Invitation is no longer available')
    # Registration creates an account only. Acceptance rechecks authority and
    # requires its own explicit action; the invitation is not consumed here.
