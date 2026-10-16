"""One operator-configured confidential OIDC client; no dynamic discovery."""
import hashlib
import json
from urllib.parse import urlsplit
from cryptography.fernet import Fernet,MultiFernet

def endpoint(value):
    if not isinstance(value,str) or not value or len(value)>1500 or any(ord(c)<33 or ord(c)==127 for c in value):
        raise ValueError('OIDC endpoints must be fixed HTTPS URLs')
    parsed=urlsplit(value)
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.port not in {None,443}:
        raise ValueError('OIDC endpoints require HTTPS port 443 without credentials, query or fragment')
    return parsed

def configuration(env):
    flag=env.get('OIDC_ENABLED','0')
    if flag not in {'0','1'}:raise ValueError('OIDC_ENABLED must be 0 or 1')
    if flag=='0':return None
    names=('OIDC_ISSUER','OIDC_AUTHORIZATION_URL','OIDC_TOKEN_URL','OIDC_JWKS_URL','OIDC_CLIENT_ID','OIDC_CLIENT_SECRET','OIDC_ENCRYPTION_KEYS')
    if any(not env.get(key) for key in names):raise ValueError('Enabled OIDC requires issuer, fixed endpoints, client credentials and encryption keys')
    for key in names[:4]:endpoint(env[key])
    for key in ('OIDC_CLIENT_ID','OIDC_CLIENT_SECRET'):
        if len(env[key])>2000 or any(ord(c)<32 or ord(c)==127 for c in env[key]):raise ValueError('Invalid OIDC client credential format')
    keys=[key.strip() for key in env['OIDC_ENCRYPTION_KEYS'].split(',') if key.strip()]
    try:cipher=MultiFernet([Fernet(key.encode()) for key in keys])
    except (ValueError,TypeError):raise ValueError('Invalid OIDC encryption keys') from None
    frontend=env.get('FRONTEND_URL','').rstrip('/')
    if not frontend:raise ValueError('OIDC requires FRONTEND_URL')
    return {'issuer':env['OIDC_ISSUER'],'authorization_url':env['OIDC_AUTHORIZATION_URL'],
        'token_url':env['OIDC_TOKEN_URL'],'jwks_url':env['OIDC_JWKS_URL'],'client_id':env['OIDC_CLIENT_ID'],
        'client_secret':env['OIDC_CLIENT_SECRET'],'redirect_uri':frontend+'/api/auth/oidc/callback','cipher':cipher,
        'revision':hashlib.sha256(json.dumps({key:env[key] for key in names if key!='OIDC_ENCRYPTION_KEYS'},sort_keys=True).encode()+frontend.encode()).hexdigest()}
