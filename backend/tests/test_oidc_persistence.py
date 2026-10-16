"""Disposable Mongo and synthetic signed provider responses; no live identity requests."""
import os,subprocess,sys,textwrap,unittest
@unittest.skipUnless(os.environ.get('MONGO_TEST_URL'),'Set MONGO_TEST_URL to a disposable MongoDB server')
class OIDCPersistenceTests(unittest.TestCase):
 def test_link_local_mfa_atomic_completion_epoch_and_unlink(self):
  code=textwrap.dedent('''
   import os,uuid,json,time,hashlib
   from concurrent.futures import ThreadPoolExecutor
   from urllib.parse import urlsplit,parse_qs,urlencode
   from unittest.mock import patch,AsyncMock
   from cryptography.fernet import Fernet
   from cryptography.hazmat.primitives.asymmetric import rsa
   from pymongo import MongoClient
   from fastapi.testclient import TestClient
   import jwt,httpx
   database='vaptx_oidc_'+uuid.uuid4().hex;encryption=Fernet.generate_key().decode()
   os.environ.update(MONGO_URL=os.environ['MONGO_TEST_URL'],DB_NAME=database,JWT_SECRET='synthetic-oidc-'*5,
    ADMIN_EMAIL='owner@example.com',ADMIN_PASSWORD='synthetic-owner-password',FRONTEND_URL='http://localhost:3000',
    INTERNAL_API_URL='http://127.0.0.1:8001',NMAP_BINARY='nmap',VAPTX_LOCAL_HTTP='1',
    OIDC_ENABLED='1',OIDC_ISSUER='https://identity.example.com',OIDC_AUTHORIZATION_URL='https://identity.example.com/authorize',
    OIDC_TOKEN_URL='https://identity.example.com/token',OIDC_JWKS_URL='https://identity.example.com/keys',
    OIDC_CLIENT_ID='synthetic-client',OIDC_CLIENT_SECRET='synthetic-secret',OIDC_ENCRYPTION_KEYS=encryption,MFA_ENCRYPTION_KEYS=encryption)
   from server import app
   from core import decode_token
   key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
   jwk=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()));jwk.update(kid='synthetic',alg='RS256',use='sig')
   mongo=MongoClient(os.environ['MONGO_TEST_URL']);current={};subject='synthetic-subject'
   async def provider(url,form=None,limit=262144):
    if url.endswith('/keys'):return {'keys':[jwk]}
    assert form['code_verifier'] and form['client_secret']=='synthetic-secret'
    flow=mongo[database].oidc_flows.find_one({'_id':hashlib.sha256(current['state'][0].encode()).hexdigest()})
    verifier=Fernet(encryption.encode()).decrypt(flow['verifier'].encode()).decode()
    assert form['code_verifier']==verifier
    return {'id_token':jwt.encode({'iss':os.environ['OIDC_ISSUER'],'sub':subject,'aud':'synthetic-client',
      'iat':int(time.time()),'exp':int(time.time())+300,'nonce':current['nonce'][0]},key,algorithm='RS256',headers={'kid':'synthetic'})}
   try:
    with patch('oidc.resolve_public',new_callable=AsyncMock,return_value='93.184.216.34'),patch('oidc.request_json',side_effect=provider),TestClient(app) as client:
     origin={'origin':'http://localhost:3000'}
     def headers():return {**origin,'x-csrf-token':client.cookies.get('csrf') or ''}
     def begin(path='/api/auth/oidc/start',body=None):
      result=client.post(path,headers=headers(),json=body or {})
      assert result.status_code==200,result.text
      current.clear();current.update(parse_qs(urlsplit(result.json()['authorization_url']).query))
      return '/api/auth/oidc/callback?'+urlencode({'state':current['state'][0],'code':'synthetic-code','iss':os.environ['OIDC_ISSUER']})
     def callback(url):return client.get(url,follow_redirects=False)
     account=client.post('/api/auth/register',headers=origin,json={'email':'linked@example.com','password':'synthetic-password'}).json();uid=account['id']
     old=client.cookies.get('access_token')
     recovery=['a'*32,'b'*32,'c'*32,'d'*32]
     mongo[database].users.update_one({'_id':uid},{'$set':{'mfa_enabled':True,'mfa_secret':Fernet(encryption.encode()).encrypt(b'JBSWY3DPEHPK3PXP').decode(),
      'mfa_recovery_hashes':[hashlib.sha256(code.encode()).hexdigest() for code in recovery],'mfa_last_counter':-1}})
     invalid=client.post('/api/auth/oidc/link/start',headers=headers(),json={'current_password':'synthetic-password'})
     assert invalid.status_code==403,invalid.text
     target=begin('/api/auth/oidc/link/start',{'current_password':'synthetic-password','mfa_code':recovery[0]})
     linked=callback(target);assert linked.headers['location'].endswith('linked'),linked.headers
     stored=mongo[database].users.find_one({'_id':uid});assert stored['oidc_identity']['subject']==subject and stored['credential_version']==1
     assert 'nonce' not in str(stored) and stored['mfa_enabled'] is True
     assert client.get('/api/auth/me',headers={'cookie':'access_token='+old}).status_code==401
     assert callback(target).headers['location'].endswith('failed')
     owner_cookies=httpx.Cookies(client.cookies)
     second=client.post('/api/auth/register',headers=origin,json={'email':'second@example.com','password':'synthetic-password'}).json()
     collision=begin('/api/auth/oidc/link/start',{'current_password':'synthetic-password'})
     assert callback(collision).headers['location'].endswith('failed')
     assert mongo[database].users.find_one({'_id':second['id']}).get('oidc_identity') is None
     assert mongo[database].users.find_one({'_id':uid})['oidc_identity']['subject']==subject
     client.cookies.clear();client.cookies.update(owner_cookies)
     client.post('/api/auth/logout',headers=headers());client.cookies.clear()
     target=begin();pending=callback(target);assert pending.headers['location'].endswith('pending'),pending.headers
     assert client.get('/api/auth/me').status_code==401
     assert client.get('/api/auth/oidc/pending').json()['mfa_required'] is True
     assert client.post('/api/auth/oidc/complete',headers=origin,json={}).status_code==403
     assert client.post('/api/auth/oidc/complete',headers=headers(),json={'mfa_code':'wrong'}).status_code==401
     finished=client.post('/api/auth/oidc/complete',headers=headers(),json={'mfa_code':recovery[1]})
     assert finished.status_code==200,finished.text
     assert client.post('/api/auth/oidc/complete',headers=headers(),json={'mfa_code':recovery[2]}).status_code==401
     # Start another proof, then change epoch: pending proof cannot mint credentials.
     target=begin();assert callback(target).headers['location'].endswith('pending')
     mongo[database].users.update_one({'_id':uid},{'$inc':{'credential_version':1}})
     assert client.post('/api/auth/oidc/complete',headers=headers(),json={'mfa_code':recovery[2]}).status_code==401
     login=client.post('/api/auth/login',headers=origin,json={'email':'linked@example.com','password':'synthetic-password','mfa_code':recovery[2]})
     assert login.status_code==200,login.text
     # Concurrent completion without MFA still grants exactly one local session.
     mongo[database].users.update_one({'_id':uid},{'$set':{'mfa_enabled':False}})
     target=begin();assert callback(target).headers['location'].endswith('pending')
     correlation='oidc_pending='+client.cookies.get('oidc_pending')+'; csrf='+client.cookies.get('csrf')
     concurrent_headers={**origin,'cookie':correlation,'x-csrf-token':client.cookies.get('csrf') or ''}
     with ThreadPoolExecutor(max_workers=2) as pool:
      outcomes=list(pool.map(lambda _:client.post('/api/auth/oidc/complete',headers=concurrent_headers,json={}).status_code,range(2)))
     assert sorted(outcomes)==[200,401],outcomes
     # Required proof applies even after successful identity authentication.
     with patch.dict(os.environ,{'REQUIRE_VERIFIED_EMAIL':'1'}):
      assert client.get('/api/auth/me').json()['verification_required'] is True
      denied=client.get('/api/projects');assert denied.status_code==403 and denied.json()['detail']['code']=='email_verification_required'
     mongo[database].users.update_one({'_id':uid},{'$set':{'mfa_enabled':True}})
     # Removing an identity stays available after operator disables OIDC.
     old=client.cookies.get('access_token')
     with patch.dict(os.environ,{'OIDC_ENABLED':'0'}):
      assert client.get('/api/auth/oidc/link').json()['linked'] is True
      removed=client.post('/api/auth/oidc/unlink',headers=headers(),json={'current_password':'synthetic-password','mfa_code':recovery[3]})
      assert removed.status_code==200,removed.text
     assert mongo[database].users.find_one({'_id':uid}).get('oidc_identity') is None
     assert client.get('/api/auth/me',headers={'cookie':'access_token='+old}).status_code==401
     target=begin()
     assert client.post('/api/auth/oidc/cancel',headers=headers()).status_code==200
     assert callback(target).headers['location'].endswith('failed')
     target=begin();assert callback(target).headers['location'].endswith('failed')
     assert mongo[database].users.count_documents({'email':'linked@example.com'})==1
     assert mongo[database].account_events.count_documents({'user_id':uid,'action':'identity.linked'})==1
     assert mongo[database].account_events.count_documents({'user_id':uid,'action':'identity.unlinked'})==1
   finally:
    mongo.drop_database(database);mongo.close()
  ''')
  result=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,timeout=90)
  self.assertEqual(result.returncode,0,result.stdout+result.stderr)
