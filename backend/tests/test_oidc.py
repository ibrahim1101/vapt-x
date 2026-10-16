"""OIDC validation/account boundaries, with no live provider."""
import base64,json,logging,time,unittest
from unittest.mock import AsyncMock,patch
import test_projects
import jwt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException,Response
from starlette.requests import Request
import oidc
from oidc_config import configuration
ENV={'OIDC_ENABLED':'1','OIDC_ISSUER':'https://identity.example.com','OIDC_AUTHORIZATION_URL':'https://identity.example.com/authorize',
'OIDC_TOKEN_URL':'https://identity.example.com/token','OIDC_JWKS_URL':'https://identity.example.com/keys','OIDC_CLIENT_ID':'synthetic-client',
'OIDC_CLIENT_SECRET':'synthetic-secret','OIDC_ENCRYPTION_KEYS':Fernet.generate_key().decode(),'FRONTEND_URL':'http://localhost:3000'}
def request(path='/api/auth/oidc/complete',cookies='',query=''):
 return Request({'type':'http','path':path,'query_string':query.encode(),'headers':[(b'cookie',cookies.encode())],'client':('127.0.0.1',1234)})
class ValidationTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
  cls.jwk=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.key.public_key()));cls.jwk.update(kid='synthetic',use='sig',alg='RS256')
 def test_configuration(self):
  self.assertIsNone(configuration({}))
  for updates in ({'OIDC_ENABLED':'yes'},{'OIDC_CLIENT_SECRET':''},{'OIDC_ENCRYPTION_KEYS':'invalid'},{'OIDC_ISSUER':'http://localhost:9000'},
   {'OIDC_TOKEN_URL':'https://secret:password@example.com/token'},{'OIDC_AUTHORIZATION_URL':'https://example.com/auth?redirect_uri=evil'},{'OIDC_JWKS_URL':'https://example.com:444/keys'}):
   with self.subTest(updates=updates),self.assertRaises(ValueError):configuration({**ENV,**updates})
 def claims(self):return {'iss':ENV['OIDC_ISSUER'],'sub':'subject','aud':ENV['OIDC_CLIENT_ID'],'iat':int(time.time()),'exp':int(time.time())+300,'nonce':'nonce'}
 def token(self,claims=None,key=None,**headers):return jwt.encode(claims or self.claims(),key or self.key,algorithm='RS256',headers={'kid':'synthetic',**headers})
 def test_signature_claim_nonce_audience_algorithm_validation(self):
  cfg=configuration(ENV)
  self.assertEqual(oidc.validate_id_token(self.token(),{'keys':[self.jwk]},cfg,'nonce')['sub'],'subject')
  updates=[{'iss':'https://evil.example.com'},{'aud':'other'},{'nonce':'wrong'},{'exp':int(time.time())-100},{'iat':int(time.time())-700},
   {'iat':int(time.time())+300},{'sub':''},{'sub':'s'*256},{'aud':[ENV['OIDC_CLIENT_ID'],'other']},{'azp':'other'},{'iat':True}]
  for update in updates:
   with self.subTest(update=update),self.assertRaises((ValueError,jwt.PyJWTError)):oidc.validate_id_token(self.token({**self.claims(),**update}),{'keys':[self.jwk]},cfg,'nonce')
  wrong=rsa.generate_private_key(public_exponent=65537,key_size=2048)
  for token in (self.token(key=wrong),jwt.encode(self.claims(),'synthetic-hmac',algorithm='HS256',headers={'kid':'synthetic'}),self.token(crit=['unknown'])):
   with self.assertRaises((ValueError,jwt.PyJWTError)):oidc.validate_id_token(token,{'keys':[self.jwk]},cfg,'nonce')
  for keys in ([],[self.jwk,self.jwk],[{**self.jwk,'use':'enc'}],[{**self.jwk,'key_ops':['encrypt']}]):
   with self.assertRaises(ValueError):oidc.validate_id_token(self.token(),{'keys':keys},cfg,'nonce')
  claims={**self.claims(),'aud':[ENV['OIDC_CLIENT_ID'],'other'],'azp':ENV['OIDC_CLIENT_ID']}
  self.assertEqual(oidc.validate_id_token(self.token(claims),{'keys':[self.jwk]},cfg,'nonce')['sub'],'subject')
 def test_es256_and_weak_rsa_key_rejection(self):
  from cryptography.hazmat.primitives.asymmetric import ec
  key=ec.generate_private_key(ec.SECP256R1());jwk=json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()));jwk.update(kid='ec',alg='ES256')
  token=jwt.encode(self.claims(),key,algorithm='ES256',headers={'kid':'ec'})
  self.assertEqual(oidc.validate_id_token(token,{'keys':[jwk]},configuration(ENV),'nonce')['sub'],'subject')
  weak=rsa.generate_private_key(public_exponent=65537,key_size=1024);jwk=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(weak.public_key()));jwk.update(kid='synthetic',alg='RS256')
  with self.assertRaises(ValueError):oidc.validate_id_token(self.token(key=weak),{'keys':[jwk]},configuration(ENV),'nonce')
 def test_callback_access_logging_removes_queries(self):
  record=logging.LogRecord('uvicorn.access',20,'',1,'%s %s %s %s %s',('client','GET','/api/auth/oidc/callback?code=SECRET&state=PRIVATE','1.1',303),None)
  oidc.CallbackLogFilter().filter(record);self.assertNotIn('SECRET',record.getMessage());self.assertNotIn('PRIVATE',record.getMessage())
class FlowTests(unittest.IsolatedAsyncioTestCase):
 async def test_begin_hashes_state_encrypts_verifier_and_uses_pkce(self):
  from urllib.parse import urlsplit,parse_qs
  with patch.dict('os.environ',ENV),patch.object(oidc,'db') as db,patch.object(oidc,'resolve_public',new_callable=AsyncMock,return_value='93.184.216.34'):
   db.oidc_flows.insert_one=AsyncMock();response=Response();result=await oidc.begin(response,{'_id':'owner','_sid':'session','credential_version':2})
   params=parse_qs(urlsplit(result['authorization_url']).query);item=db.oidc_flows.insert_one.call_args.args[0]
   self.assertEqual(item['_id'],oidc.digest(params['state'][0]));self.assertNotIn(params['state'][0],str(item));self.assertEqual(item['sid'],'session')
   verifier=configuration(ENV)['cipher'].decrypt(item['verifier'].encode()).decode();self.assertNotIn(verifier,str(item))
   self.assertEqual(params['code_challenge_method'],['S256']);self.assertEqual(params['scope'],['openid'])
   self.assertEqual(params['code_challenge'][0],base64.urlsafe_b64encode(__import__('hashlib').sha256(verifier.encode()).digest()).rstrip(b'=').decode())
   self.assertIn('HttpOnly',response.headers['set-cookie'])
 async def test_invalid_correlation_never_exchanges(self):
  with patch.dict('os.environ',ENV),patch.object(oidc,'db') as db,patch.object(oidc,'exchange',new_callable=AsyncMock) as exchange:
   db.oidc_flows.find_one_and_update=AsyncMock(return_value=None)
   for query in ('state=x&code=PRIVATE','state='+'s'*43+'&code=a&code=b','state='+'s'*43+'&code=PRIVATE'):
    response=await oidc.callback(request('/api/auth/oidc/callback','oidc_browser='+'b'*43,query))
    self.assertTrue(response.headers['location'].endswith('failed'));self.assertNotIn('PRIVATE',str(response.headers))
   exchange.assert_not_awaited()
 async def test_unlinked_subject_cannot_match_email_or_create_account(self):
  with patch.dict('os.environ',ENV),patch.object(oidc,'db') as db,patch.object(oidc,'exchange',new_callable=AsyncMock,return_value={'sub':'unlinked','email':'owner@example.com'}):
   db.oidc_flows.find_one_and_update=AsyncMock(return_value={'purpose':'login'});db.users.find_one=AsyncMock(return_value=None)
   response=await oidc.callback(request('/api/auth/oidc/callback','oidc_browser='+'b'*43,'state='+'s'*43+'&code=private'))
   self.assertTrue(response.headers['location'].endswith('failed'));query=db.users.find_one.call_args.args[0]
   self.assertEqual(query['oidc_identity.subject'],'unlinked');self.assertNotIn('email',query);db.users.insert_one.assert_not_called();db.oidc_challenges.insert_one.assert_not_called()
 async def test_pending_rejects_unlinked_disabled_or_stale_epoch(self):
  with patch.dict('os.environ',ENV),patch.object(oidc,'db') as db:
   db.oidc_challenges.find_one=AsyncMock(return_value={'user_id':'u','identity_id':'link','credential_version':2})
   for user in (None,{'credential_version':3}):
    db.users.find_one=AsyncMock(return_value=user)
    with self.assertRaises(HTTPException):await oidc.pending(request(cookies='oidc_pending='+'p'*43))
   self.assertEqual(db.users.find_one.call_args.args[0],{'_id':'u','disabled':{'$ne':True},'oidc_identity.id':'link'})
 async def test_mfa_and_one_use_claim_precede_session_creation(self):
  user={'_id':'u','mfa_enabled':True}
  with patch.object(oidc,'pending',new_callable=AsyncMock,return_value=({'_id':'challenge'},user)),patch.object(oidc,'db') as db,patch.object(oidc,'consume',new_callable=AsyncMock) as consume,patch.object(oidc,'charge_auth_attempt',new_callable=AsyncMock),patch.object(oidc,'establish_session',new_callable=AsyncMock) as establish,patch.object(oidc,'account_event',new_callable=AsyncMock):
   consume.return_value=None
   with self.assertRaises(HTTPException):await oidc.complete(oidc.Completion(mfa_code='bad'),request(),Response())
   db.oidc_challenges.find_one_and_update.assert_not_called();establish.assert_not_awaited()
   consume.return_value=user;db.oidc_challenges.find_one_and_update=AsyncMock(return_value=None)
   with self.assertRaises(HTTPException):await oidc.complete(oidc.Completion(mfa_code='used'),request(),Response())
   establish.assert_not_awaited();db.oidc_challenges.find_one_and_update.return_value={'claimed':True}
   await oidc.complete(oidc.Completion(mfa_code='valid'),request(),Response());establish.assert_awaited_once()
 async def test_linking_requires_current_session_and_epoch(self):
  item={'sid':'s','user_id':'u','credential_version':2}
  with patch.object(oidc,'db') as db:
   db.sessions.find_one=AsyncMock(return_value={'credential_version':2});db.users.find_one=AsyncMock(return_value={'credential_version':3})
   with self.assertRaises(ValueError):await oidc.fresh_linker(item)
   db.users.find_one.return_value={'credential_version':2};self.assertEqual(await oidc.fresh_linker(item),{'credential_version':2})
   db.sessions.find_one.return_value=None
   with self.assertRaises(ValueError):await oidc.fresh_linker(item)

class TransportTests(unittest.IsolatedAsyncioTestCase):
 async def test_public_dns_pinning_tls_identity_and_response_bounds(self):
  import httpx
  original=httpx.AsyncClient;requests=[]
  async def handler(request):
   requests.append(request)
   return httpx.Response(200,json={'keys':[]})
  def client(**kwargs):
   self.assertFalse(kwargs['trust_env']);self.assertFalse(kwargs['follow_redirects'])
   return original(**kwargs,transport=httpx.MockTransport(handler))
  with patch.object(oidc,'resolve_public',new_callable=AsyncMock,return_value='93.184.216.34'),patch.object(oidc.httpx,'AsyncClient',side_effect=client):
   self.assertEqual(await oidc.request_json('https://identity.example.com/keys'),{'keys':[]})
   self.assertEqual(requests[0].url.host,'93.184.216.34');self.assertEqual(requests[0].headers['host'],'identity.example.com')
   self.assertEqual(requests[0].extensions['sni_hostname'],'identity.example.com')
   with self.assertRaises(ValueError):await oidc.request_json('https://identity.example.com/keys',limit=2)
  with patch.object(oidc,'resolve_public',new_callable=AsyncMock,side_effect=ValueError('private')):
   with self.assertRaises(ValueError):await oidc.request_json('https://identity.example.com/keys')
