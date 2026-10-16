"""Rotation preserves plaintext, TTL and concurrent changes; summaries reveal counts only."""
import unittest
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock,patch
from cryptography.fernet import Fernet,MultiFernet,InvalidToken
import rewrap_secrets as rotation

class Cursor:
 def __init__(self,rows):self.rows=rows
 def sort(self,*args):return self
 def batch_size(self,size):self.size=size;return self
 def __aiter__(self):return self.iterate()
 async def iterate(self):
  for row in self.rows:yield deepcopy(row)
class Collection:
 def __init__(self,rows):self.rows=rows;self.calls=[];self.conflict=False
 def find(self,query,projection):return Cursor([row for row in self.rows if rotation.nested(row,next(iter(query))) is not None])
 async def update_one(self,query,change):
  self.calls.append((query,change))
  if self.conflict:return SimpleNamespace(modified_count=0)
  for row in self.rows:
   if row['_id']==query['_id']:
    field=next(key for key in query if key!='_id')
    if rotation.nested(row,field)!=query[field]:return SimpleNamespace(modified_count=0)
    target=row;parts=field.split('.')
    for part in parts[:-1]:target=target[part]
    target[parts[-1]]=change['$set'][field];return SimpleNamespace(modified_count=1)
  return SimpleNamespace(modified_count=0)
class RewrapTests(unittest.IsolatedAsyncioTestCase):
 def setUp(self):
  self.old=Fernet(Fernet.generate_key());self.new=Fernet(Fernet.generate_key())
  self.rings={purpose:(self.new,MultiFernet([self.new,self.old])) for purpose in rotation.PURPOSES}
 async def test_dry_run_does_not_write_or_reveal_values(self):
  cipher=self.old.encrypt(b'PRIVATE-SECRET').decode();collection=Collection([{'_id':'PRIVATE-ID','mfa_secret':cipher}])
  result=await rotation.rewrap({'users':collection},['mfa'],self.rings)
  self.assertEqual(collection.calls,[]);self.assertEqual(result['fields'][0]['would_update'],1)
  for secret in ('PRIVATE-SECRET','PRIVATE-ID',cipher):self.assertNotIn(secret,str(result))
 async def test_apply_preserves_timestamp_plaintext_metadata_and_is_idempotent(self):
  timestamp=1234567890;encrypted=self.old.encrypt_at_time(b'PRIVATE',timestamp).decode()
  users=Collection([{'_id':'u','credential_version':4,'mfa_secret':encrypted,'mfa_pending':{'secret':encrypted,'session_id':'s','expires_at':'unchanged'}}])
  hooks=Collection([{'_id':'h','encrypted_configuration':encrypted,'enabled':True}]);flows=Collection([{'_id':'f','verifier':encrypted,'used':False,'expires_at':'unchanged'}])
  database={'users':users,'webhooks':hooks,'oidc_flows':flows}
  result=await rotation.rewrap(database,list(rotation.PURPOSES),self.rings,apply=True)
  self.assertTrue(result['ok']);self.assertEqual(sum(row['updated'] for row in result['fields']),4)
  for cipher in (users.rows[0]['mfa_secret'],users.rows[0]['mfa_pending']['secret'],hooks.rows[0]['encrypted_configuration'],flows.rows[0]['verifier']):
   self.assertEqual(self.new.decrypt(cipher.encode()),b'PRIVATE');self.assertEqual(self.new.extract_timestamp(cipher.encode()),timestamp)
   with self.assertRaises(InvalidToken):self.old.decrypt(cipher.encode())
  self.assertEqual(users.rows[0]['credential_version'],4);self.assertEqual(users.rows[0]['mfa_pending']['session_id'],'s');self.assertTrue(hooks.rows[0]['enabled']);self.assertFalse(flows.rows[0]['used'])
  second=await rotation.rewrap(database,list(rotation.PURPOSES),self.rings,apply=True)
  self.assertEqual(sum(row['updated'] for row in second['fields']),0);self.assertEqual(sum(row['current'] for row in second['fields']),4)
 async def test_conflicts_and_invalid_ciphertext_are_visible_without_overwrite(self):
  cipher=self.old.encrypt(b'PRIVATE').decode();collection=Collection([{'_id':'u','mfa_secret':cipher},{'_id':'bad','mfa_secret':'INVALID-PRIVATE'}]);collection.conflict=True
  result=await rotation.rewrap({'users':collection},['mfa'],self.rings,apply=True)
  self.assertFalse(result['ok']);self.assertEqual(result['fields'][0]['conflicts'],1);self.assertEqual(result['fields'][0]['invalid'],1);self.assertEqual(collection.rows[0]['mfa_secret'],cipher)
  query,update=collection.calls[0];self.assertEqual(query,{'_id':'u','mfa_secret':cipher});self.assertEqual(set(update),{'$set'})
 def test_selected_key_rings_and_explicit_apply_arguments(self):
  args=rotation.arguments(['--purpose','mfa']);self.assertFalse(args.apply)
  self.assertTrue(rotation.arguments(['--purpose','webhook','--apply']).apply)
  for env in ({},{'MFA_ENCRYPTION_KEYS':'INVALID-PRIVATE'}):
   with self.assertRaises(ValueError):rotation.keyrings(['mfa'],env)
  self.assertIn('mfa',rotation.keyrings(['mfa'],{'MFA_ENCRYPTION_KEYS':Fernet.generate_key().decode()}))
 def test_failure_output_never_echoes_database_or_key_values(self):
  with patch.object(rotation,'execute',new_callable=AsyncMock,side_effect=ValueError('PRIVATE-URI-KEY')),patch('sys.stderr') as stderr:
   self.assertEqual(rotation.main(['--purpose','mfa']),2);self.assertNotIn('PRIVATE-URI-KEY',str(stderr.write.call_args_list))
