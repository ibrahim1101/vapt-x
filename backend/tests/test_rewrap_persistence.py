"""Operator command acceptance on a disposable database only."""
import os,subprocess,sys,textwrap,unittest
@unittest.skipUnless(os.environ.get('MONGO_TEST_URL'),'Set MONGO_TEST_URL to a disposable MongoDB server')
class RewrapPersistenceTests(unittest.TestCase):
 def test_command_dry_run_apply_idempotency_and_fail_closed(self):
  code=textwrap.dedent('''
   import os,sys,uuid,json,subprocess
   from datetime import datetime,timezone,timedelta
   from cryptography.fernet import Fernet,InvalidToken
   from pymongo import MongoClient
   database='vaptx_rewrap_'+uuid.uuid4().hex;old_key=Fernet.generate_key();new_key=Fernet.generate_key()
   old=Fernet(old_key);new=Fernet(new_key);original=old.encrypt_at_time(b'synthetic-secret',1234567890).decode()
   env={**os.environ,'MONGO_URL':os.environ['MONGO_TEST_URL'],'DB_NAME':database}
   for key in ('MFA_ENCRYPTION_KEYS','WEBHOOK_ENCRYPTION_KEYS','OIDC_ENCRYPTION_KEYS'):env[key]=new_key.decode()+','+old_key.decode()
   mongo=MongoClient(env['MONGO_URL']);db=mongo[database]
   def run(*flags):
    result=subprocess.run([sys.executable,'rewrap_secrets.py','--purpose','mfa','--purpose','webhook','--purpose','oidc',*flags],env=env,capture_output=True,text=True,timeout=30)
    assert original not in result.stdout and 'synthetic-secret' not in result.stdout and 'private-record-id' not in result.stdout
    return result,json.loads(result.stdout)
   try:
    expiry=datetime.now(timezone.utc)+timedelta(minutes=10)
    db.users.insert_one({'_id':'private-record-id','mfa_secret':original,'credential_version':3,'mfa_pending':{'secret':original,'session_id':'unchanged','expires_at':'unchanged'}})
    db.webhooks.insert_one({'_id':'hook','encrypted_configuration':original,'enabled':True})
    db.oidc_flows.insert_one({'_id':'flow','verifier':original,'expires_at':expiry,'used':False})
    result,summary=run();assert result.returncode==0,result.stderr
    assert summary['mode']=='dry-run' and summary['remaining']==4 and sum(item['updated'] for item in summary['fields'])==0
    assert db.users.find_one({'_id':'private-record-id'})['mfa_secret']==original
    result,summary=run('--apply');assert result.returncode==0,result.stderr
    assert summary['remaining']==0 and sum(item['updated'] for item in summary['fields'])==4
    user=db.users.find_one({'_id':'private-record-id'});hook=db.webhooks.find_one();flow=db.oidc_flows.find_one()
    for cipher in (user['mfa_secret'],user['mfa_pending']['secret'],hook['encrypted_configuration'],flow['verifier']):
     assert new.decrypt(cipher.encode())==b'synthetic-secret' and new.extract_timestamp(cipher.encode())==1234567890
     try:old.decrypt(cipher.encode());raise AssertionError('old key still decrypts updated ciphertext')
     except InvalidToken:pass
    assert user['credential_version']==3 and user['mfa_pending']['session_id']=='unchanged' and hook['enabled'] and not flow['used']
    assert flow['expires_at'].replace(tzinfo=timezone.utc)==expiry.replace(microsecond=expiry.microsecond//1000*1000)
    result,summary=run('--apply');assert result.returncode==0 and sum(item['updated'] for item in summary['fields'])==0
    db.users.insert_one({'_id':'malformed','mfa_secret':'invalid-synthetic-ciphertext'})
    result,summary=run('--apply');assert result.returncode==2 and not summary['ok'] and sum(item['invalid'] for item in summary['fields'])==1
    for key in ('MFA_ENCRYPTION_KEYS','WEBHOOK_ENCRYPTION_KEYS','OIDC_ENCRYPTION_KEYS'):env[key]=new_key.decode()
    db.users.delete_one({'_id':'malformed'})
    result,summary=run();assert result.returncode==0 and summary['remaining']==0 and summary['ok']
   finally:
    mongo.drop_database(database);mongo.close()
  ''')
  result=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,timeout=90)
  self.assertEqual(result.returncode,0,result.stdout+result.stderr)
