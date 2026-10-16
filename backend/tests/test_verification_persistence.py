"""Email proof is tested with disposable Mongo and mocked mail only."""
import os
import subprocess
import sys
import textwrap
import unittest

@unittest.skipUnless(os.environ.get('MONGO_TEST_URL'),'Set MONGO_TEST_URL to a disposable MongoDB server')
class VerificationPersistenceTests(unittest.TestCase):
    def test_concurrent_confirmation_address_binding_expiry_and_epoch(self):
        code=textwrap.dedent('''
            import os,uuid,hashlib
            from datetime import datetime,timedelta,timezone
            from concurrent.futures import ThreadPoolExecutor
            from urllib.parse import urlsplit,parse_qs
            from unittest.mock import patch
            from pymongo import MongoClient
            from fastapi.testclient import TestClient
            database='vaptx_email_'+uuid.uuid4().hex
            os.environ.update(MONGO_URL=os.environ['MONGO_TEST_URL'],DB_NAME=database,JWT_SECRET='synthetic-verification-'*4,
                ADMIN_EMAIL='owner@example.com',ADMIN_PASSWORD='synthetic-owner-password',FRONTEND_URL='http://localhost:3000',
                INTERNAL_API_URL='http://127.0.0.1:8001',NMAP_BINARY='nmap',VAPTX_LOCAL_HTTP='1',
                ACCOUNT_RECOVERY_ENABLED='0',EMAIL_VERIFICATION_ENABLED='1',RECOVERY_SMTP_HOST='smtp.synthetic.invalid',RECOVERY_SMTP_FROM='operator@example.com')
            from server import app
            mongo=MongoClient(os.environ['MONGO_TEST_URL'],serverSelectionTimeoutMS=5000);links=[]
            try:
                with patch('account_verification.send_verification_mail',side_effect=lambda config,email,link:links.append(link)),TestClient(app) as client:
                    origin={'origin':'http://localhost:3000'}
                    def headers():return {**origin,'x-csrf-token':client.cookies.get('csrf')}
                    def token():return parse_qs(urlsplit(links[-1]).fragment)['verify_email_token'][0]
                    first=client.post('/api/auth/register',headers=origin,json={'email':'first@example.com','password':'synthetic-password'}).json()
                    assert client.get('/api/auth/email-verification').json()['verified'] is False
                    assert client.post('/api/auth/email-verification/request',headers=origin).status_code==403
                    assert client.post('/api/auth/email-verification/request',headers=headers()).status_code==202
                    raw=token();stored=mongo[database].email_verifications.find_one({'user_id':first['id']})
                    assert stored['token_hash']==hashlib.sha256(raw.encode()).hexdigest() and raw not in str(stored)
                    second=client.post('/api/auth/register',headers=origin,json={'email':'second@example.com','password':'synthetic-password'}).json()
                    with patch.dict(os.environ,{'EMAIL_VERIFICATION_ENABLED':'0'}):
                        assert client.post('/api/auth/email-verification/confirm',headers=origin,json={'token':raw}).status_code==503
                    with ThreadPoolExecutor(max_workers=2) as pool:
                        outcomes=list(pool.map(lambda _:client.post('/api/auth/email-verification/confirm',headers=origin,json={'token':raw}).status_code,range(2)))
                    assert outcomes.count(200)==1 and all(status in {200,400,409} for status in outcomes),outcomes
                    assert client.get('/api/auth/me').json()['id']==second['id']
                    assert client.get('/api/auth/email-verification').json()['verified'] is False
                    verified=mongo[database].users.find_one({'_id':first['id']})
                    assert verified['email_verified_address']=='first@example.com' and verified.get('credential_version',0)==0
                    assert mongo[database].account_events.count_documents({'user_id':first['id'],'action':'email.verified'})==1
                    assert client.post('/api/auth/email-verification/confirm',headers=origin,json={'token':raw}).status_code==400
                    assert client.post('/api/auth/email-verification/request',headers=headers()).status_code==202
                    expired=token();mongo[database].email_verifications.update_many({'user_id':second['id']},{'$set':{'expires_at':datetime.now(timezone.utc)-timedelta(minutes=1)}})
                    assert client.post('/api/auth/email-verification/confirm',headers=origin,json={'token':expired}).status_code==400
                    client.post('/api/auth/email-verification/request',headers=headers());stale=token()
                    response=client.post('/api/auth/password',headers=headers(),json={'current_password':'synthetic-password','new_password':'synthetic-new-password'})
                    assert response.status_code==200,response.text
                    assert client.post('/api/auth/email-verification/confirm',headers=origin,json={'token':stale}).status_code==400
                    client.post('/api/auth/email-verification/request',headers=headers());disabled=token()
                    mongo[database].users.update_one({'_id':second['id']},{'$set':{'disabled':True}})
                    assert client.post('/api/auth/email-verification/confirm',headers=origin,json={'token':disabled}).status_code==400
                    assert client.post('/api/auth/email-verification/confirm',headers={'origin':'https://untrusted.example'},json={'token':disabled}).status_code==403
            finally:
                mongo.drop_database(database);mongo.close()
        ''')
        result=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,timeout=60)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
