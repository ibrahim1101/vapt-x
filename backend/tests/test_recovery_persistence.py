"""Recovery acceptance uses disposable Mongo and a mocked mail sender only."""
import os
import subprocess
import sys
import textwrap
import unittest

@unittest.skipUnless(os.environ.get('MONGO_TEST_URL'),'Set MONGO_TEST_URL to a disposable MongoDB server')
class RecoveryPersistenceTests(unittest.TestCase):
    def test_one_use_mfa_epoch_invalidation_and_expiry(self):
        code=textwrap.dedent('''
            import os,uuid,hashlib
            from datetime import datetime,timedelta,timezone
            from concurrent.futures import ThreadPoolExecutor
            from urllib.parse import urlsplit,parse_qs
            from unittest.mock import patch
            from pymongo import MongoClient
            from fastapi.testclient import TestClient
            database='vaptx_recovery_'+uuid.uuid4().hex
            os.environ.update(MONGO_URL=os.environ['MONGO_TEST_URL'],DB_NAME=database,JWT_SECRET='synthetic-recovery-'*4,
                ADMIN_EMAIL='owner@example.com',ADMIN_PASSWORD='synthetic-owner-password',FRONTEND_URL='http://localhost:3000',
                INTERNAL_API_URL='http://127.0.0.1:8001',NMAP_BINARY='nmap',VAPTX_LOCAL_HTTP='1',
                ACCOUNT_RECOVERY_ENABLED='1',RECOVERY_SMTP_HOST='smtp.synthetic.invalid',RECOVERY_SMTP_FROM='operator@example.com')
            from server import app
            mongo=MongoClient(os.environ['MONGO_TEST_URL'],serverSelectionTimeoutMS=5000)
            links=[]
            try:
                with patch('account_recovery.send_mail',side_effect=lambda config,email,link:links.append(link)),TestClient(app) as client:
                    origin={'origin':'http://localhost:3000'}
                    def headers():return {**origin,'x-csrf-token':client.cookies.get('csrf')}
                    user=client.post('/api/auth/register',headers=origin,json={'email':'recovery@example.com','password':'synthetic-original-password'}).json()
                    assert client.post('/api/organizations',headers=headers(),json={'name':'Recovery fixture'}).status_code==200
                    token=client.post('/api/api-tokens',headers=headers(),json={'name':'Recovery old token','scopes':['read']}).json()['token']
                    old_refresh=client.cookies.get('refresh_token')
                    response=client.post('/api/auth/recovery/request',headers=origin,json={'email':'recovery@example.com'})
                    unknown=client.post('/api/auth/recovery/request',headers=origin,json={'email':'unknown@example.com'})
                    assert response.status_code==202 and response.json()==unknown.json()
                    raw=parse_qs(urlsplit(links[-1]).fragment)['reset_token'][0]
                    stored=mongo[database].account_recovery.find_one({'user_id':user['id']})
                    assert stored['token_hash']==hashlib.sha256(raw.encode()).hexdigest() and raw not in str(stored)
                    codes=['a'*32,'b'*32]
                    mongo[database].users.update_one({'_id':user['id']},{'$set':{'mfa_enabled':True,'mfa_secret':'synthetic-unavailable-key',
                        'mfa_recovery_hashes':[hashlib.sha256(code.encode()).hexdigest() for code in codes]}})
                    body={'token':raw,'new_password':'synthetic-recovered-password'}
                    assert client.post('/api/auth/recovery/complete',headers=origin,json=body).status_code==403
                    assert mongo[database].account_recovery.find_one({'_id':stored['_id']})['used_at'] is None
                    body['mfa_code']=codes[0]
                    with ThreadPoolExecutor(max_workers=2) as pool:
                        results=list(pool.map(lambda _:client.post('/api/auth/recovery/complete',headers=origin,json=body).status_code,range(2)))
                    assert results.count(200)==1 and all(status in {200,400,403,409} for status in results),results
                    saved=mongo[database].users.find_one({'_id':user['id']})
                    assert saved['credential_version']==1 and saved['mfa_enabled'] is True
                    assert client.get('/api/auth/me').status_code==401
                    assert client.get('/api/projects',headers={'authorization':'Bearer '+token}).status_code==401
                    assert client.post('/api/auth/refresh',headers={**origin,'cookie':'refresh_token='+old_refresh+'; csrf=fixture','x-csrf-token':'fixture'}).status_code==401
                    assert client.post('/api/auth/recovery/complete',headers=origin,json=body).status_code==400
                    assert client.post('/api/auth/login',headers=origin,json={'email':'recovery@example.com','password':'synthetic-original-password'}).status_code==401
                    assert client.post('/api/auth/login',headers=origin,json={'email':'recovery@example.com','password':'synthetic-recovered-password','mfa_code':codes[1]}).status_code==200
                    assert mongo[database].account_events.count_documents({'user_id':user['id'],'action':'password.reset'})==1
                    client.post('/api/auth/recovery/request',headers=origin,json={'email':'recovery@example.com'})
                    expired=parse_qs(urlsplit(links[-1]).fragment)['reset_token'][0]
                    mongo[database].account_recovery.update_many({'user_id':user['id']},{'$set':{'expires_at':datetime.now(timezone.utc)-timedelta(minutes=1)}})
                    assert client.post('/api/auth/recovery/complete',headers=origin,json={'token':expired,'new_password':'another-new-password'}).status_code==400
                    client.post('/api/auth/recovery/request',headers=origin,json={'email':'recovery@example.com'})
                    disabled=parse_qs(urlsplit(links[-1]).fragment)['reset_token'][0]
                    mongo[database].users.update_one({'_id':user['id']},{'$set':{'disabled':True}})
                    assert client.post('/api/auth/recovery/complete',headers=origin,json={'token':disabled,'new_password':'another-new-password'}).status_code==400
            finally:
                mongo.drop_database(database);mongo.close()
        ''')
        result=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,timeout=60)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
