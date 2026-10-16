"""Disposable-Mongo account lifecycle and platform/organization privilege boundaries."""
import os
import subprocess
import sys
import textwrap
import unittest

@unittest.skipUnless(os.environ.get('MONGO_TEST_URL'),'Set MONGO_TEST_URL to a disposable MongoDB server')
class AccountAdminPersistenceTests(unittest.TestCase):
    def test_platform_owner_disable_reactivate_and_step_up(self):
        code=textwrap.dedent('''
            import os,uuid,json,base64
            from unittest.mock import patch
            from pymongo import MongoClient
            from fastapi.testclient import TestClient
            from cryptography.fernet import Fernet
            database='vaptx_account_admin_test_'+uuid.uuid4().hex
            os.environ.update(MONGO_URL=os.environ['MONGO_TEST_URL'],DB_NAME=database,JWT_SECRET='integration-only-'*4,
                ADMIN_EMAIL='owner@example.com',ADMIN_PASSWORD='integration-owner-password',FRONTEND_URL='http://localhost:3000',
                INTERNAL_API_URL='http://127.0.0.1:8001',NMAP_BINARY='nmap',VAPTX_LOCAL_HTTP='1')
            from server import app
            import mfa
            mongo=MongoClient(os.environ['MONGO_TEST_URL'],serverSelectionTimeoutMS=5000)
            try:
                with TestClient(app) as client,patch.dict(os.environ,{'MFA_ENCRYPTION_KEYS':Fernet.generate_key().decode()}):
                    origin={'origin':'http://localhost:3000'}
                    def headers():return {**origin,'x-csrf-token':client.cookies.get('csrf')}
                    def post(path,body):
                        response=client.post('/api/'+path,headers=headers(),json=body)
                        assert response.status_code==200,(path,response.text)
                        return response.json()
                    owner=client.post('/api/auth/login',headers=origin,json={'email':'owner@example.com','password':'integration-owner-password'}).json()
                    owner_cookies=dict(client.cookies)
                    target=client.post('/api/auth/register',headers=origin,json={'email':'target@example.com','password':'integration-target-password'}).json()
                    post('organizations',{'name':'Target org'})
                    token=post('api-tokens',{'name':'Before disable','scopes':['read']})['token']
                    target_access=client.cookies.get('access_token');target_refresh=client.cookies.get('refresh_token')
                    assert client.get('/api/platform/accounts').status_code==403
                    assert client.post('/api/platform/accounts/'+target['id']+'/state',headers=headers(),json={'disabled':True,'expected_disabled':False,'reason':'Synthetic fixture','current_password':'integration-target-password'}).status_code==403
                    client.cookies.clear();client.cookies.update(owner_cookies)
                    listed=client.get('/api/platform/accounts',params={'search':'target@example.com'}).json()
                    assert listed['total']==1 and listed['items'][0]['id']==target['id']
                    assert not any(key in json.dumps(listed) for key in ('password_hash','mfa_secret','credential_version'))
                    def change(disabled,expected,**extra):
                        return client.post('/api/platform/accounts/'+target['id']+'/state',headers=headers(),json={'disabled':disabled,'expected_disabled':expected,'reason':'Synthetic controlled lifecycle','current_password':'integration-owner-password',**extra})
                    assert change(True,False,current_password='incorrect-password').status_code==403
                    assert client.post('/api/platform/accounts/'+owner['id']+'/state',headers=headers(),json={'disabled':True,'expected_disabled':False,'reason':'Self disable blocked','current_password':'integration-owner-password'}).status_code==409
                    assert change(True,False).status_code==200
                    assert client.get('/api/auth/me',headers={'cookie':'access_token='+target_access}).status_code==401
                    assert client.get('/api/projects',headers={'authorization':'Bearer '+token}).status_code==401
                    assert client.post('/api/auth/login',headers=origin,json={'email':'target@example.com','password':'integration-target-password'}).status_code==401
                    assert client.post('/api/auth/refresh',headers={**origin,'cookie':'refresh_token='+target_refresh+'; csrf=synthetic','x-csrf-token':'synthetic'}).status_code==401
                    assert change(True,False).status_code==409
                    assert change(False,True).status_code==200
                    assert client.get('/api/auth/me',headers={'cookie':'access_token='+target_access}).status_code==401
                    assert client.get('/api/projects',headers={'authorization':'Bearer '+token}).status_code==401
                    assert client.post('/api/auth/login',headers=origin,json={'email':'target@example.com','password':'integration-target-password'}).status_code==200
                    events=client.get('/api/auth/security-events').json()['items']
                    assert {'account.disabled','account.reactivated'}<={row['action'] for row in events}
                    client.cookies.clear();client.cookies.update(owner_cookies)
                    recovery,hashes=mfa.recovery_codes()
                    encrypted=mfa.cipher().encrypt(base64.b32encode(b'12345678901234567890')).decode()
                    mongo[database].users.update_one({'_id':owner['id']},{'$set':{'mfa_enabled':True,'mfa_secret':encrypted,'mfa_last_counter':0,'mfa_recovery_hashes':hashes}})
                    assert change(True,False).status_code==403
                    assert change(True,False,mfa_code=recovery[0]).status_code==200
                    assert change(False,True,mfa_code=recovery[0]).status_code==403
                    assert change(False,True,mfa_code=recovery[1]).status_code==200
            finally:
                mongo.drop_database(database);mongo.close()
        ''')
        result=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,timeout=60)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
