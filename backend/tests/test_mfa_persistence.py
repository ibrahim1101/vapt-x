"""MFA lifecycle against disposable Mongo, with a controlled authenticator clock."""
import os
import subprocess
import sys
import textwrap
import unittest

@unittest.skipUnless(os.environ.get('MONGO_TEST_URL'),'Set MONGO_TEST_URL to a disposable MongoDB server')
class MFAPersistenceTests(unittest.TestCase):
    def test_mfa_lifecycle_and_concurrent_one_use_claims(self):
        code=textwrap.dedent('''
            import os, uuid, json, asyncio, time
            from unittest.mock import patch, AsyncMock
            from pymongo import MongoClient
            from fastapi.testclient import TestClient
            from cryptography.fernet import Fernet
            database='vaptx_mfa_test_'+uuid.uuid4().hex
            os.environ.update(MONGO_URL=os.environ['MONGO_TEST_URL'],DB_NAME=database,
                JWT_SECRET='integration-only-'*4,ADMIN_EMAIL='owner@example.com',ADMIN_PASSWORD='integration-only-password',
                FRONTEND_URL='http://localhost:3000',INTERNAL_API_URL='http://127.0.0.1:8001',NMAP_BINARY='nmap',VAPTX_LOCAL_HTTP='1')
            from server import app
            import mfa
            mongo=MongoClient(os.environ['MONGO_TEST_URL'],serverSelectionTimeoutMS=5000)
            clock=[int(time.time())]
            original=mfa.matching_counter
            def verify(secret,code): return original(secret,code,clock[0])
            try:
                with TestClient(app) as client, patch('mfa.matching_counter',side_effect=verify):
                    origin={'origin':'http://localhost:3000'}
                    def headers():return {**origin,'x-csrf-token':client.cookies.get('csrf')}
                    def post(path,body):
                        response=client.post('/api/'+path,headers=headers(),json=body)
                        assert response.status_code==200,(path,response.text)
                        return response.json()
                    user=client.post('/api/auth/register',headers=origin,json={'email':'mfa@example.com','password':'integration-password'}).json()
                    post('organizations',{'name':'MFA fixture'})
                    token=post('api-tokens',{'name':'Before MFA','scopes':['read']})['token']
                    old_access=client.cookies.get('access_token')
                    assert client.get('/api/auth/mfa',headers={'authorization':'Bearer '+token}).status_code==403
                    with patch.dict(os.environ,{'MFA_ENCRYPTION_KEYS':''}):
                        assert client.post('/api/auth/mfa/setup',headers=headers(),json={'current_password':'integration-password'}).status_code==503
                    with patch.dict(os.environ,{'MFA_ENCRYPTION_KEYS':Fernet.generate_key().decode()}):
                        setup=post('auth/mfa/setup',{'current_password':'integration-password'})
                        stored=mongo[database].users.find_one({'_id':user['id']})
                        assert setup['secret'] not in json.dumps(stored)
                        assert not client.get('/api/auth/mfa').json()['enabled']
                        current=mfa.totp(setup['secret'],clock[0]//30)
                        bad='000000' if current!='000000' else '111111'
                        assert client.post('/api/auth/mfa/confirm',headers=headers(),json={'code':bad}).status_code==403
                        enabled=post('auth/mfa/confirm',{'code':current})
                        recovery=enabled['recovery_codes']
                        assert len(recovery)==10
                        assert client.get('/api/auth/me',headers={'cookie':'access_token='+old_access}).status_code==401
                        assert client.get('/api/projects',headers={'authorization':'Bearer '+token}).status_code==401
                        stored=mongo[database].users.find_one({'_id':user['id']})
                        assert all(value not in json.dumps(stored) for value in recovery)
                        state=client.get('/api/auth/mfa').json()
                        assert state['enabled'] and state['recovery_codes_remaining']==10
                        assert 'mfa_secret' not in json.dumps(client.get('/api/auth/me').json())
                        def login(code=''):
                            return client.post('/api/auth/login',headers=origin,json={'email':'mfa@example.com','password':'integration-password','mfa_code':code})
                        assert login().status_code==401
                        assert login(current).status_code==401
                        clock[0]+=60
                        fresh=mfa.totp(setup['secret'],clock[0]//30)
                        # Atomic database claim: simultaneous copies may produce exactly one winner.
                        document=mongo[database].users.find_one({'_id':user['id']})
                        async def race():
                            with patch('mfa.charge_attempt',new_callable=AsyncMock):
                                return await asyncio.gather(*(mfa.consume(document,fresh) for _ in range(8)))
                        claimed=client.portal.call(race)
                        assert sum(row is not None for row in claimed)==1
                        assert login(fresh).status_code==401
                        clock[0]+=60
                        assert login(mfa.totp(setup['secret'],clock[0]//30)).status_code==200
                        assert login(recovery[0]).status_code==200
                        assert login(recovery[0]).status_code==401
                        with patch.dict(os.environ,{'MFA_ENCRYPTION_KEYS':''}):
                            replacement=post('auth/mfa/recovery-codes',{'current_password':'integration-password','mfa_code':recovery[1]})
                        assert login(recovery[2]).status_code==401
                        assert client.post('/api/auth/password',headers=headers(),json={'current_password':'integration-password','new_password':'changed-password'}).status_code==403
                        post('auth/password',{'current_password':'integration-password','new_password':'changed-password','mfa_code':replacement['recovery_codes'][1]})
                        assert client.post('/api/auth/mfa/disable',headers=headers(),json={'current_password':'incorrect-password','mfa_code':replacement['recovery_codes'][0]}).status_code==403
                        post('auth/mfa/disable',{'current_password':'changed-password','mfa_code':replacement['recovery_codes'][0]})
                        assert not client.get('/api/auth/mfa').json()['enabled']
                        assert client.post('/api/auth/login',headers=origin,json={'email':'mfa@example.com','password':'changed-password'}).status_code==200
                        mongo[database].mfa_attempts.insert_one({'_id':'budget-fixture','count':0,'expires_at':mfa.now()+mfa.timedelta(minutes=15)})
                        async def budget_race():return await asyncio.gather(*(mfa.charge_attempt('budget-fixture') for _ in range(24)),return_exceptions=True)
                        budget=client.portal.call(budget_race)
                        assert sum(result is None for result in budget)==10
                        assert all(result is None or getattr(result,'status_code',None)==429 for result in budget)
                        assert mongo[database].mfa_attempts.find_one({'_id':'budget-fixture'})['count']==10

            finally:
                mongo.drop_database(database)
                mongo.close()
        ''')
        result=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,timeout=60)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
