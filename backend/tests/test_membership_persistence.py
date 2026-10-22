import os
import sys
import textwrap
import subprocess
import unittest

@unittest.skipUnless(os.environ.get('MONGO_TEST_URL'),'Set MONGO_TEST_URL to a disposable MongoDB server')
class MembershipPersistenceTests(unittest.TestCase):
    def test_admin_race_removal_readdition_and_token_membership_binding(self):
        code=textwrap.dedent('''
            import os,uuid,asyncio,secrets
            from pymongo import MongoClient
            from fastapi.testclient import TestClient
            database='vaptx_membership_test_'+uuid.uuid4().hex
            os.environ.update(MONGO_URL=os.environ['MONGO_TEST_URL'],DB_NAME=database,JWT_SECRET='integration-only-'*4,
                ADMIN_EMAIL='owner@example.com',ADMIN_PASSWORD='integration-owner-password',FRONTEND_URL='http://localhost:3000',
                INTERNAL_API_URL='http://127.0.0.1:8001',NMAP_BINARY='nmap',VAPTX_LOCAL_HTTP='1')
            from server import app
            import auth
            from core import Ctx,sha256_hex,iso,now
            from datetime import timedelta
            mongo=MongoClient(os.environ['MONGO_TEST_URL'],serverSelectionTimeoutMS=5000)
            try:
                with TestClient(app) as client:
                    origin={'origin':'http://localhost:3000'}
                    def headers(org=None):return {**origin,'x-csrf-token':client.cookies.get('csrf'),**({'x-org-id':org} if org else {})}
                    def post(path,body,org=None):
                        response=client.post('/api/'+path,headers=headers(org),json=body)
                        assert response.status_code==200,(path,response.text)
                        return response.json()
                    alice=client.post('/api/auth/register',headers=origin,json={'email':'alice@example.com','password':'integration-password'}).json()
                    org=post('organizations',{'name':'Membership fixture'})
                    alice_cookies=dict(client.cookies)
                    bob=client.post('/api/auth/register',headers=origin,json={'email':'bob@example.com','password':'integration-password'}).json()
                    other=post('organizations',{'name':'Other membership fixture'})
                    other_token=post('api-tokens',{'name':'Other org access','scopes':['read']})['token']
                    bob_cookies=dict(client.cookies)
                    client.cookies.clear();client.cookies.update(alice_cookies)
                    post('members',{'email':'bob@example.com','role':'org_admin'},org['id'])
                    old_membership=mongo[database].memberships.find_one({'org_id':org['id'],'user_id':bob['id']})['_id']
                    client.cookies.clear();client.cookies.update(bob_cookies)
                    token=post('api-tokens',{'name':'Before removal','scopes':['read']},org['id'])['token']
                    async def race():
                        return await asyncio.gather(auth.grant_member(auth.MemberInput(email='bob@example.com',role='viewer'),Ctx(alice,org['id'],'org_admin')),
                            auth.grant_member(auth.MemberInput(email='alice@example.com',role='viewer'),Ctx(bob,org['id'],'org_admin')),return_exceptions=True)
                    results=client.portal.call(race)
                    assert sum(isinstance(result,dict) for result in results)==1,results
                    assert mongo[database].memberships.count_documents({'org_id':org['id'],'role':'org_admin'})==1
                    remaining=mongo[database].memberships.find_one({'org_id':org['id'],'role':'org_admin'})['user_id']
                    assert remaining in {alice['id'],bob['id']}
                    if remaining==bob['id']:
                        client.cookies.clear();client.cookies.update(bob_cookies)
                        post('members',{'email':'alice@example.com','role':'org_admin'},org['id'])
                    client.cookies.clear();client.cookies.update(alice_cookies)
                    post('members/'+bob['id']+'/remove',{'reason':'Synthetic membership removal'},org['id'])
                    assert client.get('/api/projects',headers={'authorization':'Bearer '+token}).status_code==401
                    assert client.get('/api/projects',headers={'authorization':'Bearer '+other_token}).status_code==200
                    assert client.post('/api/members/'+bob['id']+'/remove',headers=headers(org['id']),json={'reason':'Other membership must remain'}).status_code==404
                    post('members',{'email':'bob@example.com','role':'viewer'},org['id'])
                    assert client.get('/api/projects',headers={'authorization':'Bearer '+token}).status_code==401
                    late='vaptx_'+secrets.token_urlsafe(32)
                    mongo[database].api_tokens.insert_one({'_id':uuid.uuid4().hex,'org_id':org['id'],'created_by':bob['id'],
                        'token_hash':sha256_hex(late.encode()),'scopes':['read'],'revoked':False,'expires_at':iso(now()+timedelta(days=1)),
                        'credential_version':0,'membership_id':old_membership})
                    assert client.get('/api/projects',headers={'authorization':'Bearer '+late}).status_code==401
                    mongo[database].api_tokens.update_one({'token_hash':sha256_hex(late.encode())},{'$unset':{'membership_id':''}})
                    assert client.get('/api/projects',headers={'authorization':'Bearer '+late}).status_code==401

                    client.cookies.clear();client.cookies.update(bob_cookies)
                    fresh=post('api-tokens',{'name':'New membership access','scopes':['read']},org['id'])['token']
                    assert client.get('/api/projects',headers={'authorization':'Bearer '+fresh}).status_code==200
                    assert client.post('/api/members/'+alice['id']+'/remove',headers=headers(org['id']),json={'reason':'Viewer must not remove admin'}).status_code==403
            finally:
                mongo.drop_database(database);mongo.close()
        ''')
        result=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,timeout=60)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
