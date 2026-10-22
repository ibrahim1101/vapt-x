"""Custom-role API, credential and tenant boundaries through disposable MongoDB."""
import os
import subprocess
import sys
import textwrap
import unittest


@unittest.skipUnless(os.environ.get('MONGO_TEST_URL'),'Set MONGO_TEST_URL to a disposable MongoDB server')
class CustomRolePersistenceTests(unittest.TestCase):
    def test_live_permissions_assignment_token_intersection_and_tenant_isolation(self):
        code=textwrap.dedent('''
            import os,uuid,httpx
            from pymongo import MongoClient
            from fastapi.testclient import TestClient
            database='vaptx_custom_roles_'+uuid.uuid4().hex
            os.environ.update(MONGO_URL=os.environ['MONGO_TEST_URL'],DB_NAME=database,
                JWT_SECRET='synthetic-custom-role-'*4,ADMIN_EMAIL='owner@example.com',
                ADMIN_PASSWORD='synthetic-owner-password',FRONTEND_URL='http://localhost:3000',
                INTERNAL_API_URL='http://127.0.0.1:8001',NMAP_BINARY='nmap',VAPTX_LOCAL_HTTP='1')
            from server import app
            mongo=MongoClient(os.environ['MONGO_TEST_URL']);db=mongo[database]
            try:
             with TestClient(app) as client:
              origin={'origin':'http://localhost:3000'};org_id=None
              def headers():return {**origin,'x-csrf-token':client.cookies.get('csrf') or '',**({'x-org-id':org_id} if org_id else {})}
              owner=client.post('/api/auth/register',headers=origin,json={'email':'role-owner@example.com','password':'synthetic-password'}).json()
              organization=client.post('/api/organizations',headers=headers(),json={'name':'Role fixture'}).json();org_id=organization['id']
              owner_cookies=httpx.Cookies(client.cookies)
              role=client.post('/api/custom-roles',headers=headers(),json={'name':'Read and write','permissions':['read','write']})
              assert role.status_code==200,role.text
              role_id=role.json()['id']
              duplicate=client.post('/api/custom-roles',headers=headers(),json={'name':' read   AND WRITE ','permissions':['read']})
              assert duplicate.status_code==409,duplicate.text
              recipient=client.post('/api/auth/register',headers=origin,json={'email':'role-member@example.com','password':'synthetic-password'}).json()
              member_cookies=httpx.Cookies(client.cookies)
              def cookies(value):client.cookies.clear();client.cookies.update(value)
              cookies(owner_cookies)
              assign=client.post('/api/members',headers=headers(),json={'email':'role-member@example.com','role':'custom:'+role_id})
              assert assign.status_code==200,assign.text
              saved=db.memberships.find_one({'org_id':org_id,'user_id':recipient['id']})
              assert saved['role']=='custom' and saved['custom_role_id']==role_id
              assert client.post('/api/custom-roles',headers=headers(),json={'name':'bad','permissions':['read','members']}).status_code==422
              assert client.post('/api/custom-roles/'+role_id+'/delete?expected_version=1',headers=headers()).status_code==409
              cookies(member_cookies)
              me=client.get('/api/auth/me').json();member_org=next(item for item in me['organizations'] if item['id']==org_id)
              assert member_org['role']=='custom' and member_org['role_name']=='Read and write'
              assert set(member_org['permissions'])=={'read','write'}
              project=client.post('/api/projects',headers=headers(),json={'name':'Custom role project'})
              assert project.status_code==200,project.text
              token_response=client.post('/api/api-tokens',headers=headers(),json={'name':'Scoped custom role token','scopes':['read','write']})
              assert token_response.status_code==200,token_response.text
              bearer={'authorization':'Bearer '+token_response.json()['token']}
              assert client.get('/api/projects',headers=bearer).status_code==200
              assert client.post('/api/custom-roles',headers=bearer,json={'name':'Token role','permissions':['read']}).status_code==403
              cookies(owner_cookies)
              changed=client.patch('/api/custom-roles/'+role_id,headers=headers(),json={'name':'Read only','permissions':['read','report_read'],'expected_version':1})
              assert changed.status_code==200,changed.text
              stale=client.patch('/api/custom-roles/'+role_id,headers=headers(),json={'name':'Stale overwrite','permissions':['read'],'expected_version':1})
              assert stale.status_code==409,stale.text
              cookies(member_cookies)
              assert client.post('/api/projects',headers=headers(),json={'name':'Denied after live policy change'}).status_code==403
              assert client.post('/api/projects',headers=bearer,json={'name':'Token denied after live policy change'}).status_code==403
              assert client.get('/api/projects',headers=bearer).status_code==200
              cookies(owner_cookies)
              assert client.post('/api/members',headers=headers(),json={'email':'role-member@example.com','role':'viewer'}).status_code==200
              deleted=client.post('/api/custom-roles/'+role_id+'/delete?expected_version=2',headers=headers())
              assert deleted.status_code==200,deleted.text
              other=client.post('/api/organizations',headers=headers(),json={'name':'Other role tenant'}).json()
              client.cookies.clear();client.cookies.update(owner_cookies)
              assert client.post('/api/members',headers={**headers(),'x-org-id':other['id']},json={'email':'role-member@example.com','role':'custom:'+role_id}).status_code==404
            finally:
             mongo.drop_database(database);mongo.close()
        ''')
        result=subprocess.run([sys.executable,'-c',code],text=True,capture_output=True,env=os.environ.copy())
        self.assertEqual(result.returncode,0,result.stdout+'\n'+result.stderr)
