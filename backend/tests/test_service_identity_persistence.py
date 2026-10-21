"""Service principal lifecycle, capped bearer access and explicit owner handoff."""
import os
import subprocess
import sys
import textwrap
import unittest


@unittest.skipUnless(os.environ.get('MONGO_TEST_URL'),'Set MONGO_TEST_URL to a disposable MongoDB server')
class ServiceIdentityPersistenceTests(unittest.TestCase):
    def test_credential_caps_owner_handoff_revocation_and_tenant_isolation(self):
        code=textwrap.dedent('''
            import os,uuid,httpx
            from pymongo import MongoClient
            from fastapi.testclient import TestClient
            database='vaptx_service_identities_'+uuid.uuid4().hex
            os.environ.update(MONGO_URL=os.environ['MONGO_TEST_URL'],DB_NAME=database,
                JWT_SECRET='synthetic-service-identity-'*3,ADMIN_EMAIL='owner@example.com',
                ADMIN_PASSWORD='synthetic-owner-password',FRONTEND_URL='http://localhost:3000',
                INTERNAL_API_URL='http://127.0.0.1:8001',NMAP_BINARY='nmap',VAPTX_LOCAL_HTTP='1')
            from server import app
            mongo=MongoClient(os.environ['MONGO_TEST_URL']);db=mongo[database]
            try:
             with TestClient(app) as client:
              origin={'origin':'http://localhost:3000'}
              def headers(org=None):return {**origin,'x-csrf-token':client.cookies.get('csrf') or '',**({'x-org-id':org} if org else {})}
              owner=client.post('/api/auth/register',headers=origin,json={'email':'service-admin@example.com','password':'synthetic-password'}).json()
              org=client.post('/api/organizations',headers=headers(),json={'name':'Service fixture'}).json();org_id=org['id']
              first=client.post('/api/projects',headers=headers(org_id),json={'name':'Credential project'}).json()
              second=client.post('/api/projects',headers=headers(org_id),json={'name':'Outside cap'}).json()
              client.post('/api/auth/logout',headers=headers(org_id))
              client.post('/api/auth/login',headers=origin,json={'email':'service-admin@example.com','password':'synthetic-password'})
              other=client.post('/api/auth/register',headers=origin,json={'email':'service-owner@example.com','password':'synthetic-password'}).json()
              client.post('/api/auth/logout',headers=headers())
              client.post('/api/auth/login',headers=origin,json={'email':'service-admin@example.com','password':'synthetic-password'})
              assert client.post('/api/members',headers=headers(org_id),json={'email':'service-owner@example.com','role':'viewer'}).status_code==200
              created=client.post('/api/service-identities',headers=headers(org_id),json={'name':'Build agent','owner_user_id':other['id'],
                  'permissions':['read','write'],'project_ids':[first['id'],second['id']]})
              assert created.status_code==200,created.text
              identity=created.json();assert identity['id']
              issued=client.post('/api/service-identities/'+identity['id']+'/credentials',headers=headers(org_id),json={
                  'scopes':['read','write'],'project_ids':[first['id']],'expires_days':30})
              assert issued.status_code==200,issued.text
              credential=issued.json();secret=credential['token'];assert secret.startswith('vaptxsvc_')
              saved=db.service_credentials.find_one({'_id':credential['id']})
              assert saved['token_hash'] and 'token' not in saved and saved['project_ids']==[first['id']]
              listed=client.get('/api/service-identities',headers=headers(org_id)).json()['items'][0]
              assert 'token' not in listed['credentials'][0] and 'token_hash' not in listed['credentials'][0]
              bearer={'authorization':'Bearer '+secret}
              visible=client.get('/api/projects?limit=100',headers=bearer)
              assert visible.status_code==200 and [p['id'] for p in visible.json()['items']]==[first['id']],visible.text
              # A project detail GET is not an API route; use the workspace's
              # project selector to verify that the credential cap hides it.
              assert client.get('/api/workspace',params={'project_id':second['id']},headers=bearer).status_code==404
              assert client.get('/api/auth/me',headers=bearer).status_code==403
              assert client.get('/api/service-identities',headers=bearer).status_code==403
              # Removing the named human owner suspends service authentication. An administrator handoff is explicit and versioned.
              removed=client.post('/api/members/'+other['id']+'/remove',headers=headers(org_id),json={'reason':'Synthetic owner handoff test'})
              assert removed.status_code==200,removed.text
              assert client.get('/api/projects',headers=bearer).status_code==401
              handoff=client.patch('/api/service-identities/'+identity['id'],headers=headers(org_id),json={
                  'name':'Build agent','owner_user_id':owner['id'],'permissions':['read','write'],
                  'project_ids':[first['id'],second['id']],'active':True,'expected_version':1})
              assert handoff.status_code==200,handoff.text
              assert client.get('/api/projects?limit=100',headers=bearer).json()['items'][0]['id']==first['id']
              updated=client.patch('/api/service-identities/'+identity['id'],headers=headers(org_id),json={
                  'name':'Build agent','owner_user_id':owner['id'],'permissions':['read','write'],
                  'project_ids':[first['id'],second['id']],'active':False,'expected_version':2})
              assert updated.status_code==200,updated.text
              assert client.get('/api/projects',headers=bearer).status_code==401
              enabled=client.patch('/api/service-identities/'+identity['id'],headers=headers(org_id),json={
                  'name':'Build agent','owner_user_id':owner['id'],'permissions':['read','write'],
                  'project_ids':[first['id'],second['id']],'active':True,'expected_version':3})
              assert enabled.status_code==200,enabled.text
              rotated=client.post('/api/service-identities/'+identity['id']+'/credentials/'+credential['id']+'/rotate',headers=headers(org_id),json={'expires_days':30})
              assert rotated.status_code==200,rotated.text
              replacement=rotated.json()['token']
              assert client.get('/api/projects',headers=bearer).status_code==401
              assert client.get('/api/projects?limit=100',headers={'authorization':'Bearer '+replacement}).status_code==200
              other_org=client.post('/api/organizations',headers=headers(),json={'name':'Other service tenant'}).json()
              assert client.get('/api/projects',headers={'authorization':'Bearer '+replacement,'x-org-id':other_org['id']}).status_code==404
              assert client.post('/api/service-identities/'+identity['id']+'/credentials/'+rotated.json()['id']+'/revoke',headers=headers(org_id)).status_code==200
              assert client.get('/api/projects',headers={'authorization':'Bearer '+replacement}).status_code==401

            finally:
             mongo.drop_database(database);mongo.close()
        ''')
        result=subprocess.run([sys.executable,'-c',code],text=True,capture_output=True,env=os.environ.copy())
        self.assertEqual(result.returncode,0,result.stdout+'\n'+result.stderr)
