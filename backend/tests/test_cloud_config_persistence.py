"""Real API/Mongo boundaries for import-only cloud/configuration reports."""
import os,subprocess,sys,textwrap,unittest
@unittest.skipUnless(os.environ.get('MONGO_TEST_URL'),'Set MONGO_TEST_URL to a disposable MongoDB server')
class CloudConfigPersistenceTests(unittest.TestCase):
 def test_import_persistence_deduplication_omission_and_authorization(self):
  code=textwrap.dedent('''
   import os,sys,uuid,json
   from datetime import datetime,timezone,timedelta
   from pymongo import MongoClient
   from fastapi.testclient import TestClient
   database='vaptx_cloud_import_'+uuid.uuid4().hex
   os.environ.update(MONGO_URL=os.environ['MONGO_TEST_URL'],DB_NAME=database,JWT_SECRET='synthetic-cloud-import-'*4,
    ADMIN_EMAIL='owner@example.com',ADMIN_PASSWORD='synthetic-owner-password',FRONTEND_URL='http://localhost:3000',
    INTERNAL_API_URL='http://127.0.0.1:8001',NMAP_BINARY='nmap',VAPTX_LOCAL_HTTP='1')
   sys.path.insert(0,'tests')
   from test_cloud_config_imports import PROWLER,TRIVY_MIXED
   from server import app
   mongo=MongoClient(os.environ['MONGO_TEST_URL']);db=mongo[database]
   try:
    with TestClient(app) as client:
     origin={'origin':'http://localhost:3000'}
     def headers():return {**origin,'x-csrf-token':client.cookies.get('csrf') or ''}
     def post(path,body):
      response=client.post('/api/'+path,headers=headers(),json=body)
      assert response.status_code==200,(path,response.text)
      return response.json()
     user=post('auth/register',{'email':'cloud-import@example.com','password':'synthetic-password'})
     org=post('organizations',{'name':'Synthetic import organization'})
     project=post('projects',{'name':'Synthetic cloud import'})
     now=datetime.now(timezone.utc)
     scope=post('scopes',{'project_id':project['id'],'target':'training://local','authorized':True,
      'authorization_reference':'Synthetic report association only','starts_at':(now-timedelta(hours=1)).isoformat(),
      'ends_at':(now+timedelta(hours=1)).isoformat(),'allowed_scanners':['prowler','trivy']})
     asset=post('assets',{'project_id':project['id'],'scope_id':scope['id'],'name':'Synthetic report association','target':'training://local'})
     assessment=post('assessments',{'project_id':project['id'],'name':'Synthetic import acceptance','asset_ids':[asset['id']]})
     for scanner,fixture,count in [('prowler',[PROWLER],1),('trivy',TRIVY_MIXED,2)]:
      body={'assessment_id':assessment['id'],'asset_id':asset['id'],'scanner':scanner,'content':json.dumps(fixture)}
      job=post('imports',body);assert job['finding_count']==count,job
      assert job['raw_output'].startswith('Raw report omitted'),job
      assert post('imports',body)['finding_count']==0
     rows=list(db.findings.find({'assessment_id':assessment['id']}));assert len(rows)==3,rows
     assert all(r['verification']=='imported-unverified' and r['source']=='import' and r['org_id']==org['id'] for r in rows)
     stored=json.dumps(rows)+json.dumps(list(db.jobs.find({'assessment_id':assessment['id']})))
     for private in ('omitted-tag','private-code-value','private-message-value','synthetic-detected-match'):
      assert private not in stored,private
     page=client.get('/api/findings',params={'assessment_id':assessment['id']}).json()
     assert page['total']==3 and all('import_metadata' in row for row in page['items']),page
     before=db.jobs.count_documents({})
     body={'assessment_id':assessment['id'],'asset_id':asset['id'],'scanner':'prowler','content':'[{}]'}
     response=client.post('/api/imports',headers=headers(),json=body);assert response.status_code==422,response.text
     assert db.jobs.count_documents({})==before
     body['content']=json.dumps([PROWLER])
     assert client.post('/api/imports',headers={**headers(),'x-org-id':'foreign'},json=body).status_code==404
     member={'org_id':org['id'],'user_id':user['id']}
     db.memberships.update_one(member,{'$set':{'role':'viewer'}})
     assert client.post('/api/imports',headers=headers(),json=body).status_code==403
     db.memberships.update_one(member,{'$set':{'role':'analyst','project_access':{'mode':'selected','project_ids':[]}}})
     assert client.post('/api/imports',headers=headers(),json=body).status_code==404
     db.memberships.update_one(member,{'$set':{'role':'org_admin'}})
     db.scopes.update_one({'_id':scope['id']},{'$set':{'allowed_scanners':['trivy']}})
     assert client.post('/api/imports',headers=headers(),json=body).status_code==403
     assert db.jobs.count_documents({})==before
     assert db.audit_events.count_documents({'org_id':org['id'],'action':'jobs.created'})==4
   finally:
    mongo.drop_database(database);mongo.close()
  ''')
  result=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,timeout=60)
  self.assertEqual(result.returncode,0,result.stdout+result.stderr)
