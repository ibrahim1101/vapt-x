"""Project admission through real Mongo/API paths; synthetic data only."""
import os,subprocess,sys,textwrap,unittest
@unittest.skipUnless(os.environ.get('MONGO_TEST_URL'),'Set MONGO_TEST_URL to a disposable MongoDB server')
class ProjectAccessPersistenceTests(unittest.TestCase):
 def test_browser_bearer_legacy_download_and_live_membership_boundaries(self):
  code=textwrap.dedent('''
   import os,uuid,base64,hashlib,httpx
   from datetime import datetime,timezone
   from pymongo import MongoClient
   from fastapi.testclient import TestClient
   database='vaptx_project_acl_'+uuid.uuid4().hex
   os.environ.update(MONGO_URL=os.environ['MONGO_TEST_URL'],DB_NAME=database,JWT_SECRET='synthetic-project-access-'*4,
    ADMIN_EMAIL='owner@example.com',ADMIN_PASSWORD='synthetic-owner-password',FRONTEND_URL='http://localhost:3000',
    INTERNAL_API_URL='http://127.0.0.1:8001',NMAP_BINARY='nmap',VAPTX_LOCAL_HTTP='1')
   from server import app
   mongo=MongoClient(os.environ['MONGO_TEST_URL']);db=mongo[database]
   try:
    with TestClient(app) as client:
     origin={'origin':'http://localhost:3000'};org=None
     def headers():return {**origin,'x-csrf-token':client.cookies.get('csrf') or '',**({'x-org-id':org} if org else {})}
     owner=client.post('/api/auth/register',headers=origin,json={'email':'acl-owner@example.com','password':'synthetic-password'}).json()
     organization=client.post('/api/organizations',headers=headers(),json={'name':'Synthetic ACL organization'}).json();org=organization['id']
     projects=[client.post('/api/projects',headers=headers(),json={'name':name}).json()['id'] for name in ('Allowed project','Hidden project')]
     owner_cookies=httpx.Cookies(client.cookies)
     member=client.post('/api/auth/register',headers=origin,json={'email':'acl-member@example.com','password':'synthetic-password'}).json();member_cookies=httpx.Cookies(client.cookies)
     def cookies(value):client.cookies.clear();client.cookies.update(value)
     cookies(owner_cookies)
     assert client.post('/api/members',headers=headers(),json={'email':'acl-member@example.com','role':'security_lead'}).status_code==200
     stamp=datetime.now(timezone.utc).isoformat();records={}
     def add(collection,identity,project=None,**values):
      row={'_id':identity,'org_id':org,'created_by':owner['id'],'created_at':stamp,**({'project_id':project} if project else {}),**values};db[collection].insert_one(row);return row
     for index,project in enumerate(projects):
      prefix='allowed' if index==0 else 'hidden'
      finding=prefix+'-finding';assessment=prefix+'-assessment';asset=prefix+'-asset';report=prefix+'-report';evidence=prefix+'-evidence'
      add('assets',asset,project,name=prefix+' asset',target='training://local',scope_id=prefix+'-scope',kind='web')
      add('scopes',prefix+'-scope',project,target='training://local',authorized=True,authorization_reference='synthetic authorization')
      add('assessments',assessment,project,name=prefix+' assessment',status='review',asset_ids=[asset])
      add('jobs',prefix+'-job',project,assessment_id=assessment,asset_id=asset,scanner='semgrep',source='import',status='completed',raw_output=prefix+' secret')
      add('findings',finding,project,title=prefix+' finding',severity='high',status='open',verification='imported-unverified',assessment_id=assessment,asset_id=asset,description=prefix+' description',remediation='synthetic remediation')
      add('tasks',prefix+'-task',project,title=prefix+' task',finding_id=finding,status='todo',due_date='')
      raw=(prefix+' evidence').encode();sha=hashlib.sha256(raw).hexdigest()
      add('evidence',evidence,project,finding_id=finding,filename=prefix+'.txt',status='ready',size=len(raw),chunk_count=1,sha256=sha,content_type='text/plain')
      # Legacy child blobs deliberately have no project_id.
      add('evidence_chunks',prefix+'-chunk',evidence_id=evidence,index=0,data=base64.b64encode(raw).decode())
      pdf=b'%PDF-'+prefix.encode();snapshot=(prefix+' snapshot').encode()
      add('reports',report,project,assessment_id=assessment,name=prefix+' report',status='ready',sha256=hashlib.sha256(pdf).hexdigest(),snapshot_sha256=hashlib.sha256(snapshot).hexdigest(),template='technical')
      add('report_files',prefix+'-file',report_id=report,data=base64.b64encode(pdf).decode())
      add('report_snapshots',prefix+'-snapshot',report_id=report,data=base64.b64encode(snapshot).decode())
      add('audit_events',prefix+'-event',project,action='synthetic.project.event',resource_type='findings',resource_id=finding,details={'synthetic':prefix})
     add('audit_events','unattributed-event',action='legacy.private.event',details={'private':'legacy org data'})
     cookies(member_cookies)
     token_response=client.post('/api/api-tokens',headers=headers(),json={'name':'Pre-existing ACL token','scopes':['read','write','report','triage']})
     assert token_response.status_code==200,token_response.text
     token=token_response.json()['token']
     assert client.get('/api/projects',headers=headers()).json()['total']==2
     cookies(owner_cookies)
     denied=client.post('/api/members/'+owner['id']+'/project-access',headers=headers(),json={'mode':'selected','project_ids':[]});assert denied.status_code==409
     foreign=client.post('/api/members/'+member['id']+'/project-access',headers=headers(),json={'mode':'selected','project_ids':['foreign-project']});assert foreign.status_code==404
     grant=client.post('/api/members/'+member['id']+'/project-access',headers=headers(),json={'mode':'selected','project_ids':[projects[0]]});assert grant.status_code==200,grant.text
     cookies(member_cookies)
     for access_headers in (headers(),{'authorization':'Bearer '+token}):
      project_page=client.get('/api/projects',headers=access_headers).json();assert project_page['total']==1 and project_page['items'][0]['id']==projects[0],project_page
      workspace=client.get('/api/workspace',headers=access_headers).json()
      for collection in ('projects','scopes','assets','assessments','jobs','findings','tasks','evidence','reports'):
       assert len(workspace[collection])==1,(collection,workspace[collection])
      assert 'hidden' not in str(workspace) and 'unattributed-event' not in str(workspace)
      summary=client.get('/api/analytics/summary',headers=access_headers).json();assert summary['projects']==1 and summary['assets']==1 and summary['findings']==1,summary
      assert client.get('/api/findings?search=hidden',headers=access_headers).json()['total']==0
      events=client.get('/api/audit-events',headers=access_headers).json();assert events['total']>=1 and 'hidden' not in str(events) and 'unattributed-event' not in str(events)
      for path in ('/api/workspace?project_id='+projects[1],'/api/assets?project_id='+projects[1],'/api/jobs/hidden-job','/api/assets/hidden-asset/history','/api/findings/hidden-finding/history','/api/assessments/hidden-assessment/history','/api/assessments/hidden-assessment/findings/export','/api/evidence/hidden-evidence/download','/api/reports/hidden-report/download','/api/reports/hidden-report/snapshot'):
       result=client.get(path,headers=access_headers);assert result.status_code==404,(path,result.text)
      assert client.get('/api/evidence/allowed-evidence/download',headers=access_headers).content==b'allowed evidence'
      assert client.get('/api/reports/allowed-report/download',headers=access_headers).content==b'%PDF-allowed'
      assert client.get('/api/reports/allowed-report/snapshot',headers=access_headers).content==b'allowed snapshot'
     # Restricted leads cannot subscribe org-wide webhooks or alter org policy.
     assert client.get('/api/webhooks',headers=headers()).status_code==403
     assert client.put('/api/sla-policy',headers=headers(),json={}).status_code==403
     assert client.post('/api/projects',headers=headers(),json={'name':'Unauthorized project'}).status_code==403
     update=client.patch('/api/findings/hidden-finding',headers=headers(),json={'status':'confirmed'});assert update.status_code==404,update.text
     bulk=client.post('/api/findings/bulk-triage',headers=headers(),json={'finding_ids':['allowed-finding','hidden-finding'],'status':'confirmed'});assert bulk.status_code==404,bulk.text
     assert db.findings.find_one({'_id':'allowed-finding'})['status']=='open'
     assert client.post('/api/assessments/hidden-assessment/report/preview',headers=headers(),json={}).status_code==404
     assert client.post('/api/members/'+member['id']+'/project-access',headers=headers(),json={'mode':'all','project_ids':[]}).status_code==403
     me=client.get('/api/auth/me').json();assert me['organizations'][0]['project_access']['project_ids']==[projects[0]]
     # Empty selection immediately removes project data from an already-issued token.
     cookies(owner_cookies)
     assert client.post('/api/members/'+member['id']+'/project-access',headers=headers(),json={'mode':'selected','project_ids':[]}).status_code==200
     assert client.get('/api/projects',headers={'authorization':'Bearer '+token}).json()['total']==0
     assert client.get('/api/evidence/allowed-evidence/download',headers={'authorization':'Bearer '+token}).status_code==404
     # Granting all again restores project access without changing role or account.
     assert client.post('/api/members/'+member['id']+'/project-access',headers=headers(),json={'mode':'all','project_ids':[]}).status_code==200
     assert client.get('/api/projects',headers={'authorization':'Bearer '+token}).json()['total']==2
     assert db.users.find_one({'_id':member['id']}).get('credential_version',0)==0
   finally:
    mongo.drop_database(database);mongo.close()
  ''')
  result=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,timeout=90)
  self.assertEqual(result.returncode,0,result.stdout+result.stderr)
