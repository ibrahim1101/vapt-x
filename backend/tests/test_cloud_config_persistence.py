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
   from test_mobsf_import import MOBSF
   from test_scanner_facts import TRIVY_FACTS
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
      'ends_at':(now+timedelta(hours=1)).isoformat(),'allowed_scanners':['prowler','trivy','mobsf']})
     asset=post('assets',{'project_id':project['id'],'scope_id':scope['id'],'name':'Synthetic report association','target':'training://local'})
     assessment=post('assessments',{'project_id':project['id'],'name':'Synthetic import acceptance','asset_ids':[asset['id']]})
     for scanner,fixture,count in [('prowler',[PROWLER],1),('trivy',TRIVY_MIXED,2),('mobsf',MOBSF,2),('trivy',TRIVY_FACTS,1)]:
      body={'assessment_id':assessment['id'],'asset_id':asset['id'],'scanner':scanner,'content':json.dumps(fixture)}
      job=post('imports',body);assert job['finding_count']==count,job
      assert job['raw_output'].startswith('Raw report omitted'),job
      assert post('imports',body)['finding_count']==0
     rows=list(db.findings.find({'assessment_id':assessment['id']}));assert len(rows)==6,rows
     assert all(r['verification']=='imported-unverified' and r['source']=='import' and r['org_id']==org['id'] for r in rows)
     stored=json.dumps(rows)+json.dumps(list(db.jobs.find({'assessment_id':assessment['id']})))
     for private in ('omitted-tag','private-code-value','private-message-value','synthetic-detected-match','private-secret-value','private-strings-value','private.invalid'):
      assert private not in stored,private
     page=client.get('/api/findings',params={'assessment_id':assessment['id']}).json()
     assert page['total']==6 and any('scanner_cvss' in row for row in page['items']),page
     export=client.get('/api/assessments/'+assessment['id']+'/findings/export').json()
     facts=next(row for row in export['findings'] if row.get('scanner_cvss'))
     assert facts['package_info']['installed_version']=='1.0' and facts['scanner_cvss'][0]['version']=='3.1',facts
     assert any(row.get('import_metadata',{}).get('format')=='mobsf-android-json' for row in export['findings'] if row.get('import_metadata'))
     source=next(row for row in rows if row.get('scanner_cvss'))
     severity_path='findings/'+source['_id']+'/severity'
     decision=post(severity_path,{'severity':'high','reason':'Synthetic business impact review','expected_version':0})
     assert decision['severity']=='high' and decision['scanner_severity']=='low' and decision['verification']=='imported-unverified',decision
     assert decision['scanner_cvss']==source['scanner_cvss']
     repeated=post('imports',{'assessment_id':assessment['id'],'asset_id':asset['id'],'scanner':'trivy','content':json.dumps(TRIVY_FACTS)})
     assert repeated['finding_count']==0 and db.findings.find_one({'_id':source['_id']})['severity']=='high'
     overridden=client.get('/api/assessments/'+assessment['id']+'/findings/export').json()
     exported_decision=next(row for row in overridden['findings'] if row['id']==source['_id'])
     assert exported_decision['severity']=='high' and exported_decision['scanner_severity']=='low' and exported_decision['severity_override']['reason']=='Synthetic business impact review',exported_decision
     assert client.post('/api/'+severity_path,headers=headers(),json={'severity':'critical','reason':'Stale synthetic decision','expected_version':0}).status_code==409
     restored=post(severity_path,{'severity':None,'reason':'Restore scanner source rating','expected_version':1})
     assert restored['severity']=='low' and restored['scanner_severity']=='low' and restored['severity_override'] is None,restored
     history=client.get('/api/findings/'+source['_id']+'/severity-history').json()
     assert history['total']==2 and history['events'][0]['actor_id']==user['id'] and history['events'][1]['decision']=='restore_scanner',history
     from concurrent.futures import ThreadPoolExecutor
     stable_headers=headers()
     def race(severity):return client.post('/api/'+severity_path,headers=stable_headers,json={'severity':severity,'reason':'Concurrent synthetic severity decision','expected_version':2}).status_code
     with ThreadPoolExecutor(max_workers=2) as pool:statuses=list(pool.map(race,['high','critical']))
     assert sorted(statuses)==[200,409],statuses
     assert db.findings.find_one({'_id':source['_id']})['severity_history_total']==3
     assert post(severity_path,{'severity':None,'reason':'Restore original source after race','expected_version':3})['severity']=='low'
     common={'org_id':org['id'],'project_id':project['id'],'asset_id':asset['id'],'assessment_id':assessment['id'],
      'created_by':user['id'],'created_at':now.isoformat(),'title':'Synthetic correlated observation','severity':'low','status':'open',
      'verification':'imported-unverified','source':'import','scanner':'semgrep','target':'fixture','cve_ids':['CVE-2099-0001'],'description':'private-correlated-detail'}
     candidates=[{**common,'_id':'candidate-'+str(i)} for i in range(30)]
     decoys=[{**common,'_id':'foreign-org','org_id':'foreign'}, {**common,'_id':'foreign-project','project_id':'foreign'},
      {**common,'_id':'foreign-asset','asset_id':'foreign'},{**common,'_id':'same-scanner','scanner':'trivy'},
      {**common,'_id':'unrelated-cve','cve_ids':['CVE-2099-9999']}]
     db.findings.insert_many(candidates+decoys)
     correlation_path='/api/findings/'+source['_id']+'/correlations'
     first=client.get(correlation_path).json();assert first['total']==30 and len(first['items'])==25 and first['has_more'],first
     second=client.get(correlation_path,params={'offset':25}).json();assert len(second['items'])==5 and not second['has_more'],second
     assert set(r['id'] for r in first['items']).isdisjoint(r['id'] for r in second['items'])
     assert all(r['common_cve_ids']==['CVE-2099-0001'] for r in first['items'])
     assert 'private-correlated-detail' not in json.dumps(first)
     assert client.get(correlation_path,params={'search':'.*'}).json()['total']==0
     assert client.get(correlation_path,headers={'x-org-id':'foreign'}).status_code==404
     before=db.jobs.count_documents({})
     body={'assessment_id':assessment['id'],'asset_id':asset['id'],'scanner':'prowler','content':'[{}]'}
     response=client.post('/api/imports',headers=headers(),json=body);assert response.status_code==422,response.text
     assert db.jobs.count_documents({})==before
     body['content']=json.dumps([PROWLER])
     assert client.post('/api/imports',headers={**headers(),'x-org-id':'foreign'},json=body).status_code==404
     member={'org_id':org['id'],'user_id':user['id']}
     db.memberships.update_one(member,{'$set':{'role':'viewer'}})
     assert client.post('/api/imports',headers=headers(),json=body).status_code==403
     assert client.post('/api/'+severity_path,headers=headers(),json={'severity':'high','reason':'Unauthorized synthetic review','expected_version':2}).status_code==403
     db.memberships.update_one(member,{'$set':{'role':'analyst','project_access':{'mode':'selected','project_ids':[]}}})
     assert client.post('/api/imports',headers=headers(),json=body).status_code==404
     assert client.get(correlation_path).status_code==404
     assert client.get('/api/findings/'+source['_id']+'/severity-history').status_code==404
     assert client.post('/api/'+severity_path,headers=headers(),json={'severity':'high','reason':'Unavailable project decision','expected_version':2}).status_code==404
     db.memberships.update_one(member,{'$set':{'role':'org_admin'}})
     db.scopes.update_one({'_id':scope['id']},{'$set':{'allowed_scanners':['trivy']}})
     assert client.post('/api/imports',headers=headers(),json=body).status_code==403
     assert db.jobs.count_documents({})==before
     assert db.audit_events.count_documents({'org_id':org['id'],'action':'jobs.created'})==9
   finally:
    mongo.drop_database(database);mongo.close()
  ''')
  result=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,timeout=60)
  self.assertEqual(result.returncode,0,result.stdout+result.stderr)
