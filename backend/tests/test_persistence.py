"""Opt-in Mongo integration tests. Run only against a disposable test server."""
import os
import subprocess
import sys
import textwrap
import unittest


@unittest.skipUnless(os.environ.get('MONGO_TEST_URL'), 'Set MONGO_TEST_URL to a disposable MongoDB server')
class PersistenceTests(unittest.TestCase):
    def test_identity_org_session_persistence_and_tenant_isolation(self):
        # Separate process keeps global Motor/event-loop state out of unit tests.
        code = textwrap.dedent('''
            import os, uuid
            from pymongo import MongoClient
            from fastapi.testclient import TestClient
            database = 'vaptx_test_' + uuid.uuid4().hex
            os.environ.update(MONGO_URL=os.environ['MONGO_TEST_URL'], DB_NAME=database,
                JWT_SECRET='integration-only-' * 4, ADMIN_EMAIL='owner@example.com',
                ADMIN_PASSWORD='integration-only-password', FRONTEND_URL='http://localhost:3000',
                INTERNAL_API_URL='http://127.0.0.1:8001', NMAP_BINARY='nmap', VAPTX_LOCAL_HTTP='1')
            from server import app
            mongo = MongoClient(os.environ['MONGO_TEST_URL'], serverSelectionTimeoutMS=5000)
            try:
                with TestClient(app) as client:
                    origin = {'origin': 'http://localhost:3000'}
                    def headers():
                        return {**origin, 'x-csrf-token': client.cookies.get('csrf')}
                    response = client.post('/api/auth/register', headers=origin,
                        json={'email':'alice@example.com','password':'integration-password'})
                    assert response.status_code == 200, response.text
                    user = response.json()
                    assert mongo[database].users.find_one({'_id':user['id']})
                    response = client.post('/api/organizations', headers=headers(), json={'name':'Alice org'})
                    assert response.status_code == 200, response.text
                    org = response.json()
                    assert mongo[database].memberships.find_one({'org_id':org['id'],'user_id':user['id']})
                    assert client.get('/api/auth/me').json()['organizations'][0]['id'] == org['id']
                    assert client.get('/api/members', headers={'x-org-id':'other-tenant'}).status_code == 404
                    assert client.post('/api/auth/refresh', headers=headers()).status_code == 200
                    assert mongo[database].sessions.count_documents({'user_id':user['id'],'revoked':True}) == 1
                    assert client.post('/api/auth/logout', headers=headers()).status_code == 200
                    assert client.get('/api/auth/me').status_code == 401
                    response = client.post('/api/auth/login', headers=origin,
                        json={'email':'alice@example.com','password':'integration-password'})
                    assert response.status_code == 200, response.text
                    assert client.get('/api/auth/me').json()['active_org_id'] == org['id']
                    import json, base64
                    from datetime import datetime, timezone, timedelta
                    def post(path, body):
                        response = client.post('/api/' + path, headers=headers(), json=body)
                        assert response.status_code == 200, (path, response.text)
                        return response.json()
                    project = post('projects', {'name': 'Controlled integration'})
                    now = datetime.now(timezone.utc)
                    template = post('project-templates', {'name':'Synthetic template', 'description':'Reusable synthetic context'})
                    from_template = post('projects', {'name':'Template derived project','template_id':template['id']})
                    assert from_template['description'] == 'Reusable synthetic context'
                    assert any(row['id'] == template['id'] for row in client.get('/api/project-templates').json())
                    scope = post('scopes', {'project_id': project['id'], 'target': 'training://local',
                        'authorization_reference': 'Synthetic integration fixture', 'authorized': True,
                        'starts_at': (now-timedelta(hours=1)).isoformat(), 'ends_at': (now+timedelta(hours=1)).isoformat(),
                        'allowed_scanners': ['safe', 'semgrep', 'gitleaks', 'checkov', 'openapi', 'cyclonedx', 'spdx']})
                    response = client.patch('/api/projects/' + project['id'], headers=headers(),
                        json={'name': 'Updated fixture project', 'description': 'Retained context', 'owner': 'Fixture team', 'status': 'archived'})
                    assert response.status_code == 200, response.text
                    saved = mongo[database].projects.find_one({'_id': project['id'], 'org_id': org['id']})
                    assert saved['owner'] == 'Fixture team' and saved['status'] == 'archived'
                    response = client.patch('/api/projects/' + project['id'], headers=headers(),
                        json={'name': 'Updated fixture project', 'owner': 'Fixture team', 'status': 'active'})
                    assert response.status_code == 200, response.text
                    asset = post('assets', {'project_id': project['id'], 'scope_id': scope['id'],
                        'name': 'Owned fixture', 'target': 'training://local'})
                    receipt = post('assets/bulk', {'assets':[{'project_id':project['id'], 'scope_id':scope['id'],
                        'name':'Duplicate fixture', 'target':'training://local'}]})
                    assert receipt['duplicate'] == 1 and receipt['created'] == 0
                    response = client.patch('/api/assets/' + asset['id'], headers=headers(), json={
                        'name': 'Updated asset', 'owner': 'Fixture team', 'criticality': 'high',
                        'tags': [' production ', 'api', 'api'], 'target': 'https://different.example'})
                    assert response.status_code == 200, response.text
                    saved = mongo[database].assets.find_one({'_id': asset['id']})
                    assert saved['target'] == 'training://local' and saved['scope_id'] == scope['id']
                    assert saved['tags'] == ['production', 'api'] and saved['criticality'] == 'high'
                    history = client.get('/api/assets/' + asset['id'] + '/history').json()
                    assert any(event['action'] == 'assets.updated' for event in history['events'])
                    assert client.get('/api/assets', params={'search': 'production', 'criticality': 'high'}).json()['total'] == 1

                    assessment = post('assessments', {'project_id': project['id'], 'name': 'Fixture assessment', 'asset_ids': [asset['id']]})
                    fixture = json.dumps({'results': [{'check_id': 'fixture-rule', 'path': 'fixture.py',
                        'extra': {'message': 'Synthetic observation', 'severity': 'WARNING'}}]})
                    job = post('imports', {'assessment_id': assessment['id'], 'asset_id': asset['id'], 'scanner': 'semgrep', 'content': fixture})
                    assert job['finding_count'] == 1
                    workspace = client.get('/api/workspace', params={'project_id': project['id']}).json()
                    finding = workspace['findings'][0]
                    assert finding['verification'] == 'imported-unverified'
                    assert workspace['truncated_collections'] == []
                    response = client.patch('/api/findings/' + finding['id'], headers=headers(), json={'status': 'confirmed', 'notes': 'Manually reviewed synthetic fixture'})
                    assert response.status_code == 200, response.text
                    history_path = '/api/findings/' + finding['id'] + '/history'
                    history = client.get(history_path).json()
                    assert history['total'] == 1 and history['has_more'] is False
                    event = history['events'][0]
                    assert event['previous_status'] == 'open' and event['status'] == 'confirmed'
                    assert event['previous_notes'] == '' and event['notes'] == 'Manually reviewed synthetic fixture'
                    assert event['actor_id'] == user['id'] and event['actor_email'] == 'alice@example.com'
                    assert datetime.fromisoformat(event['created_at']).tzinfo is not None
                    # Repeated identical triage is idempotent, including its durable history.
                    response = client.patch('/api/findings/' + finding['id'], headers=headers(), json={'status': 'confirmed', 'notes': 'Manually reviewed synthetic fixture'})
                    assert response.status_code == 200, response.text
                    assert client.get(history_path).json()['total'] == 1
                    # Seed only the disposable fixture's old history to exercise Mongo's bounded push.
                    prior_events = [{**event, 'notes': 'Synthetic historical event ' + str(i)} for i in range(100)]
                    mongo[database].findings.update_one({'_id': finding['id']}, {'$set': {'triage_history': prior_events, 'history_total': 105}})
                    response = client.patch('/api/findings/' + finding['id'], headers=headers(), json={'status': 'confirmed', 'notes': 'Second synthetic review'})
                    assert response.status_code == 200, response.text
                    updated = response.json()
                    assert updated['verification'] == 'imported-unverified'
                    assert updated['source'] == 'import' and updated['severity'] == finding['severity']
                    history = client.get(history_path).json()
                    assert history['total'] == 106 and history['has_more'] is True
                    assert len(history['events']) == 100
                    assert history['events'][0]['notes'] == 'Synthetic historical event 1'
                    assert history['events'][-1]['notes'] == 'Second synthetic review'
                    assert history['events'][-1]['previous_notes'] == 'Manually reviewed synthetic fixture'
                    # Triage must never rewrite provenance or imply independent verification.
                    import csv, io
                    export_path = '/api/assessments/' + assessment['id'] + '/findings/export'
                    response = client.get(export_path, params={'format': 'json'})
                    assert response.status_code == 200, response.text
                    assert response.headers['content-type'].startswith('application/json')
                    assert 'attachment;' in response.headers['content-disposition']
                    exported = response.json()
                    assert exported['assessment_id'] == assessment['id']
                    assert exported['project_id'] == project['id']
                    assert exported['finding_count'] == 1
                    json_row = exported['findings'][0]
                    response = client.get(export_path, params={'format': 'csv'})
                    assert response.status_code == 200, response.text
                    assert response.headers['content-type'].startswith('text/csv')
                    assert 'attachment;' in response.headers['content-disposition']
                    csv_rows = list(csv.DictReader(io.StringIO(response.text)))
                    assert len(csv_rows) == 1
                    for row in [json_row, csv_rows[0]]:
                        assert row['id'] == finding['id']
                        assert row['status'] == 'confirmed'
                        assert row['verification'] == 'imported-unverified'
                        assert row['source'] == 'import'
                        assert row['scanner'] == 'semgrep'
                    task = post('tasks', {'finding_id': finding['id'], 'title': 'Fix synthetic fixture'})
                    response = client.patch('/api/tasks/' + task['id'], headers=headers(), json={'status': 'done'})
                    assert response.status_code == 200, response.text
                    response = client.patch('/api/tasks/' + task['id'], headers=headers(), json={
                        'status':'in_progress', 'progress':60, 'assignee':'Synthetic remediation team', 'due_date':'2027-01-01'})
                    assert response.status_code == 200, response.text
                    saved_task = mongo[database].tasks.find_one({'_id':task['id']})
                    assert saved_task['progress'] == 60 and saved_task['completed_at'] is None
                    assert saved_task['assignee'] == 'Synthetic remediation team'
                    assert client.patch('/api/tasks/' + task['id'], headers=headers(), json={'due_date':'2026-02-30'}).status_code == 422
                    payload = b'synthetic evidence only'
                    evidence = post('evidence', {'finding_id': finding['id'], 'filename': 'fixture.txt', 'size': len(payload), 'content_type': 'text/plain'})
                    response = client.put('/api/evidence/' + evidence['id'] + '/chunks/0', headers=headers(), json={'data': base64.b64encode(payload).decode()})
                    assert response.status_code == 200, response.text
                    post('evidence/' + evidence['id'] + '/complete', {})
                    response = client.get('/api/evidence/' + evidence['id'] + '/download')
                    assert response.status_code == 200 and response.content == payload
                    report = post('assessments/' + assessment['id'] + '/report', {})
                    response = client.get('/api/reports/' + report['id'] + '/download')
                    assert response.status_code == 200 and response.content.startswith(b'%PDF-')
                    assert report['version'] == 1 and report['status'] == 'ready'
                    snapshot = client.get('/api/reports/' + report['id'] + '/snapshot').json()
                    assert snapshot['findings'][0]['verification'] == 'imported-unverified'
                    assert len(snapshot['findings']) == 1
                    executive = post('assessments/' + assessment['id'] + '/report', {'template':'executive','branding':'Synthetic CI brand','sections':[{'heading':'Context','text':'Synthetic report review'}]})
                    assert executive['version'] == 2 and executive['template'] == 'executive'
                    assert client.get('/api/reports',params={'assessment_id':assessment['id']}).json()['total'] == 2
                    response = client.post('/api/assessments/' + assessment['id'] + '/report/preview',headers=headers(),json={'template':'remediation'})
                    assert response.status_code == 200 and response.content.startswith(b'%PDF-')
                    retest = post('assessments/' + assessment['id'] + '/retest', {})
                    response = client.get('/api/assessments/' + retest['id'] + '/comparison')
                    assert response.status_code == 200, response.text
                    assert len(response.json()['not_retested']) == 1
                    # Tampering with stored bytes must fail closed, not become a successful download.
                    mongo[database].report_files.update_one({'report_id': report['id']}, {'$set': {'data': base64.b64encode(b'tampered').decode()}})
                    assert client.get('/api/reports/' + report['id'] + '/download').status_code == 409
                    sessions = client.get('/api/auth/sessions').json()
                    alice_session_id = next(session['id'] for session in sessions['sessions'] if session['current'])
                    assert all(set(session) == {'id', 'created_at', 'expires_at', 'current'} for session in sessions['sessions'])
                    other_id = uuid.uuid4().hex
                    mongo[database].sessions.insert_one({'_id': other_id, 'user_id': user['id'], 'revoked': False, 'created_at': now.isoformat(), 'expires_at': (now+timedelta(days=1)).isoformat()})
                    result = post('auth/sessions/' + other_id + '/revoke', {})
                    assert result['current'] is False
                    assert mongo[database].sessions.find_one({'_id': other_id})['revoked'] is True
                    for _ in range(2):
                        mongo[database].sessions.insert_one({'_id': uuid.uuid4().hex, 'user_id': user['id'], 'revoked': False, 'created_at': now.isoformat(), 'expires_at': (now+timedelta(days=1)).isoformat()})
                    assert post('auth/sessions/revoke-others', {})['revoked_count'] == 2
                    assert client.get('/api/auth/me').status_code == 200
                    cancelled = post('assessments/' + retest['id'] + '/cancel', {'reason':'Synthetic lifecycle validation'})
                    assert cancelled['status'] == 'cancelled'
                    response = client.post('/api/imports', headers=headers(), json={
                        'assessment_id':retest['id'], 'asset_id':asset['id'], 'scanner':'semgrep', 'content':fixture})
                    assert response.status_code == 409, response.text
                    retried = post('assessments/' + retest['id'] + '/retry', {})
                    assert retried['status'] == 'draft' and retried['retry_of'] == retest['id']
                    history = client.get('/api/assessments/' + retest['id'] + '/history').json()
                    assert any(event['action'] == 'assessment.cancelled' for event in history['events'])
                    assert client.get('/api/assessments', params={'project_id':project['id'], 'status':'cancelled'}).json()['total'] == 1
                    response = post('findings/bulk-triage', {'finding_ids':[finding['id'],finding['id']],
                        'status':'confirmed','owner':'Synthetic finding team'})
                    assert response['updated'] == 1 and response['failed'] == 0
                    saved_finding = mongo[database].findings.find_one({'_id':finding['id']})
                    assert saved_finding['owner'] == 'Synthetic finding team'
                    assert saved_finding['verification'] == 'imported-unverified'
                    # Intelligence cache remains separate from scanner observations, with no network in CI.
                    mongo[database].findings.update_one({'_id':finding['id']},{'$set':{'cve_ids':['CVE-2026-12345']}})
                    mongo[database].vulnerability_intelligence.insert_one({'_id':'epss:CVE-2026-12345',
                        'status':'available','source':'epss','source_url':'https://api.first.org/data/v1/epss',
                        'fetched_at':now.isoformat(),'facts':{'probability':0.25,'percentile':0.98,'date':'2026-10-15'}})
                    intel = client.get('/api/findings/' + finding['id'] + '/intelligence/CVE-2026-12345').json()
                    assert intel['sources']['epss']['facts']['probability'] == 0.25
                    assert intel['derived_priority']['level'] == 'high'
                    assert mongo[database].findings.find_one({'_id':finding['id']})['verification'] == 'imported-unverified'
                    for scanner, data in [('gitleaks',[{'RuleID':'synthetic-secret-rule','File':'fixture.env','StartLine':1,
                        'Description':'Synthetic secret candidate','Secret':'synthetic-secret-do-not-store','Match':'KEY=synthetic-secret-do-not-store'}]),
                        ('checkov',{'results':{'failed_checks':[{'check_id':'CKV_SYNTHETIC_1','check_name':'Synthetic IaC check',
                        'file_path':'fixture.tf','file_line_range':[1,2],'code_block':[[1,'synthetic-secret-do-not-store']]}]}})]:
                        imported = post('imports',{'assessment_id':retried['id'],'asset_id':asset['id'],'scanner':scanner,'content':json.dumps(data)})
                        assert imported['finding_count'] == 1
                        assert 'synthetic-secret-do-not-store' not in imported['raw_output']
                        observed = mongo[database].findings.find_one({'job_id':imported['id']})
                        assert observed['verification'] == 'imported-unverified'
                        assert 'synthetic-secret-do-not-store' not in json.dumps(observed)
                    for format, payload in [('openapi',{'openapi':'3.1.0','paths':{'/synthetic':{'get':{'summary':'Synthetic operation'}}}}),
                        ('cyclonedx',{'bomFormat':'CycloneDX','specVersion':'1.7','components':[{'name':'fixture-library','version':'1.0'}]}),
                        ('spdx',{'spdxVersion':'SPDX-2.3','packages':[{'SPDXID':'SPDXRef-fixture','name':'fixture-spdx','versionInfo':'1.0'}]})]:
                        job_inventory = post('inventory-imports',{'assessment_id':retried['id'],'asset_id':asset['id'],
                            'format':format,'content':json.dumps(payload)})
                        assert job_inventory['finding_count'] == 0 and job_inventory['inventory_count'] == 1
                        repeated = post('inventory-imports',{'assessment_id':retried['id'],'asset_id':asset['id'],
                            'format':format,'content':json.dumps(payload)})
                        assert repeated['inventory_count'] == 0 and repeated['duplicate_count'] == 1
                    inventory = client.get('/api/assets/' + asset['id'] + '/inventory').json()
                    assert inventory['total'] == 3
                    assert all('severity' not in row for row in inventory['items'])
                    revoked = post('scopes/' + scope['id'] + '/revoke', {'reason': 'Synthetic engagement completed'})
                    assert revoked['authorized'] is False
                    assert revoked['revocation_reason'] == 'Synthetic engagement completed'
                    blocked = client.post('/api/imports', headers=headers(), json={'assessment_id': assessment['id'], 'asset_id': asset['id'], 'scanner': 'semgrep', 'content': fixture})
                    assert blocked.status_code == 403, blocked.text
                    comment = post('findings/' + finding['id'] + '/comments', {'text':'Synthetic analyst discussion'})
                    comments = client.get('/api/findings/' + finding['id'] + '/comments').json()
                    assert comments['total'] == 1 and comments['items'][0]['id'] == comment['id']
                    response = client.put('/api/sla-policy', headers=headers(), json={'high':14,'critical':2,'medium':30,'low':90,'info':0})
                    assert response.status_code == 200, response.text
                    assert client.get('/api/sla-policy').json()['days']['high'] == 14
                    page = client.get('/api/findings', params={'assessment_id':assessment['id']}).json()
                    assert page['items'][0]['sla']['applicable'] is True
                    # Exercise optional AI persistence through a mock; never contact a paid provider.
                    from unittest.mock import patch, AsyncMock
                    with patch.dict(os.environ,{'OPENAI_API_KEY':'synthetic-only-key','OPENAI_MODEL':'synthetic-model'}), patch('analyst.answer',new_callable=AsyncMock,return_value={'text':'AI interpretation: synthetic fixture only','usage':{'input_tokens':20,'output_tokens':10}}):
                        chat=post('ai/messages',{'project_id':project['id'],'provider':'openai','model':'synthetic-model','message':'Explain password=synthetic-secret'})
                        assert chat['provider'] == 'openai' and chat['message_count'] == 2
                        assert 'synthetic-secret' not in json.dumps(chat)
                        followup=post('ai/messages',{'project_id':project['id'],'session_id':chat['id'],'provider':'openai','model':'synthetic-model','message':'Summarize coverage limitations'})
                        assert followup['message_count'] == 4 and len(followup['messages']) == 4
                        assert mongo[database].ai_usage.count_documents({'org_id':org['id']}) == 2
                    credential=post('api-tokens',{'name':'Synthetic read token','scopes':['read'],'expires_days':1})
                    bearer={'authorization':'Bearer '+credential['token']}
                    stored=mongo[database].api_tokens.find_one({'_id':credential['id']})
                    assert stored['token_hash'] != credential['token'] and 'token' not in stored
                    assert client.get('/api/workspace',headers=bearer).status_code == 200
                    assert client.get('/api/workspace',headers={**bearer,'x-org-id':'foreign'}).status_code == 404
                    assert client.post('/api/projects',headers=bearer,json={'name':'Forbidden token write'}).status_code == 403
                    assert client.post('/api/auth/sessions/revoke-others',headers=bearer).status_code == 403
                    assert client.post('/api/api-tokens',headers=bearer,json={'name':'Escalation','scopes':['write']}).status_code == 403
                    writer=post('api-tokens',{'name':'Synthetic write token','scopes':['read','write'],'expires_days':1})
                    writer_headers={'authorization':'Bearer '+writer['token']}
                    assert client.post('/api/projects',headers=writer_headers,json={'name':'API synthetic project'}).status_code == 200
                    mongo[database].memberships.update_one({'org_id':org['id'],'user_id':user['id']},{'$set':{'role':'viewer'}})
                    assert client.post('/api/projects',headers=writer_headers,json={'name':'Role demotion denial'}).status_code == 403
                    mongo[database].memberships.update_one({'org_id':org['id'],'user_id':user['id']},{'$set':{'role':'org_admin'}})
                    post('api-tokens/'+credential['id']+'/revoke',{})
                    assert client.get('/api/workspace',headers=bearer).status_code == 401
                    listed=client.get('/api/api-tokens').json()
                    assert writer['token'] not in json.dumps(listed) and 'token_hash' not in json.dumps(listed)
                    mongo[database].api_tokens.update_one({'_id':writer['id']},{'$set':{'expires_at':'2020-01-01T00:00:00+00:00'}})
                    assert client.get('/api/workspace',headers=writer_headers).status_code == 401
                    # Configure a synthetic webhook under mocks. No external destination is contacted.
                    from cryptography.fernet import Fernet
                    import webhooks
                    with patch.dict(os.environ,{'WEBHOOK_ENCRYPTION_KEYS':Fernet.generate_key().decode()}), patch('webhooks.destination',new_callable=AsyncMock,return_value=(__import__('urllib.parse',fromlist=['urlsplit']).urlsplit('https://example.com/synthetic-hook'),'93.184.216.34')):
                        hook=post('webhooks',{'name':'Synthetic destination','url':'https://example.com/synthetic-hook','events':['finding.triaged'],'enabled':False})
                        stored=mongo[database].webhooks.find_one({'_id':hook['id']})
                        assert hook['signing_secret'] not in json.dumps(stored)
                        assert 'synthetic-hook' not in json.dumps(stored)
                        assert client.post('/api/webhooks/'+hook['id']+'/test',headers=headers()).status_code == 409
                        response=client.patch('/api/webhooks/'+hook['id'],headers=headers(),json={'enabled':True})
                        assert response.status_code == 200
                        receipt=post('webhooks/'+hook['id']+'/test',{})
                        assert receipt['status'] == 'queued'
                        with patch('webhooks.send',new_callable=AsyncMock,return_value=204):
                            assert client.portal.call(webhooks.deliver_one) is True
                        delivery=mongo[database].webhook_deliveries.find_one({'_id':receipt['id']})
                        assert delivery['status'] == 'delivered'
                        assert client.get('/api/webhooks/'+hook['id']+'/deliveries').json()['total'] == 1
                        listed=client.get('/api/webhooks').json()
                        assert hook['signing_secret'] not in json.dumps(listed)
                        assert 'encrypted_configuration' not in json.dumps(listed)
                    # Navigation must reach findings beyond the workspace's 1,000-row limit.
                    mongo[database].findings.insert_many([{
                        '_id': 'page-' + str(i).zfill(5), 'org_id': org['id'], 'created_by': user['id'],
                        'created_at': now.isoformat(), 'project_id': project['id'],
                        'assessment_id': assessment['id'], 'title': 'Pagination fixture literal .*',
                        'target': 'training://local', 'severity': 'high', 'status': 'open',
                        'scanner': 'semgrep', 'verification': 'imported-unverified'} for i in range(1005)])
                    page_params = {'project_id': project['id'], 'assessment_id': assessment['id'],
                        'search': 'literal .*', 'severity': 'high', 'status': 'open', 'scanner': 'semgrep',
                        'offset': 1000, 'limit': 25}
                    response = client.get('/api/findings', params=page_params)
                    assert response.status_code == 200, response.text
                    page = response.json()
                    assert page['total'] == 1005 and len(page['items']) == 5 and not page['has_more']
                    summary = client.get('/api/analytics/summary',params={'project_id':project['id']}).json()
                    assert summary['assets'] == 1 and summary['complete_collection_counts'] is True, summary
                    assert summary['open_findings'] == mongo[database].findings.count_documents({'org_id':org['id'],'project_id':project['id'],'status':{'$nin':['resolved','false_positive']}})
                    assert client.get('/api/analytics/summary',params={'project_id':'foreign'}).status_code == 404

                    assert all(row['org_id'] == org['id'] for row in page['items'])
                    assert client.get('/api/findings', params={'limit': 101}).status_code == 422
                    mongo[database].assets.insert_many([{'_id': 'asset-page-' + str(i),
                        'org_id': org['id'], 'created_by': user['id'], 'created_at': now.isoformat(),
                        'project_id': project['id'], 'name': 'Inventory page fixture',
                        'target': 'training://local'} for i in range(1005)])
                    page = client.get('/api/assets', params={'project_id': project['id'],
                        'search': 'Inventory page fixture', 'criticality': 'medium', 'offset':1000}).json()
                    assert page['total'] == 1005 and len(page['items']) == 5 and not page['has_more']
                    summary = client.get('/api/analytics/summary',params={'project_id':project['id']}).json()
                    assert summary['assets'] == 1006 and summary['complete_collection_counts'] is True, summary
                    assert summary['open_findings'] == mongo[database].findings.count_documents({'org_id':org['id'],'project_id':project['id'],'status':{'$nin':['resolved','false_positive']}})
                    assert client.get('/api/analytics/summary',params={'project_id':'foreign'}).status_code == 404

                    mongo[database].projects.insert_many([{'_id':'project-page-'+str(i), 'org_id':org['id'],
                        'created_by':user['id'],'created_at':(now-timedelta(days=1)).isoformat(),
                        'name':'Project navigation fixture','status':'active','description':'','owner':'Pagination team'} for i in range(1005)])
                    project_page = client.get('/api/projects',params={'search':'Project navigation fixture','status':'active','offset':1000}).json()
                    assert project_page['total'] == 1005 and len(project_page['items']) == 5 and not project_page['has_more']
                    assert all(row['asset_count'] == 0 for row in project_page['items'])
                    selected_id = project_page['items'][-1]['id']
                    selected_workspace = client.get('/api/workspace',params={'project_id':selected_id}).json()
                    assert any(row['id'] == selected_id for row in selected_workspace['projects'])
                    # A second organization cannot retrieve or mutate any first-organization resource.
                    response = client.post('/api/auth/register', headers=origin, json={'email': 'bob@example.com', 'password': 'integration-password'})
                    assert response.status_code == 200, response.text
                    post('organizations', {'name': 'Bob org'})
                    for path in ['findings/' + finding['id'] + '/history', 'jobs/' + job['id'], 'evidence/' + evidence['id'] + '/download', 'reports/' + report['id'] + '/download', 'assessments/' + retest['id'] + '/comparison', 'assessments/' + assessment['id'] + '/findings/export?format=json', 'assessments/' + assessment['id'] + '/findings/export?format=csv']:
                        assert client.get('/api/' + path).status_code == 404, path
                    response = client.patch('/api/findings/' + finding['id'], headers=headers(), json={'status': 'resolved'})
                    assert response.status_code == 404
                    response = client.post('/api/scopes/' + scope['id'] + '/revoke', headers=headers(), json={'reason': 'Foreign tenant attempt'})
                    assert response.status_code == 404
                    response = client.post('/api/auth/sessions/' + alice_session_id + '/revoke', headers=headers())
                    assert response.status_code == 404
                    response = client.patch('/api/projects/' + project['id'], headers=headers(), json={'name': 'Foreign edit'})
                    assert response.status_code == 404
                    response = client.patch('/api/assets/' + asset['id'], headers=headers(), json={'name': 'Foreign edit'})
                    assert response.status_code == 404
                    assert client.get('/api/findings', params={'project_id': project['id']}).status_code == 404
                    assert client.get('/api/findings').json()['total'] == 0
                    assert client.get('/api/analytics/summary').json()['findings'] == 0
                    assert client.get('/api/assets/' + asset['id'] + '/history').status_code == 404
                    assert client.get('/api/assets', params={'project_id': project['id']}).status_code == 404
                    assert client.get('/api/assets').json()['total'] == 0
                    assert client.get('/api/assessments/' + retest['id'] + '/history').status_code == 404
                    assert client.post('/api/assessments/' + retest['id'] + '/cancel', headers=headers(), json={'reason':'Foreign tenant attempt'}).status_code == 404
                    assert client.get('/api/assessments').json()['total'] == 0
                    assert client.get('/api/project-templates').json() == []
                    assert client.post('/api/projects', headers=headers(), json={'name':'Foreign template attempt','template_id':template['id']}).status_code == 404
                    assert client.get('/api/findings/' + finding['id'] + '/intelligence/CVE-2026-12345').status_code == 404
                    assert client.get('/api/assets/' + asset['id'] + '/inventory').status_code == 404
                    assert client.get('/api/findings/' + finding['id'] + '/comments').status_code == 404
                    assert client.get('/api/sla-policy').json()['days']['high'] == 7
                    assert client.get('/api/reports/' + report['id'] + '/snapshot').status_code == 404
                    assert client.get('/api/webhooks/'+hook['id']+'/deliveries').status_code == 404
                    bob_token = post('api-tokens', {'name':'Password rotation fixture','scopes':['read']})['token']
                    old_access = client.cookies.get('access_token')
                    old_refresh = client.cookies.get('refresh_token')
                    wrong = client.post('/api/auth/password', headers=headers(), json={'current_password':'incorrect-password','new_password':'changed-password'})
                    assert wrong.status_code == 403
                    assert post('auth/password', {'current_password':'integration-password','new_password':'changed-password'})['ok']
                    assert client.get('/api/auth/me').status_code == 200
                    assert client.get('/api/projects',headers={'authorization':'Bearer '+bob_token}).status_code == 401
                    assert client.get('/api/auth/me',headers={'cookie':'access_token='+old_access}).status_code == 401
                    assert client.post('/api/auth/refresh', headers={**origin,'cookie':'refresh_token='+old_refresh+'; csrf=synthetic','x-csrf-token':'synthetic'}).status_code == 401
                    assert client.post('/api/auth/login',headers=origin,json={'email':'bob@example.com','password':'integration-password'}).status_code == 401
                    assert client.post('/api/auth/login',headers=origin,json={'email':'bob@example.com','password':'changed-password'}).status_code == 200
                    bob_sessions = client.get('/api/auth/sessions').json()['sessions']
                    bob_current = next(session['id'] for session in bob_sessions if session['current'])
                    assert post('auth/sessions/' + bob_current + '/revoke', {})['current'] is True
                    assert client.get('/api/auth/me').status_code == 401
            finally:
                mongo.drop_database(database)
                mongo.close()
        ''')
        result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
