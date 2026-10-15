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
                    scope = post('scopes', {'project_id': project['id'], 'target': 'training://local',
                        'authorization_reference': 'Synthetic integration fixture', 'authorized': True,
                        'starts_at': (now-timedelta(hours=1)).isoformat(), 'ends_at': (now+timedelta(hours=1)).isoformat(),
                        'allowed_scanners': ['safe', 'semgrep']})
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
                    response = client.patch('/api/assets/' + asset['id'], headers=headers(), json={
                        'name': 'Updated asset', 'owner': 'Fixture team', 'criticality': 'high',
                        'tags': [' production ', 'api', 'api'], 'target': 'https://different.example'})
                    assert response.status_code == 200, response.text
                    saved = mongo[database].assets.find_one({'_id': asset['id']})
                    assert saved['target'] == 'training://local' and saved['scope_id'] == scope['id']
                    assert saved['tags'] == ['production', 'api'] and saved['criticality'] == 'high'
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
                    retest = post('assessments/' + assessment['id'] + '/retest', {})
                    response = client.get('/api/assessments/' + retest['id'] + '/comparison')
                    assert response.status_code == 200, response.text
                    assert len(response.json()['not_retested']) == 1
                    # Tampering with stored bytes must fail closed, not become a successful download.
                    mongo[database].report_files.update_one({'report_id': report['id']}, {'$set': {'data': base64.b64encode(b'tampered').decode()}})
                    assert client.get('/api/reports/' + report['id'] + '/download').status_code == 409
                    revoked = post('scopes/' + scope['id'] + '/revoke', {'reason': 'Synthetic engagement completed'})
                    assert revoked['authorized'] is False
                    assert revoked['revocation_reason'] == 'Synthetic engagement completed'
                    blocked = client.post('/api/imports', headers=headers(), json={'assessment_id': assessment['id'], 'asset_id': asset['id'], 'scanner': 'semgrep', 'content': fixture})
                    assert blocked.status_code == 403, blocked.text
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
                    assert all(row['org_id'] == org['id'] for row in page['items'])
                    assert client.get('/api/findings', params={'limit': 101}).status_code == 422
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
