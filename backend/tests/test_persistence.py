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
                    asset = post('assets', {'project_id': project['id'], 'scope_id': scope['id'],
                        'name': 'Owned fixture', 'target': 'training://local'})
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
                    # A second organization cannot retrieve or mutate any first-organization resource.
                    response = client.post('/api/auth/register', headers=origin, json={'email': 'bob@example.com', 'password': 'integration-password'})
                    assert response.status_code == 200, response.text
                    post('organizations', {'name': 'Bob org'})
                    for path in ['jobs/' + job['id'], 'evidence/' + evidence['id'] + '/download', 'reports/' + report['id'] + '/download', 'assessments/' + retest['id'] + '/comparison']:
                        assert client.get('/api/' + path).status_code == 404, path
                    response = client.patch('/api/findings/' + finding['id'], headers=headers(), json={'status': 'resolved'})
                    assert response.status_code == 404
            finally:
                mongo.drop_database(database)
                mongo.close()
        ''')
        result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
