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
            finally:
                mongo.drop_database(database)
                mongo.close()
        ''')
        result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
