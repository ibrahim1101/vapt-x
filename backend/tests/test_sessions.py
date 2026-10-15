"""Owned-session administration: query scope, expiry, and response privacy."""
import os
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

os.environ.update({
    'MONGO_URL': 'mongodb://127.0.0.1:27018', 'DB_NAME': 'vaptx_test',
    'JWT_SECRET': 'test-only-' * 8, 'ADMIN_EMAIL': 'owner@example.com',
    'ADMIN_PASSWORD': 'test-only-password', 'FRONTEND_URL': 'http://localhost:3000',
    'INTERNAL_API_URL': 'http://127.0.0.1:8001', 'NMAP_BINARY': 'nmap',
    'VAPTX_LOCAL_HTTP': '1',
})

import auth
from fastapi import HTTPException, Response

USER = {'id': 'alice', '_sid': 'current'}
NOW = '2026-01-01T00:00:00+00:00'


class SessionTests(unittest.IsolatedAsyncioTestCase):
    async def test_listing_scopes_expiry_bounds_and_response_privacy(self):
        rows = [{'_id': 'current' if i == 0 else str(i), 'created_at': NOW,
                 'expires_at': '2026-01-08T00:00:00+00:00',
                 'user_id': 'alice', 'access_token': 'must-not-return',
                 'password_hash': 'must-not-return'} for i in range(101)]
        for count, has_more in [(0, False), (100, False), (101, True)]:
            with self.subTest(count=count), patch.object(auth, 'db') as db, patch.object(auth, 'iso', return_value=NOW):
                cursor = db.sessions.find.return_value.sort.return_value
                cursor.to_list = AsyncMock(return_value=rows[:count])
                result = await auth.list_sessions(USER)
                db.sessions.find.assert_called_once_with(
                    {'user_id': 'alice', 'revoked': False, 'expires_at': {'$gt': NOW}},
                    {'_id': 1, 'created_at': 1, 'expires_at': 1})
                cursor.to_list.assert_awaited_once_with(101)
                self.assertEqual(len(result['sessions']), min(count, 100))
                self.assertEqual(result['has_more'], has_more)
                for row in result['sessions']:
                    self.assertEqual(set(row), {'id', 'created_at', 'expires_at', 'current'})
                    self.assertEqual(row['current'], row['id'] == 'current')

    async def test_revoke_is_atomic_owned_unexpired_and_clears_only_current_cookies(self):
        for sid in ['current', 'other']:
            with self.subTest(sid=sid), patch.object(auth, 'db') as db, patch.object(auth, 'iso', return_value=NOW):
                db.sessions.find_one_and_update = AsyncMock(return_value={'_id': sid})
                response = Response()
                result = await auth.revoke_session(sid, response, USER)
                db.sessions.find_one_and_update.assert_awaited_once_with(
                    {'_id': sid, 'user_id': 'alice', 'revoked': False, 'expires_at': {'$gt': NOW}},
                    {'$set': {'revoked': True}})
                self.assertEqual(result, {'ok': True, 'current': sid == 'current'})
                cookies = response.headers.getlist('set-cookie')
                if sid == 'current':
                    self.assertEqual(len(cookies), 3)
                    self.assertTrue(all('Max-Age=0' in cookie for cookie in cookies))
                else:
                    self.assertEqual(cookies, [])

    async def test_unmatched_session_is_not_found_and_does_not_clear_cookies(self):
        with patch.object(auth, 'db') as db:
            db.sessions.find_one_and_update = AsyncMock(return_value=None)
            response = Response()
            with self.assertRaises(HTTPException) as rejected:
                await auth.revoke_session('foreign-or-expired', response, USER)
            self.assertEqual(rejected.exception.status_code, 404)
            self.assertEqual(response.headers.getlist('set-cookie'), [])
            self.assertEqual(db.sessions.find_one_and_update.call_args.args[0]['user_id'], 'alice')

    async def test_revoke_others_excludes_current_and_foreign_sessions(self):
        with patch.object(auth, 'db') as db, patch.object(auth, 'iso', return_value=NOW):
            db.sessions.update_many = AsyncMock(return_value=SimpleNamespace(modified_count=3))
            self.assertEqual(await auth.revoke_other_sessions(USER), {'revoked_count': 3})
            db.sessions.update_many.assert_awaited_once_with(
                {'user_id': 'alice', '_id': {'$ne': 'current'}, 'revoked': False,
                 'expires_at': {'$gt': NOW}}, {'$set': {'revoked': True}})


class SessionRouteTests(unittest.TestCase):
    def test_authentication_and_csrf_are_required(self):
        from fastapi.testclient import TestClient
        import server
        client = TestClient(server.app)
        self.assertEqual(client.get('/api/auth/sessions').status_code, 401)
        for path in ['/api/auth/sessions/current/revoke', '/api/auth/sessions/revoke-others']:
            self.assertEqual(client.post(path).status_code, 403)
            self.assertEqual(client.post(path, headers={'origin': 'http://localhost:3000'}).status_code, 403)
            self.assertEqual(client.post(path, headers={
                'origin': 'http://localhost:3000', 'cookie': 'csrf=test', 'x-csrf-token': 'test',
            }).status_code, 401)
