"""Refresh rotation must consume each session at most once."""
import asyncio
from copy import deepcopy
from datetime import timedelta
import os
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

# Standalone collection must not depend on another test module's import order.
os.environ.update({
    'MONGO_URL': 'mongodb://127.0.0.1:27018', 'DB_NAME': 'vaptx_test',
    'JWT_SECRET': 'test-only-' * 8, 'ADMIN_EMAIL': 'owner@example.com',
    'ADMIN_PASSWORD': 'test-only-password', 'FRONTEND_URL': 'http://localhost:3000',
    'INTERNAL_API_URL': 'http://127.0.0.1:8001', 'NMAP_BINARY': 'nmap',
    'VAPTX_LOCAL_HTTP': '1',
})

import auth
from core import create_access_token, create_refresh_token, iso, now
from fastapi import HTTPException, Response
from starlette.requests import Request


class Sessions:
    """Model Mongo's atomic conditional update and yielding separate operations."""
    def __init__(self, document):
        self.document = document
        self.lock = asyncio.Lock()

    def matches(self, query):
        for key, value in query.items():
            actual = self.document.get(key)
            if isinstance(value, dict):
                if actual is None or actual <= value['$gt']:
                    return False
            elif actual != value:
                return False
        return True

    async def find_one(self, query):
        result = deepcopy(self.document) if self.matches(query) else None
        await asyncio.sleep(0)
        return result

    async def update_one(self, query, update):
        if self.matches(query):
            self.document.update(update['$set'])
        await asyncio.sleep(0)

    async def find_one_and_update(self, query, update):
        await asyncio.sleep(0)
        async with self.lock:
            if not self.matches(query):
                return None
            original = deepcopy(self.document)
            self.document.update(update['$set'])
            return original


class RefreshRotationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.sessions = Sessions({
            '_id': 'old-session', 'user_id': 'alice', 'revoked': False,
            'expires_at': iso(now() + timedelta(days=1)),
        })
        self.users = SimpleNamespace(find_one=AsyncMock(return_value={
            '_id': 'alice', 'email': 'alice@example.com',
        }))
        self.db = SimpleNamespace(sessions=self.sessions, users=self.users)

    def request(self, token=None):
        if token is None:
            token = create_refresh_token('alice', 'old-session')
        return Request({'type': 'http', 'headers': [
            (b'cookie', f'refresh_token={token}'.encode()),
        ]})

    async def test_concurrent_refresh_and_later_replay_issue_only_one_session(self):
        replacement = {'id': 'alice', 'email': 'alice@example.com'}
        with patch.object(auth, 'db', self.db), patch.object(auth, 'establish_session', AsyncMock(return_value=replacement)) as establish:
            results = await asyncio.gather(*[
                auth.refresh(self.request(), Response()) for _ in range(20)
            ], return_exceptions=True)
            self.assertEqual(sum(result == replacement for result in results), 1)
            failures = [result for result in results if isinstance(result, HTTPException)]
            self.assertEqual(len(failures), 19)
            self.assertTrue(all(error.status_code == 401 for error in failures))
            with self.assertRaises(HTTPException) as replay:
                await auth.refresh(self.request(), Response())
            self.assertEqual(replay.exception.status_code, 401)
            establish.assert_awaited_once()
            self.assertTrue(self.sessions.document['revoked'])

    async def test_invalid_or_inactive_session_never_issues_replacement(self):
        cases = [
            ({'revoked': True}, None),
            ({'expires_at': iso(now() - timedelta(seconds=1))}, None),
            ({'user_id': 'bob'}, None),
            ({'_id': 'different-session'}, None),
            ({}, create_access_token('alice', 'old-session')),
            ({}, 'malformed'),
        ]
        for changes, token in cases:
            with self.subTest(changes=changes, token=token):
                self.setUp()
                self.sessions.document.update(changes)
                with patch.object(auth, 'db', self.db), patch.object(auth, 'establish_session', AsyncMock()) as establish:
                    with self.assertRaises(HTTPException) as rejected:
                        await auth.refresh(self.request(token), Response())
                    self.assertEqual(rejected.exception.status_code, 401)
                    establish.assert_not_awaited()

    async def test_replacement_failure_leaves_old_session_consumed(self):
        with patch.object(auth, 'db', self.db), patch.object(auth, 'establish_session', AsyncMock(side_effect=RuntimeError('write failed'))) as establish:
            with self.assertRaises(RuntimeError):
                await auth.refresh(self.request(), Response())
            with self.assertRaises(HTTPException) as replay:
                await auth.refresh(self.request(), Response())
            self.assertEqual(replay.exception.status_code, 401)
            establish.assert_awaited_once()

    async def test_success_preserves_public_user_and_sets_rotated_cookies(self):
        from http.cookies import SimpleCookie
        from core import decode_token
        response = Response()
        with patch.object(auth, 'db', self.db), patch.object(auth, 'insert_identity', AsyncMock()) as insert:
            result = await auth.refresh(self.request(), response)
        self.assertEqual(result['id'], 'alice')
        self.assertEqual(result['email'], 'alice@example.com')
        self.assertNotIn('password_hash', result)
        insert.assert_awaited_once()
        collection, session = insert.call_args.args
        self.assertEqual(collection, 'sessions')
        self.assertNotEqual(session['id'], 'old-session')
        cookies = SimpleCookie()
        for header in response.headers.getlist('set-cookie'):
            cookies.load(header)
        for name, token_type in [('access_token', 'access'), ('refresh_token', 'refresh')]:
            token = decode_token(cookies[name].value)
            self.assertEqual(token['sid'], session['id'])
            self.assertEqual(token['sub'], 'alice')
            self.assertEqual(token['type'], token_type)
            self.assertTrue(cookies[name]['httponly'])
        self.assertTrue(cookies['csrf'].value)
