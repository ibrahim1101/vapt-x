import asyncio
import os
import unittest
from unittest.mock import AsyncMock, patch

from config import Settings

ENV = {
    'MONGO_URL': 'mongodb://127.0.0.1:27018', 'DB_NAME': 'vaptx_test',
    'JWT_SECRET': 'test-only-' * 8, 'ADMIN_EMAIL': 'owner@example.com',
    'ADMIN_PASSWORD': 'test-only-password', 'FRONTEND_URL': 'http://localhost:3000',
    'INTERNAL_API_URL': 'http://127.0.0.1:8001', 'NMAP_BINARY': 'nmap',
    'VAPTX_LOCAL_HTTP': '1',
}
os.environ.update(ENV)


class ConfigurationTests(unittest.TestCase):
    def test_local_and_https_config(self):
        self.assertEqual(Settings.from_env(ENV).mongo_timeout_ms, 5000)
        self.assertEqual(Settings.from_env({**ENV, 'FRONTEND_URL': 'https://example.com', 'VAPTX_LOCAL_HTTP': '0'}).frontend_origin, 'https://example.com')

    def test_invalid_config_does_not_expose_values(self):
        for key, value in [('JWT_SECRET', 'REPLACE_WITH_SECRET'), ('ADMIN_PASSWORD', 'short'),
                           ('DB_NAME', 'bad/name'), ('MONGO_TIMEOUT_MS', '0'),
                           ('FRONTEND_URL', 'http://example.com'),
                           ('FRONTEND_URL', 'https://user:password@example.com'),
                           ('FRONTEND_URL', 'https://example.com/path'),
                           ('INTERNAL_API_URL', 'ftp://localhost'), ('MONGO_URL', 'https://db')]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError) as error:
                Settings.from_env({**ENV, key: value})
            if key in ("JWT_SECRET", "ADMIN_PASSWORD", "MONGO_URL"):
                self.assertNotIn(value, str(error.exception))

    def test_missing_config_lists_names(self):
        with self.assertRaisesRegex(ValueError, 'MONGO_URL'):
            Settings.from_env({})


class RequestLimitTests(unittest.IsolatedAsyncioTestCase):
    async def call(self, headers, chunks, limit=5):
        from request_limits import RequestBodyLimitMiddleware
        called = []
        messages = []
        queue = iter([{'type': 'http.request', 'body': part, 'more_body': i < len(chunks)-1} for i, part in enumerate(chunks)])
        async def receive():
            return next(queue)
        async def send(message):
            messages.append(message)
        async def app(scope, receive, send):
            called.append((await receive())['body'])
            await send({'type': 'http.response.start', 'status': 200, 'headers': []})
        await RequestBodyLimitMiddleware(app, limit)({'type': 'http', 'headers': headers}, receive, send)
        return messages[0]['status'], called

    async def test_exact_limit_replayed(self):
        self.assertEqual(await self.call([], [b'ab', b'cde']), (200, [b'abcde']))

    async def test_chunked_and_false_length_rejected_before_handler(self):
        for headers in ([], [(b'content-length', b'1')]):
            self.assertEqual(await self.call(headers, [b'abc', b'def']), (413, []))

    async def test_malformed_and_duplicate_lengths(self):
        for headers in ([(b'content-length', b'garbage')], [(b'content-length', b'-1')],
                        [(b'content-length', b'1'), (b'content-length', b'2')]):
            self.assertEqual(await self.call(headers, []), (400, []))

    async def test_oversized_header_rejected_without_read(self):
        self.assertEqual(await self.call([(b'content-length', b'6')], []), (413, []))
        self.assertEqual(await self.call([(b'content-length', b'9' * 5000)], []), (413, []))


class ApplicationTests(unittest.TestCase):
    def test_password_byte_limit(self):
        from auth import Credentials
        from pydantic import ValidationError
        Credentials(email='test@example.com', password='a' * 72)
        with self.assertRaises(ValidationError):
            Credentials(email='test@example.com', password='é' * 37)

    def test_health_and_security(self):
        import server
        from fastapi.testclient import TestClient
        from pymongo.errors import ServerSelectionTimeoutError
        # No lifespan: database readiness is mocked, not integration-tested.
        with patch.object(server, 'db') as db:
            db.command = AsyncMock(return_value={'ok': 1})
            client = TestClient(server.app)
            self.assertEqual(client.get('/api/live').status_code, 200)
            self.assertEqual(client.get('/api/health').status_code, 200)
            db.command.side_effect = ServerSelectionTimeoutError('secret connection info')
            response = client.get('/api/health')
            self.assertEqual(response.status_code, 503)
            self.assertNotIn('secret', response.text)
            self.assertEqual(client.post('/api/auth/login', json={}).status_code, 403)
            self.assertEqual(client.post('/api/organizations', headers={'origin': ENV['FRONTEND_URL']}, json={}).status_code, 403)
            self.assertEqual(client.get('/api/live').headers['x-content-type-options'], 'nosniff')

    def test_database_closed_on_initialization_failure(self):
        import server
        async def run():
            with patch.object(server, 'db') as db, patch.object(server, 'client') as client:
                db.command = AsyncMock(side_effect=RuntimeError('unavailable'))
                with self.assertRaises(RuntimeError):
                    async with server.lifespan(server.app):
                        pass
                client.close.assert_called_once()
        asyncio.run(run())


class TenantBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_repository_overrides_caller_org(self):
        from core import Ctx
        from repository import Repository
        repo = Repository(Ctx({'id': 'alice'}, 'org-a', 'analyst'))
        self.assertEqual(repo.query({'org_id': 'org-b', '_id': 'asset'}), {'org_id': 'org-a', '_id': 'asset'})

    async def test_missing_membership_denies_selected_organization(self):
        import core
        from fastapi import HTTPException
        from starlette.requests import Request
        request = Request({'type': 'http', 'headers': [(b'x-org-id', b'org-b')]})
        with patch.object(core, 'get_current_user', AsyncMock(return_value={'id': 'alice', 'active_org_id': 'org-a'})), patch.object(core, 'db') as db:
            db.memberships.find_one = AsyncMock(return_value=None)
            with self.assertRaises(HTTPException) as error:
                await core.get_ctx(request)
            self.assertEqual(error.exception.status_code, 404)
            db.memberships.find_one.assert_awaited_once_with({'org_id': 'org-b', 'user_id': 'alice'})

    async def test_scoped_tokens_cannot_expand_role_permissions(self):
        from core import Ctx
        self.assertFalse(Ctx({'id': 'alice', '_token_scopes': ['*']}, 'org-a', 'viewer').can('scan'))
        self.assertFalse(Ctx({'id': 'alice', '_token_scopes': ['read']}, 'org-a', 'org_admin').can('scan'))


class CapabilityTests(unittest.IsolatedAsyncioTestCase):
    async def test_optional_ai_needs_key_and_sdk(self):
        import workflow
        from core import Ctx
        ctx = Ctx({'id': 'alice'}, 'org-a', 'viewer')
        for key, sdk, expected in [('', None, False), ('test-only-key', None, False), ('test-only-key', object(), True)]:
            with patch.dict(os.environ, {'ANTHROPIC_API_KEY': key}), patch.object(workflow, 'find_spec', return_value=sdk):
                self.assertEqual((await workflow.capabilities(ctx))['ai'], expected)
