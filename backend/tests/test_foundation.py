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


class ReportIntegrityTests(unittest.IsolatedAsyncioTestCase):
    async def test_download_integrity_and_missing_files(self):
        import base64
        import reporting
        from core import Ctx, sha256_hex
        from fastapi import HTTPException
        ctx = Ctx({'id': 'alice'}, 'org-a', 'viewer')
        raw = b'%PDF-1.4 synthetic test fixture'
        good = {'data': base64.b64encode(raw).decode()}
        cases = [([], 404), ([{'data': '!invalid!'}], 409),
                 ([{'data': base64.b64encode(b'tampered').decode()}], 409),
                 ([good, good], 409), ([{}], 409), ([good], 200)]
        for files, expected in cases:
            with self.subTest(expected=expected, files=files), patch.object(reporting, 'Repository') as repo_cls, patch.object(reporting, 'audit', AsyncMock()) as audit:
                repo = repo_cls.return_value
                repo.get = AsyncMock(return_value={'sha256': sha256_hex(raw)})
                repo.list = AsyncMock(return_value=files)
                if expected == 200:
                    response = await reporting.download_report('report-a', ctx)
                    self.assertEqual(response.body, raw)
                    audit.assert_awaited_once()
                else:
                    with self.assertRaises(HTTPException) as error:
                        await reporting.download_report('report-a', ctx)
                    self.assertEqual(error.exception.status_code, expected)
                    audit.assert_not_awaited()
                repo.get.assert_awaited_once_with('reports', 'report-a')
                repo_cls.assert_called_once_with(ctx)


class CompletenessTests(unittest.IsolatedAsyncioTestCase):
    async def test_complete_list_keeps_more_than_1000_and_rejects_over_cap(self):
        from repository import Repository
        from core import Ctx
        from fastapi import HTTPException
        repo = Repository(Ctx({'id': 'alice'}, 'org-a', 'viewer'))
        with patch.object(repo, 'list', AsyncMock(return_value=[{}] * 2000)) as listing:
            self.assertEqual(len(await repo.complete_list('findings')), 2000)
            listing.assert_awaited_once_with('findings', None, limit=5001)
        with patch.object(repo, 'list', AsyncMock(return_value=[{}] * 5001)):
            with self.assertRaises(HTTPException) as error:
                await repo.complete_list('findings')
            self.assertEqual(error.exception.status_code, 413)

    async def test_workspace_discloses_truncation(self):
        import workflow
        from core import Ctx
        async def listing(collection, filters=None, limit=1000):
            return [{'id': str(i)} for i in range(1001 if collection == 'findings' else 2)]
        with patch.object(workflow, 'Repository') as repo_cls:
            repo_cls.return_value.list = AsyncMock(side_effect=listing)
            data = await workflow.workspace(None, Ctx({'id': 'alice'}, 'org-a', 'viewer'))
            self.assertEqual(data['truncated_collections'], ['findings'])
            self.assertEqual(len(data['findings']), 1000)
            self.assertEqual(len(data['assets']), 2)


class EvidenceIntegrityTests(unittest.IsolatedAsyncioTestCase):
    async def test_bad_sequences_encoding_and_size_are_rejected(self):
        import evidence
        from fastapi import HTTPException
        from unittest.mock import Mock
        item = {'id': 'e1', 'chunk_count': 2, 'size': 2}
        for chunks in [[], [{'index': 0, 'data': 'YQ=='}, {'index': 0, 'data': 'Yg=='}],
                       [{'index': 0, 'data': '!'}, {'index': 1, 'data': 'Yg=='}],
                       [{'index': 0, 'data': 'YQ=='}, {'index': 1, 'data': ''}]]:
            repo = Mock(list=AsyncMock(return_value=chunks))
            with self.assertRaises(HTTPException) as error:
                await evidence.read_bytes(repo, item)
            self.assertEqual(error.exception.status_code, 409)

    async def test_ready_evidence_cannot_be_reblessed_after_tampering(self):
        import evidence
        from core import Ctx, sha256_hex
        from fastapi import HTTPException
        item = {'id': 'e1', 'created_by': 'alice', 'status': 'ready', 'size': 4, 'sha256': sha256_hex(b'good')}
        with patch.object(evidence, 'Repository') as repo_cls, patch.object(evidence, 'read_bytes', AsyncMock(return_value=b'evil')):
            repo_cls.return_value.get = AsyncMock(return_value=item)
            repo_cls.return_value.update = AsyncMock()
            with self.assertRaises(HTTPException) as error:
                await evidence.complete('e1', Ctx({'id': 'alice'}, 'org-a', 'analyst'))
            self.assertEqual(error.exception.status_code, 409)
            repo_cls.return_value.update.assert_not_awaited()


class FindingExportTests(unittest.IsolatedAsyncioTestCase):
    async def test_csv_quotes_spreadsheet_formulas_and_retains_provenance(self):
        import csv
        import io
        import reporting
        from core import Ctx
        row = {'id': 'finding-1', 'title': '  =HYPERLINK("example")', 'description': 'multi\nline, text',
               'verification': 'imported-unverified', 'source': 'import', 'password_hash': 'must-not-export'}
        with patch.object(reporting, 'Repository') as repo_cls, patch.object(reporting, 'audit', AsyncMock()):
            repo = repo_cls.return_value
            repo.get = AsyncMock(return_value={'project_id': 'project-a'})
            repo.complete_list = AsyncMock(return_value=[row])
            response = await reporting.export_findings('assessment-a', 'csv', Ctx({'id': 'alice'}, 'org-a', 'viewer'))
            data = list(csv.DictReader(io.StringIO(response.body.decode())))
            self.assertEqual(data[0]['title'], "'" + row['title'])
            self.assertEqual(data[0]['description'], row['description'])
            self.assertEqual(data[0]['verification'], 'imported-unverified')
            self.assertNotIn('password_hash', data[0])
            repo.get.assert_awaited_once_with('assessments', 'assessment-a')
            repo.complete_list.assert_awaited_once_with('findings', {'assessment_id': 'assessment-a'})

    async def test_json_preserves_original_text_and_schema(self):
        import json
        import reporting
        from core import Ctx
        row = {'title': '=original', 'verification': 'observed', 'source': 'execution'}
        with patch.object(reporting, 'Repository') as repo_cls, patch.object(reporting, 'audit', AsyncMock()):
            repo_cls.return_value.get = AsyncMock(return_value={'project_id': 'project-a'})
            repo_cls.return_value.complete_list = AsyncMock(return_value=[row])
            response = await reporting.export_findings('assessment-a', 'json', Ctx({'id': 'alice'}, 'org-a', 'viewer'))
            data = json.loads(response.body)
            self.assertEqual(data['schema_version'], 1)
            self.assertEqual(data['finding_count'], 1)
            self.assertEqual(data['findings'][0]['title'], '=original')
            self.assertIn('provenance', data['notice'])

    async def test_foreign_assessment_and_unsupported_format_are_denied(self):
        import reporting
        from core import Ctx
        from fastapi import HTTPException
        ctx = Ctx({'id': 'alice'}, 'org-a', 'viewer')
        with self.assertRaises(HTTPException) as error:
            await reporting.export_findings('assessment-a', 'xml', ctx)
        self.assertEqual(error.exception.status_code, 422)
        with patch.object(reporting, 'Repository') as repo_cls:
            repo_cls.return_value.get = AsyncMock(side_effect=HTTPException(404, 'Not found'))
            repo_cls.return_value.complete_list = AsyncMock()
            with self.assertRaises(HTTPException) as error:
                await reporting.export_findings('foreign', 'json', ctx)
            self.assertEqual(error.exception.status_code, 404)
            repo_cls.return_value.complete_list.assert_not_awaited()
