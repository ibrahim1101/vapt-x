"""Authorization and SSRF regression tests; all transports and DNS are mocked."""
import os
import socket
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

for key, value in {
    'MONGO_URL': 'mongodb://127.0.0.1:27018', 'DB_NAME': 'vaptx_test',
    'JWT_SECRET': 'test-only-' * 8, 'ADMIN_EMAIL': 'owner@example.com',
    'ADMIN_PASSWORD': 'test-only-password', 'FRONTEND_URL': 'http://localhost:3000',
    'INTERNAL_API_URL': 'http://127.0.0.1:8001', 'NMAP_BINARY': 'nmap',
    'VAPTX_LOCAL_HTTP': '1',
}.items():
    os.environ.setdefault(key, value)

import httpx
from fastapi import HTTPException
import scanners


class ScopeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        now = datetime.now(timezone.utc)
        self.scope = {
            'project_id': 'project-a', 'authorized': True, 'host': 'example.com',
            'starts_at': (now - timedelta(hours=1)).isoformat(),
            'ends_at': (now + timedelta(hours=1)).isoformat(),
            'allowed_scanners': ['safe'],
        }
        self.repo = AsyncMock()
        self.repo.get.return_value = self.scope
        self.assessment = {'project_id': 'project-a', 'asset_ids': ['asset-a']}
        self.asset = {'id': 'asset-a', 'project_id': 'project-a', 'scope_id': 'scope-a',
                      'target': 'https://example.com/path'}

    async def test_exact_host_authorization(self):
        self.assertEqual(await scanners.validate_scope(self.repo, self.assessment, self.asset, 'safe'), self.scope)
        for target in ('https://sub.example.com', 'https://example.com.evil.test'):
            with self.subTest(target=target), self.assertRaises(HTTPException) as error:
                await scanners.validate_scope(self.repo, self.assessment, {**self.asset, 'target': target}, 'safe')
            self.assertEqual(error.exception.status_code, 403)

    async def test_scope_cannot_cross_project(self):
        self.scope['project_id'] = 'project-b'
        with self.assertRaises(HTTPException) as error:
            await scanners.validate_scope(self.repo, self.assessment, self.asset, 'safe')
        self.assertEqual(error.exception.status_code, 403)

    async def test_asset_must_be_in_assessment_and_project(self):
        for updates in ({'project_id': 'project-b'}, {'id': 'asset-b'}):
            with self.subTest(updates=updates), self.assertRaises(HTTPException) as error:
                await scanners.validate_scope(self.repo, self.assessment, {**self.asset, **updates}, 'safe')
            self.assertEqual(error.exception.status_code, 400)
        self.repo.get.assert_not_awaited()

    async def test_authorization_window_and_scanner_enforced(self):
        now = datetime.now(timezone.utc)
        for updates in ({'authorized': False}, {'allowed_scanners': ['nmap']},
                        {'starts_at': (now + timedelta(hours=2)).isoformat()},
                        {'ends_at': (now - timedelta(hours=2)).isoformat()}):
            self.repo.get.return_value = {**self.scope, **updates}
            with self.subTest(updates=updates), self.assertRaises(HTTPException) as error:
                await scanners.validate_scope(self.repo, self.assessment, self.asset, 'safe')
            self.assertEqual(error.exception.status_code, 403)


class NetworkSafetyTests(unittest.IsolatedAsyncioTestCase):
    async def test_dns_rejects_private_reserved_and_mixed_answers(self):
        for ips in ([], ['127.0.0.1'], ['10.0.0.1'], ['169.254.169.254'], ['::1'],
                    ['fc00::1'], ['192.0.2.1'], ['8.8.8.8', '10.0.0.1']):
            answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 0)) for ip in ips]
            with self.subTest(ips=ips), patch.object(scanners.socket, 'getaddrinfo', return_value=answers), self.assertRaises(ValueError):
                await scanners.resolve_public('example.com')

    async def test_dns_selects_public_address(self):
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 0))]
        with patch.object(scanners.socket, 'getaddrinfo', return_value=answers):
            self.assertEqual(await scanners.resolve_public('example.com'), '8.8.8.8')

    async def test_transport_pins_ip_preserves_host_and_sni_without_redirects(self):
        requests = []
        def handler(request):
            requests.append(request)
            return httpx.Response(302, headers={'location': 'http://127.0.0.1/private'}, content=b'redirect')
        original_client = httpx.AsyncClient
        def client_factory(**kwargs):
            self.assertFalse(kwargs['trust_env'])
            self.assertFalse(kwargs['follow_redirects'])
            return original_client(transport=httpx.MockTransport(handler), **kwargs)
        with patch.object(scanners.httpx, 'AsyncClient', side_effect=client_factory):
            status, _, body = await scanners.fetch_pinned('https://example.com:8443/a?q=1', '8.8.8.8')
        self.assertEqual((status, body), (302, b'redirect'))
        self.assertEqual(len(requests), 1)
        self.assertEqual(str(requests[0].url), 'https://8.8.8.8:8443/a?q=1')
        self.assertEqual(requests[0].headers['host'], 'example.com:8443')
        self.assertEqual(requests[0].extensions['sni_hostname'], 'example.com')

    async def test_response_size_limit(self):
        original_client = httpx.AsyncClient
        def client_factory(**kwargs):
            return original_client(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b'123456')), **kwargs)
        with patch.object(scanners.httpx, 'AsyncClient', side_effect=client_factory), self.assertRaisesRegex(ValueError, 'limit'):
            await scanners.fetch_pinned('https://example.com', '8.8.8.8', max_bytes=5)

    def test_invalid_target_urls_rejected(self):
        for target in ('ftp://example.com', 'https://user:pass@example.com',
                       'https://example.com/#fragment', 'https://example.com:22', 'https://example.com:bad'):
            with self.subTest(target=target), self.assertRaises(ValueError):
                scanners.target_host(target)
