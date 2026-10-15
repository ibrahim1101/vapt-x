import asyncio
import json
import os
import unittest
from unittest.mock import AsyncMock,MagicMock,patch
from cryptography.fernet import Fernet
import test_projects
from core import Ctx
from fastapi import HTTPException
import webhooks

class WebhookTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.enterContext(patch.dict(os.environ,{'WEBHOOK_ENCRYPTION_KEYS':Fernet.generate_key().decode()}))
        self.enterContext(patch.object(webhooks,'OUTBOX_LOCK',asyncio.Lock()))
    def test_authenticated_encryption_and_url_constraints(self):
        raw=json.dumps({'url':'https://example.com/private-path','secret':'synthetic-secret'}).encode()
        token=webhooks.cipher().encrypt(raw)
        self.assertNotIn(b'synthetic-secret',token);self.assertEqual(webhooks.cipher().decrypt(token),raw)
        for url in ('http://example.com','https://example.com:8443','https://user:password@example.com','https://example.com?token=secret','https://example.com/\nheader'):
            with self.assertRaises(ValueError):webhooks.validate_url(url)
    async def test_pinned_signed_transport_without_proxy_or_redirects(self):
        config=webhooks.cipher().encrypt(json.dumps({'url':'https://example.com/hook','secret':'synthetic-secret'}).encode()).decode()
        delivery={'_id':'delivery','event':'finding.triaged','payload':{'schema_version':1}}
        manager=MagicMock();manager.__aenter__=AsyncMock(return_value=MagicMock(status_code=204));manager.__aexit__=AsyncMock()
        client=MagicMock();client.stream.return_value=manager
        container=MagicMock();container.__aenter__=AsyncMock(return_value=client);container.__aexit__=AsyncMock()
        with patch.object(webhooks,'resolve_public',new_callable=AsyncMock,return_value='93.184.216.34'),patch.object(webhooks.httpx,'AsyncClient',return_value=container) as constructor:
            self.assertEqual(await webhooks.send({'encrypted_configuration':config},delivery),204)
            constructor.assert_called_once_with(timeout=10,follow_redirects=False,trust_env=False)
            args,kwargs=client.stream.call_args
            self.assertEqual(args,('POST','https://93.184.216.34:443/hook'))
            self.assertEqual(kwargs['headers']['Host'],'example.com')
            self.assertEqual(kwargs['extensions'],{'sni_hostname':'example.com'})
            expected=webhooks.sign('synthetic-secret',kwargs['content'],kwargs['headers']['X-VAPTX-Timestamp'])
            self.assertEqual(kwargs['headers']['X-VAPTX-Signature'],expected)
    async def test_private_destination_and_readonly_creation_are_denied(self):
        with patch.object(webhooks,'resolve_public',new_callable=AsyncMock,side_effect=ValueError('Private IP')):
            with self.assertRaises(HTTPException) as error:
                await webhooks.create_hook(webhooks.HookInput(name='Synthetic',url='https://example.com/hook',events=['finding.triaged']),Ctx({'id':'admin'},'org','org_admin'))
            self.assertEqual(error.exception.status_code,422)
        with self.assertRaises(HTTPException):
            await webhooks.create_hook(webhooks.HookInput(name='Synthetic',url='https://example.com/hook',events=['finding.triaged']),Ctx({'id':'analyst'},'org','analyst'))
    async def test_retry_budget_and_lease_guard(self):
        with patch.object(webhooks,'db') as database,patch.object(webhooks,'send',new_callable=AsyncMock,side_effect=ValueError('Sensitive internal error')):
            database.webhook_deliveries.find_one_and_update=AsyncMock(return_value={'_id':'delivery','org_id':'org','webhook_id':'hook','attempts':5,'cycle_attempts':5,'lease_id':'lease'})
            database.webhooks.find_one=AsyncMock(return_value={'_id':'hook'})
            database.webhook_deliveries.update_one=AsyncMock()
            await webhooks.deliver_one()
            query,update=database.webhook_deliveries.update_one.call_args.args
            self.assertEqual(query['lease_id'],'lease');self.assertEqual(update['$set']['status'],'failed')
            self.assertNotIn('Sensitive',update['$set']['last_error'])
    async def test_disabled_integration_does_not_enqueue(self):
        with patch.dict(os.environ,{'WEBHOOK_ENCRYPTION_KEYS':''}),patch.object(webhooks,'db') as database:
            await webhooks.dispatch_event('org','finding.triaged',{'id':'event'})
            database.webhooks.find.assert_not_called()
