"""Queued execution must not outlive revocation of its initiating authority."""
import unittest
from unittest.mock import AsyncMock, patch
import test_projects
from core import Ctx
import scanners

class ExecutionCredentialTests(unittest.IsolatedAsyncioTestCase):
    async def test_disabled_missing_or_rotated_owner_stops_before_network(self):
        for user in (None, {'disabled': True}, {'credential_version': 2}):
            with self.subTest(user=user), patch.object(scanners, 'db') as db, patch.object(scanners, 'Repository') as repo, patch.object(scanners, 'audit', new_callable=AsyncMock), patch.object(scanners, 'safe_checks', new_callable=AsyncMock) as checks, patch.object(scanners, 'resolve_public', new_callable=AsyncMock) as resolve:
                db.users.find_one=AsyncMock(return_value=user)
                repo.return_value.get=AsyncMock(return_value={'status':'queued'})
                repo.return_value.update=AsyncMock()
                await scanners.run_job(Ctx({'id':'u'}, 'org', 'analyst'), 'job')
                checks.assert_not_awaited();resolve.assert_not_awaited()
                db.memberships.find_one.assert_not_called()
                fields=repo.return_value.update.call_args.args[2]
                self.assertEqual(fields['status'],'failed')
                self.assertIn('credentials changed',fields['error'])

    async def test_missing_expired_or_rotated_session_is_denied(self):
        with patch.object(scanners,'db') as db:
            db.users.find_one=AsyncMock(return_value={'credential_version':1})
            db.sessions.find_one=AsyncMock(return_value=None)
            ctx=Ctx({'id':'u','_sid':'session','credential_version':1},'org','analyst')
            with self.assertRaisesRegex(ValueError,'Session revoked or expired'):
                await scanners.execution_credentials(ctx)
            query=db.sessions.find_one.call_args.args[0]
            self.assertEqual(query['_id'],'session');self.assertEqual(query['revoked'],False)
            self.assertIn('$gt',query['expires_at'])
            db.sessions.find_one.return_value={'credential_version':0}
            with self.assertRaises(ValueError):await scanners.execution_credentials(ctx)
            db.sessions.find_one.return_value={'credential_version':1}
            await scanners.execution_credentials(ctx)

    async def test_live_token_is_owner_tenant_epoch_expiry_bound_and_refreshes_caps(self):
        with patch.object(scanners,'db') as db:
            db.users.find_one=AsyncMock(return_value={'credential_version':3})
            db.api_tokens.find_one=AsyncMock(return_value=None)
            ctx=Ctx({'id':'u','credential_version':3,'_api_token_id':'token','_token_membership_id':'membership','_token_scopes':['scan'],'_token_project_ids':None},'org','analyst')
            with self.assertRaisesRegex(ValueError,'API token revoked or expired'):
                await scanners.execution_credentials(ctx)
            query=db.api_tokens.find_one.call_args.args[0]
            self.assertEqual({k:query[k] for k in ('_id','org_id','created_by','revoked','credential_version')},{'_id':'token','org_id':'org','created_by':'u','revoked':False,'credential_version':3})
            self.assertIn('$gt',query['expires_at'])
            db.api_tokens.find_one.return_value={'membership_id':'different','scopes':['scan']}
            with self.assertRaisesRegex(ValueError,'membership changed'):await scanners.execution_credentials(ctx)
            db.api_tokens.find_one.return_value={'membership_id':'membership','scopes':['read'],'project_ids':[]}
            await scanners.execution_credentials(ctx)
            self.assertFalse(ctx.can('scan'));self.assertEqual(ctx.user['_token_project_ids'],[])
            db.sessions.find_one.assert_not_called()
