import unittest
from unittest.mock import AsyncMock,patch
import test_auth_rotation
import auth
from fastapi import HTTPException

class AccountHistoryTests(unittest.IsolatedAsyncioTestCase):
    async def test_history_is_owned_and_returns_only_allowed_metadata(self):
        with patch.object(auth,'db') as db:
            db.account_events.count_documents=AsyncMock(return_value=1005)
            db.account_events.find.return_value.sort.return_value.skip.return_value.limit.return_value.to_list=AsyncMock(return_value=[{'_id':'event','action':'mfa.enabled','created_at':'2026-10-15T00:00:00Z','secret':'never-return'}])
            result=await auth.security_events(1000,25,{'id':'alice'})
            self.assertEqual(result['total'],1005)
            self.assertEqual(set(result['items'][0]),{'id','action','created_at'})
            self.assertEqual(db.account_events.find.call_args.args[0],{'user_id':'alice'})
    async def test_api_token_cannot_read_history(self):
        with patch.object(auth,'db') as db:
            with self.assertRaises(HTTPException):await auth.security_events(0,25,{'id':'alice','_token_scopes':['read']})
            db.account_events.find.assert_not_called()
    async def test_recording_failure_does_not_break_credential_changes_or_log_details(self):
        with patch.object(auth,'insert_identity',AsyncMock(side_effect=RuntimeError('synthetic-secret'))),self.assertLogs('auth',level='WARNING') as logs:
            await auth.account_event('alice','password.changed')
        self.assertNotIn('synthetic-secret',str(logs.output))
