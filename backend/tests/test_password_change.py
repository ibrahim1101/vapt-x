"""Credential changes invalidate concurrent stale sessions and tokens."""
import unittest
from unittest.mock import AsyncMock, patch, MagicMock
import test_auth_rotation
import auth, core
from fastapi import HTTPException, Response
from starlette.requests import Request

class PasswordTests(unittest.IsolatedAsyncioTestCase):
    async def test_change_uses_cas_and_rotates_session_without_returning_hash(self):
        user={'id':'alice','credential_version':2}
        with patch.object(auth,'db') as db, patch.object(auth,'verify_password',side_effect=[True,False]), patch.object(auth,'hash_password',return_value='new-hash'), patch.object(auth,'insert_identity',AsyncMock()), patch.object(auth,'establish_session',AsyncMock()) as establish:
            db.users.find_one=AsyncMock(return_value={'_id':'alice','password_hash':'old-hash','credential_version':2})
            db.auth_rate_limits.find_one_and_update=AsyncMock(return_value={'count':1})
            db.users.find_one_and_update=AsyncMock(return_value={'_id':'alice','password_hash':'new-hash','credential_version':3})
            db.sessions.update_many=AsyncMock();db.api_tokens.update_many=AsyncMock()
            result=await auth.change_password(auth.PasswordChange(current_password='old-password',new_password='new-password'),Response(),user)
            self.assertEqual(result['ok'],True);self.assertNotIn('hash',str(result))
            query,update=db.users.find_one_and_update.call_args.args
            self.assertEqual(query,{'_id':'alice','password_hash':'old-hash','credential_version':2})
            self.assertEqual(update['$inc'],{'credential_version':1})
            self.assertEqual(establish.call_args.args[0]['credential_version'],3)
            self.assertEqual(db.api_tokens.update_many.call_args.args[0]['created_by'],'alice')
    async def test_wrong_password_and_throttle_do_not_change_credentials(self):
        for count,status in [(0,403),(10,429)]:
            with patch.object(auth,'db') as db,patch.object(auth,'verify_password',return_value=False),patch.object(auth,'insert_identity',AsyncMock()):
                db.users.find_one=AsyncMock(return_value={'_id':'alice','password_hash':'old'})
                db.auth_rate_limits.find_one_and_update=AsyncMock(return_value={'count':count+1})
                with self.assertRaises(HTTPException) as error:
                    await auth.change_password(auth.PasswordChange(current_password='wrong-password',new_password='new-password'),Response(),{'id':'alice','password_hash':'old'})
                self.assertEqual(error.exception.status_code,status);db.users.find_one_and_update.assert_not_called()
    async def test_old_inflight_session_and_token_are_rejected(self):
        for bearer in (False,True):
            headers=[(b'authorization',('Bearer vaptx_'+'x'*43).encode())] if bearer else [(b'cookie',('access_token='+core.create_access_token('alice','stale')).encode())]
            with patch.object(core,'db') as db:
                db.users.find_one=AsyncMock(return_value={'_id':'alice','credential_version':1})
                db.sessions.find_one=AsyncMock(return_value={'_id':'stale','credential_version':0})
                db.api_tokens.find_one=AsyncMock(return_value={'_id':'stale','created_by':'alice','credential_version':0})
                with self.assertRaises(HTTPException) as error:await core.get_current_user(Request({'type':'http','headers':headers}))
                self.assertEqual(error.exception.status_code,401)
    async def test_refresh_cannot_upgrade_stale_session_version(self):
        case=test_auth_rotation.RefreshRotationTests();case.setUp()
        case.users.find_one.return_value={'_id':'alice','credential_version':1}
        with patch.object(auth,'db',case.db),patch.object(auth,'establish_session',AsyncMock()) as establish:
            with self.assertRaises(HTTPException):await auth.refresh(case.request(),Response())
            establish.assert_not_awaited()
