import unittest
from unittest.mock import AsyncMock,patch
import test_auth_rotation
import account_admin, auth, core
from fastapi import HTTPException, Response
from starlette.requests import Request

OWNER={'id':'owner','platform_role':'platform_admin'}
def body(**changes):return account_admin.AccountState(current_password='valid-password',reason='Synthetic fixture',disabled=True,expected_disabled=False,**changes)

class AccountAdminTests(unittest.IsolatedAsyncioTestCase):
    async def test_org_admin_and_api_tokens_have_no_platform_access(self):
        for user in ({'id':'u','platform_role':None},{**OWNER,'_token_scopes':['read']}):
            with patch.object(account_admin,'db') as db:
                with self.assertRaises(HTTPException) as error:await account_admin.list_accounts('',None,0,25,user)
                self.assertEqual(error.exception.status_code,403);db.users.find.assert_not_called()
    async def test_self_and_platform_owner_accounts_are_protected(self):
        with self.assertRaises(HTTPException):await account_admin.change_state('owner',body(),OWNER)
        with patch.object(account_admin,'reauthenticate',AsyncMock(return_value={'platform_role':'platform_admin'})),patch.object(account_admin,'db') as db:
            db.users.find_one=AsyncMock(return_value={'_id':'protected','platform_role':'platform_admin'})
            with self.assertRaises(HTTPException) as error:await account_admin.change_state('protected',body(),OWNER)
            self.assertEqual(error.exception.status_code,409);db.users.find_one_and_update.assert_not_called()
    async def test_state_and_epoch_cas_preserves_credentials_created_after_reactivation(self):
        with patch.object(account_admin,'reauthenticate',AsyncMock(return_value={'platform_role':'platform_admin'})),patch.object(account_admin,'account_event',AsyncMock()),patch.object(account_admin,'db') as db:
            db.users.find_one=AsyncMock(return_value={'_id':'target','disabled':True,'credential_version':2})
            db.users.find_one_and_update=AsyncMock(return_value={'_id':'target','disabled':False,'credential_version':3})
            db.sessions.update_many=AsyncMock();db.api_tokens.update_many=AsyncMock();db.mfa_attempts.delete_one=AsyncMock()
            value=account_admin.AccountState(current_password='valid-password',reason='Synthetic restore',disabled=False,expected_disabled=True)
            result=await account_admin.change_state('target',value,OWNER)
            self.assertFalse(result['disabled'])
            query,update=db.users.find_one_and_update.call_args.args
            self.assertEqual(query['credential_version'],2);self.assertTrue(query['disabled'])
            self.assertEqual(update['$inc'],{'credential_version':1})
            for collection in (db.sessions,db.api_tokens):
                self.assertIn({'credential_version':{'$lt':3}},collection.update_many.call_args.args[0]['$or'])
    async def test_stale_state_is_rejected_without_cleanup(self):
        with patch.object(account_admin,'reauthenticate',AsyncMock(return_value={'platform_role':'platform_admin'})),patch.object(account_admin,'db') as db:
            db.users.find_one=AsyncMock(return_value={'_id':'target','disabled':True})
            with self.assertRaises(HTTPException) as error:await account_admin.change_state('target',body(),OWNER)
            self.assertEqual(error.exception.status_code,409);db.users.find_one_and_update.assert_not_called()
    def test_metadata_is_explicitly_allowlisted(self):
        result=account_admin.public_account({'_id':'u','email':'fixture@example.com','password_hash':'private','mfa_secret':'private','mfa_recovery_hashes':['private']})
        self.assertNotIn('private',str(result));self.assertFalse(result['disabled'])
    async def test_disabled_user_is_rejected_for_cookie_bearer_login_and_refresh(self):
        for bearer in (False,True):
            headers=[(b'authorization',('Bearer vaptx_'+'x'*43).encode())] if bearer else [(b'cookie',('access_token='+core.create_access_token('u','s')).encode())]
            with patch.object(core,'db') as db:
                db.users.find_one=AsyncMock(return_value={'_id':'u','disabled':True})
                db.sessions.find_one=AsyncMock(return_value={'_id':'s'})
                db.api_tokens.find_one=AsyncMock(return_value={'_id':'t','created_by':'u'})
                with self.assertRaises(HTTPException):await core.get_current_user(Request({'type':'http','headers':headers}))
        with patch.object(auth,'db') as db,patch.object(auth,'charge_auth_attempt',AsyncMock()),patch.object(auth,'insert_identity',AsyncMock()),patch.object(auth,'establish_session',AsyncMock()) as establish:
            db.auth_attempts.count_documents=AsyncMock(return_value=0);db.users.find_one=AsyncMock(return_value={'_id':'u','disabled':True})
            with self.assertRaises(HTTPException):await auth.login(auth.Credentials(email='fixture@example.com',password='valid-password'),Response())
            establish.assert_not_awaited()
        case=test_auth_rotation.RefreshRotationTests();case.setUp()
        case.users.find_one.return_value={'_id':'alice','disabled':True}
        with patch.object(auth,'db',case.db),patch.object(auth,'establish_session',AsyncMock()) as establish:
            with self.assertRaises(HTTPException):await auth.refresh(case.request(),Response())
            establish.assert_not_awaited()
