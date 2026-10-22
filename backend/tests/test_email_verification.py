import unittest
from unittest.mock import AsyncMock,patch
import test_projects
from core import sha256_hex
from fastapi import HTTPException
import account_verification as verification

class EmailVerificationTests(unittest.IsolatedAsyncioTestCase):
    async def test_hash_only_token_bound_to_requesting_account(self):
        with patch.object(verification,'configuration',return_value={}),patch.object(verification,'db') as db,patch.object(verification,'charge_auth_attempt',new_callable=AsyncMock),patch.object(verification,'send_verification_mail') as sender:
            db.email_verifications.insert_one=AsyncMock()
            await verification.request_verification({'id':'u','email':'fixture@example.com','credential_version':2})
            raw=sender.call_args.args[2].split('verify_email_token=')[1]
            stored=db.email_verifications.insert_one.call_args.args[0]
            self.assertEqual(stored['token_hash'],sha256_hex(raw.encode()));self.assertNotIn(raw,str(stored))
            self.assertEqual(stored['user_id'],'u');self.assertEqual(stored['credential_version'],2)
            self.assertEqual(sender.call_args.args[1],'fixture@example.com')
    async def test_failure_invalidates_token_and_omits_provider_details(self):
        with patch.object(verification,'configuration',return_value={}),patch.object(verification,'db') as db,patch.object(verification,'charge_auth_attempt',new_callable=AsyncMock),patch.object(verification,'send_verification_mail',side_effect=RuntimeError('PRIVATE')):
            db.email_verifications.insert_one=AsyncMock();db.email_verifications.delete_one=AsyncMock()
            with self.assertLogs('account_verification',level='WARNING') as logs:
                with self.assertRaises(HTTPException) as error:await verification.request_verification({'id':'u','email':'fixture@example.com'})
            self.assertEqual(error.exception.status_code,503);self.assertNotIn('PRIVATE',str(logs.output));db.email_verifications.delete_one.assert_awaited_once()
    async def test_one_use_claim_updates_only_verified_email_metadata(self):
        with patch.object(verification,'configuration',return_value={}),patch.object(verification,'db') as db,patch.object(verification,'charge_auth_attempt',new_callable=AsyncMock),patch.object(verification,'account_event',new_callable=AsyncMock) as event:
            db.email_verifications.find_one=AsyncMock(return_value={'user_id':'owner','email':'owner@example.com','credential_version':2})
            db.users.find_one=AsyncMock(return_value={'_id':'owner','email':'owner@example.com','credential_version':2})
            db.email_verifications.find_one_and_update=AsyncMock(return_value={'claimed':True});db.users.find_one_and_update=AsyncMock(return_value={'updated':True})
            await verification.confirm_verification(verification.Confirmation(token='t'*43))
            query,change=db.users.find_one_and_update.call_args.args
            self.assertEqual(query['email'],'owner@example.com');self.assertEqual(query['credential_version'],2)
            self.assertEqual(set(change),{'$set'});self.assertEqual(set(change['$set']),{'email_verified_address','email_verified_at'})
            event.assert_awaited_once_with('owner','email.verified')
            db.email_verifications.find_one_and_update.return_value=None;db.users.find_one_and_update.reset_mock()
            with self.assertRaises(HTTPException):await verification.confirm_verification(verification.Confirmation(token='t'*43))
            db.users.find_one_and_update.assert_not_called()
    async def test_disabled_configuration_blocks_old_links(self):
        with patch.object(verification,'configuration',return_value=None),patch.object(verification,'db') as db:
            with self.assertRaises(HTTPException) as error:await verification.confirm_verification(verification.Confirmation(token='t'*43))
            self.assertEqual(error.exception.status_code,503);db.email_verifications.find_one.assert_not_called()
    async def test_stale_epoch_and_missing_account_rejected_before_claim(self):
        for user in (None,{'credential_version':3}):
            with patch.object(verification,'configuration',return_value={}),patch.object(verification,'db') as db,patch.object(verification,'charge_auth_attempt',new_callable=AsyncMock):
                db.email_verifications.find_one=AsyncMock(return_value={'user_id':'u','email':'fixture@example.com','credential_version':2})
                db.users.find_one=AsyncMock(return_value=user)
                with self.assertRaises(HTTPException):await verification.confirm_verification(verification.Confirmation(token='t'*43))
                db.email_verifications.find_one_and_update.assert_not_called()
    async def test_bearer_management_is_forbidden(self):
        with self.assertRaises(HTTPException) as error:await verification.status({'id':'u','_token_scopes':['read']})
        self.assertEqual(error.exception.status_code,403)
    def test_verified_state_is_bound_to_current_address(self):
        self.assertTrue(verification.verified({'email':'a@example.com','email_verified_address':'a@example.com','email_verified_at':'timestamp'}))
        self.assertFalse(verification.verified({'email':'b@example.com','email_verified_address':'a@example.com','email_verified_at':'timestamp'}))
