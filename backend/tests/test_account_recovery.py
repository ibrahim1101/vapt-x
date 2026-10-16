import unittest
from unittest.mock import AsyncMock, patch
import test_projects
from core import sha256_hex
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError
import account_recovery as recovery

class AccountRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_hash_only_delivery_and_nonexistent_account_response(self):
        with patch.object(recovery,'mail_configuration',return_value={'synthetic':True}),patch.object(recovery,'db') as db,patch.object(recovery,'charge_auth_attempt',new_callable=AsyncMock),patch.object(recovery,'send_mail') as sender:
            db.users.find_one=AsyncMock(return_value={'_id':'u','email':'fixture@example.com','credential_version':2})
            db.account_recovery.insert_one=AsyncMock()
            known=await recovery.request_recovery(recovery.RecoveryRequest(email='fixture@example.com'))
            link=sender.call_args.args[2]
            raw=link.split('reset_token=')[1]
            saved=db.account_recovery.insert_one.call_args.args[0]
            self.assertEqual(saved['token_hash'],sha256_hex(raw.encode()));self.assertNotIn(raw,str(saved))
            self.assertEqual(saved['credential_version'],2);self.assertIn('/#reset_token=',link)
            db.users.find_one.return_value=None
            unknown=await recovery.request_recovery(recovery.RecoveryRequest(email='missing@example.com'))
            self.assertEqual(known,unknown);self.assertEqual(sender.call_count,1)
    async def test_failed_delivery_invalidates_token_without_leaking_provider_error(self):
        with patch.object(recovery,'mail_configuration',return_value={}),patch.object(recovery,'db') as db,patch.object(recovery,'charge_auth_attempt',new_callable=AsyncMock),patch.object(recovery,'send_mail',side_effect=RuntimeError('PRIVATE')):
            db.users.find_one=AsyncMock(return_value={'_id':'u'});db.account_recovery.insert_one=AsyncMock();db.account_recovery.delete_one=AsyncMock()
            with self.assertLogs('account_recovery',level='WARNING') as logs:
                result=await recovery.request_recovery(recovery.RecoveryRequest(email='fixture@example.com'))
            db.account_recovery.delete_one.assert_awaited_once();self.assertNotIn('PRIVATE',str(logs.output));self.assertEqual(result['notice'],recovery.NOTICE)
    async def test_mfa_cannot_be_bypassed_and_token_is_not_consumed_on_bad_factor(self):
        with patch.object(recovery,'db') as db,patch.object(recovery,'charge_auth_attempt',new_callable=AsyncMock),patch.object(recovery,'verify_password',return_value=False),patch.object(recovery,'consume',new_callable=AsyncMock,return_value=None):
            db.account_recovery.find_one=AsyncMock(return_value={'user_id':'u','email':'fixture@example.com','credential_version':0})
            db.users.find_one=AsyncMock(return_value={'_id':'u','password_hash':'hash','mfa_enabled':True})
            with self.assertRaises(HTTPException) as error:await recovery.complete_recovery(recovery.RecoveryCompletion(token='t'*43,new_password='new-password',mfa_code='bad'))
            self.assertEqual(error.exception.status_code,403);db.account_recovery.find_one_and_update.assert_not_called();db.users.find_one_and_update.assert_not_called()
    async def test_one_use_claim_and_credential_epoch_cas(self):
        with patch.object(recovery,'db') as db,patch.object(recovery,'charge_auth_attempt',new_callable=AsyncMock),patch.object(recovery,'verify_password',return_value=False),patch.object(recovery,'hash_password',return_value='new-hash'),patch.object(recovery,'account_event',new_callable=AsyncMock):
            db.account_recovery.find_one=AsyncMock(return_value={'user_id':'u','email':'fixture@example.com','credential_version':2})
            db.users.find_one=AsyncMock(return_value={'_id':'u','password_hash':'old-hash','credential_version':2})
            db.account_recovery.find_one_and_update=AsyncMock(return_value={'claimed':True})
            db.users.find_one_and_update=AsyncMock(return_value={'credential_version':3})
            db.sessions.update_many=AsyncMock();db.api_tokens.update_many=AsyncMock()
            result=await recovery.complete_recovery(recovery.RecoveryCompletion(token='t'*43,new_password='new-password'))
            query,change=db.users.find_one_and_update.call_args.args
            self.assertEqual(query['credential_version'],2);self.assertEqual(query['disabled'],{'$ne':True});self.assertEqual(change['$inc'],{'credential_version':1})
            db.sessions.update_many.assert_awaited_once();db.api_tokens.update_many.assert_awaited_once();self.assertIn('Sign in',result['notice'])
            db.account_recovery.find_one_and_update.return_value=None;db.users.find_one_and_update.reset_mock()
            with self.assertRaises(HTTPException):await recovery.complete_recovery(recovery.RecoveryCompletion(token='t'*43,new_password='another-password'))
            db.users.find_one_and_update.assert_not_called()
    async def test_stale_credential_epoch_rejects_link(self):
        with patch.object(recovery,'db') as db,patch.object(recovery,'charge_auth_attempt',new_callable=AsyncMock):
            db.account_recovery.find_one=AsyncMock(return_value={'user_id':'u','email':'fixture@example.com','credential_version':0})
            db.users.find_one=AsyncMock(return_value={'_id':'u','credential_version':1})
            with self.assertRaises(HTTPException) as error:await recovery.complete_recovery(recovery.RecoveryCompletion(token='t'*43,new_password='new-password'))
            self.assertEqual(error.exception.status_code,400);db.users.find_one_and_update.assert_not_called()
    def test_recovery_preserves_origin_guard_without_requiring_an_existing_session(self):
        from server import app
        with patch.object(recovery,'mail_configuration',return_value=None):
            client=TestClient(app)
            self.assertEqual(client.post('/api/auth/recovery/request',headers={'origin':'https://untrusted.example'},json={'email':'fixture@example.com'}).status_code,403)
            self.assertEqual(client.post('/api/auth/recovery/request',headers={'origin':'http://localhost:3000'},json={'email':'fixture@example.com'}).status_code,503)
    def test_password_byte_limit(self):
        with self.assertRaises(ValidationError):recovery.RecoveryCompletion(token='t'*43,new_password='é'*40)
    def test_mail_requires_explicit_enable_and_tls(self):
        with patch.dict('os.environ',{},clear=True):self.assertIsNone(recovery.mail_configuration())
        with patch.dict('os.environ',{'ACCOUNT_RECOVERY_ENABLED':'1','RECOVERY_SMTP_HOST':'fixture.example','RECOVERY_SMTP_FROM':'operator@example.com','RECOVERY_SMTP_MODE':'plain'},clear=True):
            with self.assertRaises(ValueError):recovery.mail_configuration()

    def test_smtp_tls_is_verified_before_authentication(self):
        config={'host':'smtp.synthetic.invalid','port':587,'mode':'starttls','sender':'operator@example.com','username':'fixture','password':'private'}
        with patch.object(recovery.ssl,'create_default_context') as context,patch.object(recovery.smtplib,'SMTP') as smtp:
            recovery.send_mail(config,'fixture@example.com','https://frontend.example/#reset_token=synthetic')
            connection=smtp.return_value.__enter__.return_value
            connection.starttls.assert_called_once_with(context=context.return_value)
            self.assertLess([call[0] for call in connection.method_calls].index('starttls'),[call[0] for call in connection.method_calls].index('login'))
            self.assertEqual(smtp.call_args.kwargs['timeout'],10)
