"""RFC vectors, atomic claims and enrollment secret boundaries."""
import base64
import os
import unittest
from unittest.mock import AsyncMock, patch
from cryptography.fernet import Fernet
import test_auth_rotation
import mfa, auth
from core import clean, iso, now, sha256_hex
from fastapi import HTTPException, Response
from datetime import timedelta

class MFATests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.enterContext(patch.dict(os.environ,{'MFA_ENCRYPTION_KEYS':Fernet.generate_key().decode()}))
        self.secret=base64.b32encode(b'12345678901234567890').decode()
        self.enterContext(patch.object(mfa,'charge_attempt',AsyncMock()))
        self.encrypted=mfa.cipher().encrypt(self.secret.encode()).decode()
        self.document={'_id':'alice','email':'alice@example.com','password_hash':'hash','mfa_enabled':True,
            'mfa_secret':self.encrypted,'mfa_last_counter':0,'credential_version':2}
    def test_rfc_6238_sha1_vectors_and_clock_window(self):
        for timestamp,expected in [(59,'94287082'),(1111111109,'07081804'),(1111111111,'14050471'),(1234567890,'89005924'),(2000000000,'69279037'),(20000000000,'65353130')]:
            self.assertEqual(mfa.totp(self.secret,timestamp//30,8),expected)
        code=mfa.totp(self.secret,100)
        self.assertEqual(mfa.matching_counter(self.secret,code,3030),100)
        self.assertIsNone(mfa.matching_counter(self.secret,code,3060))
        for invalid in ('12345','1234567','１２３４５６','abcdef'):self.assertIsNone(mfa.matching_counter(self.secret,invalid,3000))
    def test_encryption_recovery_entropy_and_public_sanitization(self):
        codes,hashes=mfa.recovery_codes()
        self.assertEqual(len(set(codes)),10);self.assertTrue(all(len(code)==32 for code in codes))
        self.assertEqual(hashes,[sha256_hex(code.encode()) for code in codes])
        self.assertNotIn(self.secret,self.encrypted)
        result=clean({**self.document,'mfa_pending':{'secret':'secret'},'mfa_recovery_hashes':hashes})
        for key in ('password_hash','mfa_secret','mfa_pending','mfa_recovery_hashes'):self.assertNotIn(key,result)
    async def test_totp_claim_uses_version_secret_and_previous_counter(self):
        with patch.object(mfa,'db') as db,patch.object(mfa.time,'time',return_value=3000):
            db.users.find_one_and_update=AsyncMock(return_value={**self.document,'mfa_last_counter':100})
            result=await mfa.consume(self.document,mfa.totp(self.secret,100))
            query,update=db.users.find_one_and_update.call_args.args
            self.assertEqual(query['mfa_last_counter'],0);self.assertEqual(query['credential_version'],2)
            self.assertEqual(query['mfa_secret'],self.encrypted)
            self.assertEqual(update['$set']['mfa_last_counter'],100)
            db.users.find_one_and_update.reset_mock()
            self.assertIsNone(await mfa.consume(result,mfa.totp(self.secret,100)))
            db.users.find_one_and_update.assert_not_awaited()
    async def test_recovery_code_atomic_pull_works_without_encryption_key(self):
        code='a'*32
        with patch.dict(os.environ,{'MFA_ENCRYPTION_KEYS':''}),patch.object(mfa,'db') as db:
            db.users.find_one_and_update=AsyncMock(side_effect=[self.document,None])
            self.assertIsNotNone(await mfa.consume(self.document,code))
            self.assertIsNone(await mfa.consume(self.document,code))
            query,update=db.users.find_one_and_update.call_args.args
            self.assertEqual(query['mfa_recovery_hashes'],sha256_hex(code.encode()))
            self.assertEqual(update,{'$pull':{'mfa_recovery_hashes':sha256_hex(code.encode())}})
    async def test_confirm_expired_or_other_session_is_rejected(self):
        for pending in ({'session_id':'other','expires_at':iso(now()+timedelta(minutes=5))},{'session_id':'current','expires_at':iso(now()-timedelta(seconds=1))}):
            with patch.object(mfa,'db') as db,patch.object(mfa,'charge_attempt',AsyncMock()):
                db.users.find_one=AsyncMock(return_value={'_id':'alice','mfa_pending':pending})
                with self.assertRaises(HTTPException) as error:
                    await mfa.confirm(mfa.Confirmation(code='123456'),Response(),{'id':'alice','_sid':'current'})
                self.assertEqual(error.exception.status_code,409);db.users.find_one_and_update.assert_not_called()
    async def test_login_without_valid_second_factor_never_establishes_session(self):
        with patch.object(auth,'db') as db,patch.object(auth,'verify_password',return_value=True),patch.object(auth,'insert_identity',AsyncMock()),patch.object(auth,'establish_session',AsyncMock()) as establish,patch.object(mfa,'consume',AsyncMock(return_value=None)):
            db.auth_rate_limits.find_one_and_update=AsyncMock(return_value={'count':1});db.users.find_one=AsyncMock(return_value=self.document)
            with self.assertRaises(HTTPException) as error:await auth.login(auth.Credentials(email='alice@example.com',password='valid-password'),Response())
            self.assertEqual(error.exception.status_code,401);establish.assert_not_awaited()
    async def test_api_tokens_cannot_start_enrollment_or_confirm(self):
        user={'id':'alice','_token_scopes':['read']}
        for action,body in ((mfa.setup,mfa.Reauthenticate(current_password='valid-password')),(mfa.confirm,mfa.Confirmation(code='123456'))):
            with self.assertRaises(HTTPException) as error:
                if action is mfa.confirm:await action(body,Response(),user)
                else:await action(body,user)
            self.assertEqual(error.exception.status_code,403)
