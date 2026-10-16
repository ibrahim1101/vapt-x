import unittest
from datetime import timedelta
from unittest.mock import AsyncMock,patch
import test_projects
from core import Ctx,now,sha256_hex
from fastapi import HTTPException
import invitations

USER={'id':'recipient','email':'recipient@example.com'}
ITEM={'_id':'invite','org_id':'org','created_by':'issuer','email':USER['email'],'role':'viewer',
      'issuer_membership_id':'issuer-member','issuer_credential_version':0}
class InvitationTests(unittest.IsolatedAsyncioTestCase):
    async def test_email_mismatch_never_reads_authority_or_grants_access(self):
        with patch.object(invitations,'db') as db:
            db.invitations.find_one=AsyncMock(return_value=ITEM)
            with self.assertRaises(HTTPException) as error:await invitations.valid_invitation(invitations.Acceptance(token='t'*43),{**USER,'email':'other@example.com'})
            self.assertEqual(error.exception.status_code,403);db.users.find_one.assert_not_called();db.memberships.insert_one.assert_not_called()
    async def test_issuer_membership_lifetime_and_epoch_are_checked(self):
        for issuer,authority in (({'credential_version':1},{'_id':'issuer-member'}),({'credential_version':0},None)):
            with patch.object(invitations,'db') as db:
                db.invitations.find_one=AsyncMock(return_value=ITEM);db.users.find_one=AsyncMock(side_effect=[{'credential_version':0},issuer]);db.memberships.find_one=AsyncMock(return_value=authority)
                with self.assertRaises(HTTPException):await invitations.valid_invitation(invitations.Acceptance(token='t'*43),USER)
                query=db.memberships.find_one.call_args.args[0]
                self.assertEqual(query['_id'],'issuer-member');self.assertEqual(query['role'],'org_admin');db.memberships.insert_one.assert_not_called()
    async def test_existing_role_is_preserved_without_membership_write(self):
        with patch.object(invitations,'require_configuration',return_value={}),patch.object(invitations,'charge_auth_attempt',new_callable=AsyncMock),patch.object(invitations,'valid_invitation',new_callable=AsyncMock,return_value=(ITEM,{'name':'Fixture'})),patch.object(invitations,'db') as db,patch.object(invitations,'audit',new_callable=AsyncMock) as audit,patch.object(invitations,'account_event',new_callable=AsyncMock):
            db.memberships.find_one=AsyncMock(return_value={'role':'security_lead'});db.invitations.find_one_and_update=AsyncMock(return_value={'claimed':True});db.invitations.update_one=AsyncMock()
            result=await invitations.accept_invitation(invitations.Acceptance(token='t'*43),USER)
            self.assertEqual(result['org_id'],'org');db.memberships.insert_one.assert_not_called();self.assertEqual(audit.call_args.args[0].role,'security_lead')
    async def test_concurrent_claim_loser_cannot_insert_membership(self):
        with patch.object(invitations,'require_configuration',return_value={}),patch.object(invitations,'charge_auth_attempt',new_callable=AsyncMock),patch.object(invitations,'valid_invitation',new_callable=AsyncMock,return_value=(ITEM,{'name':'Fixture'})),patch.object(invitations,'db') as db:
            db.memberships.find_one=AsyncMock(return_value=None);db.invitations.find_one_and_update=AsyncMock(return_value=None)
            with self.assertRaises(HTTPException):await invitations.accept_invitation(invitations.Acceptance(token='t'*43),USER)
            db.memberships.insert_one.assert_not_called()
    async def test_preview_does_not_claim_token_or_add_membership(self):
        with patch.object(invitations,'require_configuration',return_value={}),patch.object(invitations,'charge_auth_attempt',new_callable=AsyncMock),patch.object(invitations,'valid_invitation',new_callable=AsyncMock,return_value=({**ITEM,'expires_at':now()+timedelta(days=7)},{'name':'Fixture organization'})),patch.object(invitations,'db') as db:
            result=await invitations.preview_invitation(invitations.Acceptance(token='t'*43),USER)
            self.assertEqual(result['organization_name'],'Fixture organization');self.assertEqual(result['role'],'viewer')
            self.assertNotIn('token_hash',result);db.invitations.find_one_and_update.assert_not_called();db.memberships.insert_one.assert_not_called()
    async def test_mail_response_omits_raw_and_hashed_token(self):
        async def add(collection,fields,log=False):return {'id':'invite','created_at':'timestamp',**fields}
        ctx=Ctx({'id':'issuer'},'org','org_admin')
        with patch.object(invitations,'require_configuration',return_value={}),patch.object(invitations,'charge_auth_attempt',new_callable=AsyncMock),patch.object(invitations,'administrator',new_callable=AsyncMock,return_value=({'_id':'issuer-member'},{})),patch.object(invitations,'Repository') as repository,patch.object(invitations,'db') as db,patch.object(invitations,'send_invitation_mail') as sender,patch.object(invitations,'audit',new_callable=AsyncMock):
            db.users.find_one=AsyncMock(return_value=None);repository.return_value.add=AsyncMock(side_effect=add)
            result=await invitations.create_invitation(invitations.InvitationInput(email=USER['email']),ctx)
            raw=sender.call_args.args[2].split('invite_token=')[1];stored=repository.return_value.add.call_args.args[1]
            self.assertEqual(stored['token_hash'],sha256_hex(raw.encode()));self.assertEqual(stored['issuer_membership_id'],'issuer-member')
            self.assertNotIn(raw,str(result));self.assertNotIn('token_hash',result)
    async def test_current_administrator_required_for_revoke(self):
        with patch.object(invitations,'db') as db:
            db.memberships.find_one=AsyncMock(return_value=None);db.users.find_one=AsyncMock(return_value={})
            with self.assertRaises(HTTPException):await invitations.revoke_invitation('invite',Ctx({'id':'issuer'},'org','org_admin'))
            db.invitations.update_one.assert_not_called()
    async def test_api_tokens_cannot_accept(self):
        with self.assertRaises(HTTPException) as error:await invitations.accept_invitation(invitations.Acceptance(token='t'*43),{**USER,'_token_scopes':['read']})
        self.assertEqual(error.exception.status_code,403)
    def test_expired_pending_metadata_never_exposes_token(self):
        result=invitations.metadata({'id':'i','status':'pending','expires_at':now()-timedelta(seconds=1),'token_hash':'private'})
        self.assertEqual(result['status'],'expired');self.assertNotIn('token_hash',result)
