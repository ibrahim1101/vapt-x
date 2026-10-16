import asyncio
import unittest
from unittest.mock import AsyncMock,patch
import test_auth_rotation
import auth, core
from core import Ctx
from fastapi import HTTPException
from starlette.requests import Request

class MembershipTests(unittest.IsolatedAsyncioTestCase):
    async def test_removed_or_demoted_actor_cannot_use_stale_admin_context(self):
        with patch.object(auth,'MEMBER_LOCK',asyncio.Lock()),patch.object(auth,'db') as db:
            db.memberships.find_one=AsyncMock(return_value=None)
            with self.assertRaises(HTTPException) as error:await auth.grant_member(auth.MemberInput(email='target@example.com',role='viewer'),Ctx({'id':'old-admin'},'org','org_admin'))
            self.assertEqual(error.exception.status_code,403);db.users.find_one.assert_not_called()
    async def test_self_removal_and_viewer_removal_are_denied(self):
        for ctx,target in ((Ctx({'id':'owner'},'org','org_admin'),'owner'),(Ctx({'id':'viewer'},'org','viewer'),'owner')):
            with self.assertRaises(HTTPException):await auth.remove_member(target,auth.MemberRemoval(reason='Synthetic reason'),ctx)
    async def test_removal_is_scoped_and_revokes_only_that_organizations_tokens(self):
        ctx=Ctx({'id':'owner'},'org','org_admin')
        with patch.object(auth,'MEMBER_LOCK',asyncio.Lock()),patch.object(auth,'db') as db,patch.object(auth,'audit',AsyncMock()):
            db.memberships.find_one=AsyncMock(side_effect=[{'_id':'admin','role':'org_admin'},{'_id':'membership','role':'viewer'}])
            db.memberships.delete_one=AsyncMock(return_value=type('Result',(),{'deleted_count':1})())
            db.api_tokens.update_many=AsyncMock();db.users.update_one=AsyncMock();db.membership_revocations.update_one=AsyncMock()
            await auth.remove_member('target',auth.MemberRemoval(reason='Synthetic reason'),ctx)
            self.assertEqual(db.memberships.delete_one.call_args.args[0],{'_id':'membership','org_id':'org','user_id':'target'})
            self.assertEqual(db.api_tokens.update_many.call_args.args[0],{'org_id':'org','created_by':'target','revoked':False})
    async def test_token_bound_to_old_membership_cannot_revive_after_readdition(self):
        with patch.object(core,'get_current_user',AsyncMock(return_value={'id':'user','_token_org':'org','_token_scopes':['read'],'_token_membership_id':'old-membership'})),patch.object(core,'db') as db:
            db.memberships.find_one=AsyncMock(return_value={'_id':'new-membership','role':'viewer'})
            with self.assertRaises(HTTPException) as error:await core.get_ctx(Request({'type':'http','headers':[]}))
            self.assertEqual(error.exception.status_code,401)
