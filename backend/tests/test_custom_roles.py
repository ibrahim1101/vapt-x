import unittest
from unittest.mock import AsyncMock,patch

import test_projects
import auth
import custom_roles
from core import Ctx
from fastapi import HTTPException
from pydantic import ValidationError


ROLE_ID='7e54ba47-0c0a-4c62-911d-1d47e89b13b2'


class CustomRoleModelTests(unittest.TestCase):
    def test_names_and_permissions_are_normalized_and_bounded(self):
        role=custom_roles.RoleInput(name='  Release   Reviewer ',permissions=['read','report_read','read'])
        self.assertEqual(role.name,'Release Reviewer')
        self.assertEqual(role.permissions,['read','report_read'])
        for values in (
            {'name':'x','permissions':['read']},
            {'name':'No read','permissions':['scan']},
            {'name':'Admin','permissions':['read','members']},
            {'name':'Wildcard','permissions':['read','*']},
        ):
            with self.subTest(values=values),self.assertRaises(ValidationError):custom_roles.RoleInput(**values)

    def test_custom_permissions_intersect_token_scopes_and_never_gain_admin(self):
        ctx=Ctx({'id':'user'},'org','custom',['read','scan'])
        self.assertTrue(ctx.can('read'));self.assertTrue(ctx.can('scan'))
        self.assertFalse(ctx.can('write'));self.assertFalse(ctx.can('members'));self.assertFalse(ctx.can('authorize'))
        token_ctx=Ctx({'id':'user','_token_scopes':['read']},'org','custom',['read','scan'])
        self.assertTrue(token_ctx.can('read'));self.assertFalse(token_ctx.can('scan'))


class CustomRoleResolutionTests(unittest.IsolatedAsyncioTestCase):
    async def test_role_permissions_are_org_scoped_and_fail_closed(self):
        with patch.object(custom_roles,'db') as database:
            database.custom_roles.find_one=AsyncMock(return_value={'permissions':['read','scan']})
            self.assertEqual(await custom_roles.role_permissions('org',ROLE_ID),frozenset({'read','scan'}))
            query=database.custom_roles.find_one.call_args.args[0]
            self.assertEqual(query,{'_id':ROLE_ID,'org_id':'org','active':True})
            database.custom_roles.find_one.return_value={'permissions':['read','members']}
            self.assertIsNone(await custom_roles.role_permissions('org',ROLE_ID))
            database.custom_roles.find_one.return_value=None
            self.assertIsNone(await custom_roles.role_permissions('org',ROLE_ID))
            self.assertIsNone(await custom_roles.role_permissions('org','not-a-role'))

    async def test_assignment_accepts_builtins_or_an_active_same_org_custom_role(self):
        self.assertEqual(await custom_roles.resolve_role_choice('org','analyst'),{'role':'analyst'})
        with patch.object(custom_roles,'role_permissions',AsyncMock(return_value=frozenset({'read'}))):
            self.assertEqual(await custom_roles.resolve_role_choice('org','custom:'+ROLE_ID),{'role':'custom','custom_role_id':ROLE_ID})
        with patch.object(custom_roles,'role_permissions',AsyncMock(return_value=None)):
            with self.assertRaises(HTTPException) as error:await custom_roles.resolve_role_choice('org','custom:'+ROLE_ID)
            self.assertEqual(error.exception.status_code,404)
            with self.assertRaises(HTTPException):await custom_roles.resolve_role_choice('org','custom:foreign')

    async def test_role_definition_update_uses_organization_and_version_cas(self):
        ctx=Ctx({'id':'owner','email':'owner@example.com','credential_version':2},'org','org_admin')
        previous={'_id':ROLE_ID,'org_id':'org','name':'Review','name_key':'review','permissions':['read'],'version':3,'active':True}
        updated={**previous,'name':'Release Review','name_key':'release review','permissions':['read','report_read'],'version':4}
        with patch.object(custom_roles,'current_admin',AsyncMock()),patch.object(custom_roles,'db') as database,patch.object(custom_roles,'audit',AsyncMock()):
            database.custom_roles.find_one=AsyncMock(side_effect=[previous,None,previous,None])
            database.custom_roles.find_one_and_update=AsyncMock(return_value=updated)
            result=await custom_roles.update_custom_role(ROLE_ID,custom_roles.RoleUpdate(name='Release Review',permissions=['read','report_read'],expected_version=3),ctx)
            query,update=database.custom_roles.find_one_and_update.call_args.args[:2]
            self.assertEqual(query,{'_id':ROLE_ID,'org_id':'org','active':True,'version':3})
            self.assertEqual(update['$set']['version'],4)
            self.assertEqual(result['id'],ROLE_ID)
            database.custom_roles.find_one.return_value=previous
            database.custom_roles.find_one_and_update.return_value=None
            with self.assertRaises(HTTPException) as error:
                await custom_roles.update_custom_role(ROLE_ID,custom_roles.RoleUpdate(name='Release Review',permissions=['read'],expected_version=2),ctx)
            self.assertEqual(error.exception.status_code,409)

    async def test_cannot_delete_assigned_role(self):
        role={'_id':ROLE_ID,'org_id':'org','version':1,'active':True}
        with patch.object(custom_roles,'current_admin',AsyncMock()),patch('auth.MEMBER_LOCK') as lock,patch.object(custom_roles,'db') as database:
            lock.__aenter__=AsyncMock();lock.__aexit__=AsyncMock(return_value=False)
            database.custom_roles.find_one=AsyncMock(return_value=role)
            database.memberships.count_documents=AsyncMock(return_value=1)
            database.custom_roles.delete_one=AsyncMock()
            with self.assertRaises(HTTPException) as error:
                await custom_roles.delete_custom_role(ROLE_ID,1,Ctx({'id':'owner'},'org','org_admin'))
            self.assertEqual(error.exception.status_code,409)
            database.custom_roles.delete_one.assert_not_called()

    async def test_admin_assignment_stores_custom_role_id_and_clears_stale_project_role(self):
        ctx=Ctx({'id':'owner','email':'owner@example.com','credential_version':2},'org','org_admin')
        with patch.object(auth,'MEMBER_LOCK'),patch.object(auth,'live_membership_admin',AsyncMock()),\
             patch.object(auth,'db') as database,patch('custom_roles.resolve_role_choice',AsyncMock(return_value={'role':'custom','custom_role_id':ROLE_ID})),\
             patch.object(auth,'audit',AsyncMock()):
            database.users.find_one=AsyncMock(return_value={'_id':'target','email':'target@example.com'})
            database.memberships.find_one=AsyncMock(return_value={'_id':'target-membership','role':'viewer','role_version':1})
            database.memberships.update_one=AsyncMock()
            result=await auth.grant_member(auth.MemberInput(email='target@example.com',role='custom:'+ROLE_ID),ctx)
            self.assertEqual(result,{'ok':True})
            query,update=database.memberships.update_one.call_args.args
            self.assertEqual(query,{'org_id':'org','user_id':'target'})
            self.assertEqual(update['$set']['role'],'custom')
            self.assertEqual(update['$set']['custom_role_id'],ROLE_ID)
            self.assertEqual(update['$set']['role_version'],2)
            self.assertNotIn('$unset',update)

