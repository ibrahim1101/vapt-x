import unittest
from unittest.mock import AsyncMock,patch

import test_projects
import core
import service_identities as services
import scanners
from fastapi import HTTPException
from pydantic import ValidationError
from starlette.requests import Request


ORG='org-1'
IDENTITY='7e54ba47-0c0a-4c62-911d-1d47e89b13b2'
CREDENTIAL='ecaf41e7-8e61-4556-aa2e-7dc671e21fc6'
OWNER='owner-1'


def bearer(secret):
    return Request({'type':'http','path':'/api/workspace','headers':[(b'authorization',('Bearer '+secret).encode())]})


class ServiceIdentityModels(unittest.TestCase):
    def test_permissions_are_bounded_and_read_is_required(self):
        role=services.IdentityInput(name='  Build   bot ',owner_user_id=OWNER,permissions=['read','scan','read'],project_ids=['p2','p1','p2'])
        self.assertEqual(role.name,'Build bot')
        self.assertEqual(role.permissions,['read','scan'])
        self.assertEqual(role.project_ids,['p1','p2'])
        for body in (
            {'name':'x','owner_user_id':OWNER,'permissions':['read']},
            {'name':'No read','owner_user_id':OWNER,'permissions':['scan']},
            {'name':'Admin','owner_user_id':OWNER,'permissions':['read','members']},
            {'name':'Wildcard','owner_user_id':OWNER,'permissions':['read','*']},
        ):
            with self.subTest(body=body),self.assertRaises(ValidationError):services.IdentityInput(**body)

    def test_credential_permissions_and_project_caps_are_explicit(self):
        credential=services.CredentialInput(scopes=['read','scan','read'],project_ids=['p2','p1','p2'])
        self.assertEqual(credential.scopes,['read','scan'])
        self.assertEqual(credential.project_ids,['p1','p2'])
        with self.assertRaises(ValidationError):services.CredentialInput(scopes=['members'])
        with self.assertRaises(ValidationError):services.CredentialInput(scopes=['read'],expires_days=91)


class ServiceIdentityAuthTests(unittest.IsolatedAsyncioTestCase):
    async def test_service_secret_is_hash_only_and_requires_active_owner_and_principal(self):
        secret='vaptxsvc_'+'s'*48
        credential={'_id':CREDENTIAL,'identity_id':IDENTITY,'org_id':ORG,'scopes':['read','scan'],'project_ids':['p1']}
        identity={'_id':IDENTITY,'org_id':ORG,'name':'Build bot','owner_user_id':OWNER,'active':True}
        with patch.object(core,'db') as database:
            database.service_credentials.find_one=AsyncMock(return_value=credential)
            database.service_credentials.update_one=AsyncMock(return_value=type('Result',(),{'matched_count':1})())
            database.service_identities.find_one=AsyncMock(return_value=identity)
            database.memberships.find_one=AsyncMock(return_value={'_id':'owner-membership'})
            database.users.find_one=AsyncMock(return_value={'_id':OWNER})
            user=await core.get_current_user(bearer(secret))
            self.assertEqual(user['_service_identity_id'],IDENTITY)
            self.assertEqual(user['_token_scopes'],['read','scan'])
            query=database.service_credentials.find_one.call_args.args[0]
            self.assertEqual(query['token_hash'],core.sha256_hex(secret.encode()))
            self.assertFalse(query['revoked'])
            self.assertIn('$gt',query['expires_at'])
            self.assertNotIn('token_hash',user)

    async def test_missing_owner_disables_credentials_until_admin_handoff(self):
        secret='vaptxsvc_'+'s'*48
        with patch.object(core,'db') as database:
            database.service_credentials.find_one=AsyncMock(return_value={'_id':CREDENTIAL,'identity_id':IDENTITY,'org_id':ORG,'scopes':['read'],'project_ids':[]})
            database.service_identities.find_one=AsyncMock(return_value={'_id':IDENTITY,'org_id':ORG,'name':'Build bot','owner_user_id':OWNER,'active':True})
            database.memberships.find_one=AsyncMock(return_value=None)
            database.users.find_one=AsyncMock(return_value={'_id':OWNER})
            with self.assertRaises(HTTPException) as error:await core.get_current_user(bearer(secret))
            self.assertEqual(error.exception.status_code,401)
            self.assertIn('transfer ownership',error.exception.detail)

    async def test_context_intersects_credential_caps_with_live_identity_grants(self):
        user={'id':IDENTITY,'email':'Build bot (service identity)','_service_identity_id':IDENTITY,
            '_service_credential_id':CREDENTIAL,'_service_owner_id':OWNER,'_token_org':ORG,
            '_token_scopes':['read','scan'],'_token_project_ids':['p1','p2']}
        identity={'_id':IDENTITY,'org_id':ORG,'owner_user_id':OWNER,'active':True,
            'permissions':['read'],'project_ids':['p2','p3']}
        request=bearer('vaptxsvc_'+'s'*48)
        with patch.object(core,'get_current_user',AsyncMock(return_value=user)),patch.object(core,'db') as database:
            database.service_identities.find_one=AsyncMock(return_value=identity)
            database.memberships.find_one=AsyncMock(return_value={'_id':'owner-membership'})
            database.users.find_one=AsyncMock(return_value={'_id':OWNER})
            ctx=await core.get_ctx(request)
            self.assertEqual(ctx.project_ids,['p2'])
            self.assertTrue(ctx.can('read'))
            self.assertFalse(ctx.can('scan'))
            self.assertFalse(ctx.can('members'))
            self.assertEqual(ctx.service_identity_id,IDENTITY)


class ServiceIdentityManagementTests(unittest.IsolatedAsyncioTestCase):
    async def test_identity_metadata_never_exposes_database_secrets(self):
        row={'_id':IDENTITY,'name':'Build bot','name_key':'build bot','owner_user_id':OWNER,
            'permissions':['read'],'project_ids':['p1'],'active':True,'version':2,'token_hash':'secret-hash'}
        result=services.identity_metadata(row)
        self.assertEqual(result['id'],IDENTITY)
        self.assertNotIn('token_hash',result)

    async def test_credential_caps_must_be_subsets_and_secret_is_shown_once(self):
        ctx=core.Ctx({'id':'admin','email':'admin@example.com'},ORG,'org_admin')
        identity={'_id':IDENTITY,'org_id':ORG,'owner_user_id':OWNER,'permissions':['read','scan'],'project_ids':['p1'],'active':True}
        body=services.CredentialInput(scopes=['read','scan'],project_ids=['p1'])
        with patch.object(services,'owner_in_org',AsyncMock(return_value={'_id':OWNER})),patch.object(services,'db') as database,patch.object(services,'audit',AsyncMock()):
            database.service_credentials.count_documents=AsyncMock(return_value=0)
            database.service_credentials.insert_one=AsyncMock()
            result=await services.issue_credential(ctx,identity,body)
            saved=database.service_credentials.insert_one.call_args.args[0]
            self.assertEqual(saved['token_hash'],core.sha256_hex(result['token'].encode()))
            self.assertNotIn('token_hash',result)
            self.assertEqual(result['scopes'],['read','scan'])
            self.assertEqual(result['project_ids'],['p1'])
            database.service_credentials.insert_one.assert_awaited_once()
            with self.assertRaises(HTTPException):await services.issue_credential(ctx,identity,services.CredentialInput(scopes=['write'],project_ids=[]))

    async def test_owner_removal_rejects_credential_issuance(self):
        ctx=core.Ctx({'id':'admin'},ORG,'org_admin')
        identity={'_id':IDENTITY,'org_id':ORG,'owner_user_id':OWNER,'permissions':['read'],'project_ids':[],'active':True}
        with patch.object(services,'owner_in_org',AsyncMock(side_effect=HTTPException(404,'owner unavailable'))),patch.object(services,'db') as database:
            database.service_credentials.count_documents=AsyncMock(return_value=0)
            with self.assertRaises(HTTPException):await services.issue_credential(ctx,identity,services.CredentialInput(scopes=['read']))
            database.service_credentials.insert_one.assert_not_called()

    async def test_queued_job_rechecks_credential_identity_owner_and_project_caps(self):
        ctx=core.Ctx({'id':IDENTITY,'_service_identity_id':IDENTITY,'_service_credential_id':CREDENTIAL,
            '_service_owner_id':OWNER,'_token_scopes':['read'],'_token_project_ids':[]},ORG,'service')
        with patch.object(scanners,'db') as database:
            database.service_credentials.find_one=AsyncMock(return_value={'scopes':['read','scan'],'project_ids':['p2']})
            database.service_identities.find_one=AsyncMock(return_value={'owner_user_id':OWNER,'permissions':['read','scan'],'project_ids':['p1','p2'],'active':True})
            database.memberships.find_one=AsyncMock(return_value={'_id':'owner-membership'})
            database.users.find_one=AsyncMock(return_value={'_id':OWNER})
            await scanners.execution_credentials(ctx)
            self.assertEqual(ctx.project_ids,['p2'])
            self.assertTrue(ctx.can('scan'))
            database.service_credentials.find_one.return_value=None
            with self.assertRaisesRegex(ValueError,'changed before execution'):await scanners.execution_credentials(ctx)
