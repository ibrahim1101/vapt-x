import unittest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException
import identity_policy as policy

class IdentityPolicyTests(unittest.IsolatedAsyncioTestCase):
    def test_configuration_dependencies_and_defaults(self):
        policy.validate_environment({})
        for env in ({'REGISTRATION_MODE':'invalid'},{'REGISTRATION_MODE':'invite_only'},
                    {'REQUIRE_VERIFIED_EMAIL':'yes'},{'REQUIRE_VERIFIED_EMAIL':'1'}):
            with self.assertRaises(ValueError):policy.validate_environment(env)
        policy.validate_environment({'REGISTRATION_MODE':'invite_only','ORG_INVITATIONS_ENABLED':'1',
            'REQUIRE_VERIFIED_EMAIL':'1','EMAIL_VERIFICATION_ENABLED':'1'})

    def test_required_policy_blocks_domain_admin_and_bearer_access(self):
        with patch.dict('os.environ',{'REQUIRE_VERIFIED_EMAIL':'1'}):
            for path in ('/api/projects','/api/organizations','/api/auth/mfa','/api/auth/invitations/accept','/api/platform/users'):
                with self.subTest(path=path),self.assertRaises(HTTPException) as error:
                    policy.enforce_workspace_policy({'platform_role':'platform_owner'},path)
                self.assertEqual(error.exception.detail['code'],'email_verification_required')
            for path in policy.LIMITED_ACCOUNT_PATHS|{'/api/auth/sessions','/api/auth/sessions/synthetic'}:
                policy.enforce_workspace_policy({},path)
                with self.assertRaises(HTTPException):policy.enforce_workspace_policy({'_token_scopes':['read']},path)
            policy.enforce_workspace_policy({'email':'a@example.com','email_verified_address':'a@example.com','email_verified_at':'now'},'/api/projects')
            with self.assertRaises(HTTPException):policy.enforce_workspace_policy({'email':'changed@example.com','email_verified_address':'a@example.com','email_verified_at':'now'},'/api/projects')
        with patch.dict('os.environ',{'REQUIRE_VERIFIED_EMAIL':'0'}):policy.enforce_workspace_policy({},'/api/projects')

    async def test_closed_registration_never_queries_or_writes(self):
        db=MagicMock()
        with patch.dict('os.environ',{'REGISTRATION_MODE':'closed'}):
            with self.assertRaises(HTTPException):await policy.allow_registration(db,'new@example.com','')
        self.assertEqual(db.mock_calls,[])

    async def test_invitation_checks_authority_without_consuming(self):
        db=MagicMock()
        item={'created_by':'issuer','issuer_membership_id':'member','org_id':'org','issuer_credential_version':2}
        db.invitations.find_one=AsyncMock(return_value=item)
        db.users.find_one=AsyncMock(return_value={'credential_version':2})
        db.memberships.find_one=AsyncMock(return_value={'_id':'member'})
        db.organizations.find_one=AsyncMock(return_value={'_id':'org'})
        with patch.dict('os.environ',{'REGISTRATION_MODE':'invite_only','ORG_INVITATIONS_ENABLED':'1'}):
            with self.assertRaises(HTTPException):await policy.allow_registration(db,'new@example.com','')
            db.invitations.find_one.assert_not_awaited()
            await policy.allow_registration(db,'new@example.com','secret-token')
            query=db.invitations.find_one.call_args.args[0]
            self.assertEqual(query['email'],'new@example.com');self.assertEqual(query['status'],'pending')
            self.assertIn('$gt',query['expires_at']);self.assertNotIn('secret-token',str(query))
            self.assertEqual(db.memberships.find_one.call_args.args[0],{'_id':'member','org_id':'org','user_id':'issuer','role':'org_admin'})
            for collection,value in ((db.invitations,None),(db.users,None),(db.users,{'credential_version':3}),(db.memberships,None),(db.organizations,None)):
                original=collection.find_one.return_value;collection.find_one.return_value=value
                with self.assertRaises(HTTPException):await policy.allow_registration(db,'new@example.com','wrong-or-stale')
                collection.find_one.return_value=original
        db.invitations.update_one.assert_not_called();db.memberships.insert_one.assert_not_called()
