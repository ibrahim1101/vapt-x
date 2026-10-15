import unittest
from unittest.mock import AsyncMock,patch
import test_projects
from core import Ctx,sha256_hex,get_current_user,get_ctx
from fastapi import HTTPException
from starlette.requests import Request
from pydantic import ValidationError
import api_tokens

def request(token,path='/api/workspace',org=None):
    headers=[(b'authorization',('Bearer '+token).encode())]
    if org:headers.append((b'x-org-id',org.encode()))
    return Request({'type':'http','path':path,'headers':headers})
class APITokenTests(unittest.IsolatedAsyncioTestCase):
    async def test_only_hash_persisted_and_token_shown_once(self):
        ctx=Ctx({'id':'owner'},'org','org_admin')
        with patch.object(api_tokens,'db') as database,patch.object(api_tokens,'Repository') as repository:
            database.api_tokens.count_documents=AsyncMock(return_value=0)
            async def add(coll,fields):
                self.assertNotIn('token',fields)
                return {'id':'token-id',**fields}
            repository.return_value.add=AsyncMock(side_effect=add)
            result=await api_tokens.create_token(api_tokens.TokenInput(name='Synthetic token',scopes=['read']),ctx)
            fields=repository.return_value.add.call_args.args[1]
            self.assertEqual(fields['token_hash'],sha256_hex(result['token'].encode()))
            self.assertNotIn('token_hash',result)
            self.assertNotIn('token',api_tokens.metadata({'token':'secret','token_hash':'hash'}))
    async def test_current_role_and_browser_session_boundaries(self):
        for ctx,scopes in ((Ctx({'id':'viewer'},'org','viewer'),['scan']),
            (Ctx({'id':'owner','_token_scopes':['read']},'org','org_admin'),['read'])):
            with self.assertRaises(HTTPException):await api_tokens.create_token(api_tokens.TokenInput(name='Synthetic',scopes=scopes),ctx)
    async def test_bearer_expiry_revocation_hash_and_organization_scope(self):
        token='vaptx_'+'s'*43
        with patch('core.db') as database:
            database.api_tokens.find_one=AsyncMock(return_value={'_id':'token','created_by':'owner','org_id':'org','scopes':['read']})
            database.users.find_one=AsyncMock(return_value={'_id':'owner','email':'synthetic@example.com'})
            database.memberships.find_one=AsyncMock(return_value={'role':'org_admin'})
            user=await get_current_user(request(token))
            self.assertEqual(user['_token_scopes'],['read'])
            query=database.api_tokens.find_one.call_args.args[0]
            self.assertEqual(query['token_hash'],sha256_hex(token.encode()));self.assertFalse(query['revoked'])
            self.assertIn('$gt',query['expires_at'])
            with self.assertRaises(HTTPException) as error:await get_ctx(request(token,org='foreign'))
            self.assertEqual(error.exception.status_code,404)
            database.api_tokens.find_one.return_value=None
            with self.assertRaises(HTTPException):await get_current_user(request(token))
    def test_permission_and_expiry_validation(self):
        for body in ({'name':'Synthetic','scopes':['*']},{'name':'Synthetic','scopes':['read'],'expires_days':91},{'name':'Synthetic','scopes':[]}):
            with self.assertRaises(ValidationError):api_tokens.TokenInput(**body)
