import unittest
from unittest.mock import AsyncMock, patch
import test_projects
from core import Ctx
from fastapi import HTTPException
import register_navigation as navigation

class RegisterNavigationTests(unittest.IsolatedAsyncioTestCase):
    async def test_literal_search_scope_and_metadata_allowlist(self):
        for collection,field in [('evidence','filename'),('reports','name'),('scopes','target')]:
            with self.subTest(collection=collection),patch.object(navigation,'Repository') as repository:
                repo=repository.return_value
                repo.get=AsyncMock()
                repo.page=AsyncMock(return_value={'items':[{'id':'old',field:'literal .*','data':'PRIVATE','sections':['PRIVATE']}],'total':1005,'has_more':False})
                page=await navigation.metadata_page(collection,Ctx({'id':'u'},'tenant','viewer'),'project','literal .*',{},1000,25)
                repo.get.assert_awaited_once_with('projects','project')
                self.assertEqual(repo.page.call_args.args[1]['$or'][0][field]['$regex'],r'literal\ \.\*')
                self.assertEqual(repo.page.call_args.args[1]['project_id'],'project')
                self.assertNotIn('data',page['items'][0]);self.assertNotIn('sections',page['items'][0])
                self.assertNotIn('data',repo.page.call_args.kwargs['projection'])
                self.assertIn('created_by',repo.page.call_args.kwargs['projection'])
                self.assertEqual(page['total'],1005)
    async def test_foreign_project_rejected_before_listing(self):
        with patch.object(navigation,'Repository') as repository:
            repository.return_value.get=AsyncMock(side_effect=HTTPException(404,'Resource not found'))
            with self.assertRaises(HTTPException):
                await navigation.metadata_page('evidence',Ctx({'id':'u'},'tenant','viewer'),'foreign','',{},0,25)
            repository.return_value.page.assert_not_called()
    async def test_false_authorization_filter_is_preserved(self):
        with patch.object(navigation,'metadata_page',new_callable=AsyncMock) as page:
            await navigation.scopes_page(None,'',False,0,25,Ctx({'id':'u'},'tenant','viewer'))
            self.assertEqual(page.call_args.args[4],{'authorized':False})
