import unittest
from unittest.mock import AsyncMock, patch
import test_projects
from core import Ctx
from fastapi import HTTPException
import workflow

class AssetNavigationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.ctx=Ctx({'id':'reader'},'org-one','viewer')

    async def test_medium_filter_includes_legacy_and_literal_tag_search(self):
        with patch.object(workflow,'Repository') as repository:
            repo=repository.return_value
            repo.get=AsyncMock()
            repo.page=AsyncMock()
            await workflow.list_assets(project_id='project',search=' .* ',criticality='medium',offset=1000,limit=25,ctx=self.ctx)
            repo.get.assert_awaited_once_with('projects','project')
            query=repo.page.call_args.args[1]
            self.assertEqual(query['$and'],[{'$or':[{'criticality':'medium'},{'criticality':{'$exists':False}}]}])
            self.assertIn({'tags':{'$regex':r'\.\*','$options':'i'}},query['$or'])
            self.assertEqual(repo.page.call_args.kwargs,{'offset':1000,'limit':25})

    async def test_activity_checks_asset_access_and_bounds_results(self):
        with patch.object(workflow,'Repository') as repository:
            repo=repository.return_value
            repo.get=AsyncMock()
            repo.list=AsyncMock(return_value=[{'id':str(i)} for i in range(101)])
            result=await workflow.asset_history('asset',self.ctx)
            repo.get.assert_awaited_once_with('assets','asset')
            repo.list.assert_awaited_once_with('audit_events',{'resource_type':'assets','resource_id':'asset'},limit=101)
            self.assertEqual(len(result['events']),100)
            self.assertTrue(result['has_more'])
            repo.get.side_effect=HTTPException(404,'Resource not found')
            repo.list.reset_mock()
            with self.assertRaises(HTTPException):
                await workflow.asset_history('foreign',self.ctx)
            repo.list.assert_not_awaited()
