import unittest
from unittest.mock import AsyncMock,patch,MagicMock
import test_projects
from core import Ctx
import analytics
from fastapi import HTTPException

class AnalyticsTests(unittest.IsolatedAsyncioTestCase):
    async def test_complete_counts_scoped_and_bounded_groups(self):
        ctx=Ctx({'id':'viewer'},'tenant','viewer')
        with patch.object(analytics,'db') as db,patch.object(analytics,'Repository') as repository:
            repository.return_value.query.side_effect=lambda filters=None,**kwargs:{**(filters or {}),'org_id':'tenant'}
            repository.return_value.get=AsyncMock()
            collection=MagicMock();db.__getitem__.return_value=collection
            collection.aggregate.return_value.to_list=AsyncMock(side_effect=[
                [{'_id':'high','count':1200},{'_id':'unspecified','count':2}],
                [{'_id':'queued','count':3},{'_id':'completed','count':1001}],
                [{'_id':'observed','count':1202}]])
            db.assets.count_documents=AsyncMock(return_value=1100);db.projects.count_documents=AsyncMock(return_value=1);db.findings.count_documents=AsyncMock(return_value=1202)
            result=await analytics.summary('project',ctx)
            self.assertEqual(result['open_findings'],1202);self.assertEqual(result['critical_high'],1200)
            self.assertEqual(result['assets'],1100);self.assertEqual(result['unclassified_open'],2)
            self.assertEqual(result['active_jobs'],3)
            for call in collection.aggregate.call_args_list:
                self.assertEqual(call.args[0][0]['$match']['org_id'],'tenant')
                self.assertEqual(call.args[0][0]['$match']['project_id'],'project')
                self.assertIn('$cond',call.args[0][1]['$group']['_id'])
            repository.return_value.get.assert_awaited_once_with('projects','project')
    async def test_foreign_project_denied_before_aggregation(self):
        with patch.object(analytics,'Repository') as repository,patch.object(analytics,'db') as db:
            repository.return_value.get=AsyncMock(side_effect=HTTPException(404))
            with self.assertRaises(HTTPException):await analytics.summary('foreign',Ctx({'id':'u'},'tenant','viewer'))
            db.__getitem__.assert_not_called()
