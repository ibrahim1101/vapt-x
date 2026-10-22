"""Candidates cannot widen project/tenant boundaries or mutate observations."""
import unittest
from unittest.mock import AsyncMock,patch
import test_projects
from core import Ctx
from fastapi import HTTPException
import finding_correlations as module
class CorrelationTests(unittest.IsolatedAsyncioTestCase):
 async def call(self,ctx=None,search=''):
  return await module.correlations('finding',search=search,offset=25,limit=25,ctx=ctx or Ctx({'id':'u'},'org','viewer'))
 async def test_exact_asset_project_cve_and_cross_scanner_filters_are_fixed(self):
  with patch.object(module,'Repository') as repository:
   repo=repository.return_value
   repo.get=AsyncMock(return_value={'id':'finding','project_id':'project','asset_id':'asset','scanner':'trivy','cve_ids':['CVE-2099-0001']})
   repo.page=AsyncMock(return_value={'items':[{'id':'other','cve_ids':['CVE-2099-0001','CVE-2099-0002']}],'total':26,'has_more':False})
   result=await self.call(search='.*')
   query=repo.page.call_args.args[1]
   self.assertEqual(query['project_id'],'project');self.assertEqual(query['asset_id'],'asset')
   self.assertEqual(query['scanner'],{'$ne':'trivy'});self.assertEqual(query['cve_ids'],{'$in':['CVE-2099-0001']})
   self.assertEqual(query['$or'][0]['title']['$regex'],r'\.\*')
   self.assertEqual(result['items'][0]['common_cve_ids'],['CVE-2099-0001'])
   self.assertNotIn('description',repo.page.call_args.kwargs['projection'])
   repo.add.assert_not_called();repo.update.assert_not_called()
 async def test_source_admission_and_no_permission_deny_before_candidate_query(self):
  with patch.object(module,'Repository') as repository:
   repo=repository.return_value;repo.get=AsyncMock(side_effect=HTTPException(404,'Resource not found'))
   with self.assertRaises(HTTPException):await self.call()
   repo.page.assert_not_called()
   with self.assertRaises(HTTPException):await self.call(Ctx({'id':'u','_token_scopes':['scan']},'org','analyst'))
 async def test_missing_normalized_identifiers_returns_empty_without_broad_query(self):
  with patch.object(module,'Repository') as repository:
   repo=repository.return_value;repo.get=AsyncMock(return_value={'id':'finding','cve_ids':['invalid'],'asset_id':'asset'})
   result=await self.call();self.assertEqual(result['total'],0);repo.page.assert_not_called()
