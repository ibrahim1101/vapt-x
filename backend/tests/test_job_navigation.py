import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import test_projects
from core import Ctx
import workflow

class JobNavigationTests(unittest.IsolatedAsyncioTestCase):
    async def test_literal_search_projection_and_scoped_asset_names(self):
        with patch.object(workflow,'Repository') as repository, patch.object(workflow,'db') as db:
            repo=repository.return_value
            repo.get=AsyncMock()
            repo.query.side_effect=lambda query:{**query,'org_id':'tenant'}
            repo.page=AsyncMock(return_value={'items':[{'id':'old','asset_id':'a','scanner':'nmap','raw_output':'SECRET','logs':['SECRET']}], 'total':1005,'has_more':True})
            cursor=MagicMock();cursor.to_list=AsyncMock(return_value=[{'_id':'a','name':'Older asset'}]);db.assets.find.return_value=cursor
            result=await workflow.list_jobs('project','literal.*','completed','nmap','import',1000,25,Ctx({'id':'u'},'tenant','viewer'))
            repo.get.assert_awaited_once_with('projects','project')
            self.assertEqual(repo.page.call_args.args[1]['$or'][0]['_id']['$regex'],r'literal\.\*')
            self.assertNotIn('raw_output',repo.page.call_args.kwargs['projection'])
            self.assertEqual(db.assets.find.call_args.args[0],{'_id':{'$in':['a']},'org_id':'tenant'})
            self.assertEqual(result['total'],1005);self.assertEqual(result['items'][0]['asset_name'],'Older asset')
            self.assertNotIn('logs',result['items'][0]);self.assertNotIn('raw_output',result['items'][0])
