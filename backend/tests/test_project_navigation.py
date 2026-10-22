import unittest
from unittest.mock import AsyncMock,patch,MagicMock
import test_projects
from core import Ctx
import workflow

class ProjectNavigationTests(unittest.IsolatedAsyncioTestCase):
    async def test_server_search_escapes_regex_and_counts_full_related_sets(self):
        with patch.object(workflow,'Repository') as repository,patch.object(workflow,'db') as db:
            repo=repository.return_value
            repo.page=AsyncMock(return_value={'items':[{'id':'project'}],'total':1005,'has_more':False})
            repo.query.side_effect=lambda filters=None:{**(filters or {}),'org_id':'tenant'}
            db.__getitem__.return_value.aggregate.return_value.to_list=AsyncMock(side_effect=[[{'_id':'project','count':1500}],[{'_id':'project','count':2}]])
            result=await workflow.list_projects('literal.*','active',1000,25,Ctx({'id':'u'},'tenant','viewer'))
            self.assertEqual(result['items'][0]['asset_count'],1500)
            self.assertEqual(result['items'][0]['assessment_count'],2)
            query=repo.page.call_args.args[1]
            self.assertEqual(query['$or'][0]['name']['$regex'],r'literal\.\*')
            for call in db.__getitem__.return_value.aggregate.call_args_list:
                self.assertEqual(call.args[0][0]['$match'],{'project_id':{'$in':['project']},'org_id':'tenant'})
    async def test_empty_page_does_not_scan_related_collections(self):
        with patch.object(workflow,'Repository') as repository,patch.object(workflow,'db') as db:
            repository.return_value.page=AsyncMock(return_value={'items':[],'total':0})
            await workflow.list_projects('',None,0,25,Ctx({'id':'u'},'tenant','viewer'))
            db.__getitem__.assert_not_called()
    async def test_selected_project_stays_in_selector_beyond_workspace_limit(self):
        with patch.object(workflow,'Repository') as repository:
            repo=repository.return_value
            repo.get=AsyncMock(return_value={'id':'selected','name':'Selected old project'})
            repo.list=AsyncMock(return_value=[])
            result=await workflow.workspace('selected',Ctx({'id':'u'},'tenant','viewer'))
            self.assertEqual(result['projects'][0]['id'],'selected')
