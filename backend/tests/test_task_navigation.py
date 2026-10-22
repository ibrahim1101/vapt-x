import unittest
from unittest.mock import AsyncMock,patch
import test_projects
import workflow
from core import Ctx
from fastapi import HTTPException

class TaskNavigationTests(unittest.IsolatedAsyncioTestCase):
    async def test_complete_page_escaped_filters_and_utc_overdue_state(self):
        with patch.object(workflow,'Repository') as repository:
            repo=repository.return_value;repo.get=AsyncMock();repo.page=AsyncMock(return_value={'items':[{'id':'old','status':'todo','due_date':'2000-01-01'},{'id':'done','status':'done','due_date':'2000-01-01'},{'id':'invalid','status':'todo','due_date':'1999-02-30'}],'total':1005,'has_more':False})
            result=await workflow.list_tasks('project','literal.*',' Team ','todo',True,1000,25,Ctx({'id':'viewer'},'tenant','viewer'))
            query=repo.page.call_args.args[1]
            self.assertEqual(query['project_id'],'project');self.assertEqual(query['$or'][0]['title']['$regex'],r'literal\.\*')
            self.assertEqual(query['assignee']['$regex'],'Team');self.assertIn('$expr',query['$and'][1])
            self.assertEqual(result['total'],1005);self.assertTrue(result['items'][0]['overdue']);self.assertFalse(result['items'][1]['overdue']);self.assertFalse(result['items'][2]['overdue'])
            repo.get.assert_awaited_once_with('projects','project')
    async def test_foreign_project_is_denied_before_reading_tasks(self):
        with patch.object(workflow,'Repository') as repository:
            repository.return_value.get=AsyncMock(side_effect=HTTPException(404))
            repository.return_value.page=AsyncMock()
            with self.assertRaises(HTTPException):await workflow.list_tasks('foreign','','',None,False,0,25,Ctx({'id':'u'},'tenant','viewer'))
            repository.return_value.page.assert_not_awaited()
