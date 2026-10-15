"""Complete finding navigation with bounded queries and literal search."""
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import test_projects
from core import Ctx
from fastapi import HTTPException
from repository import Repository
import workflow

class FindingPaginationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.ctx=Ctx({'id':'reader'},'org-one','viewer')

    async def test_filters_validate_relationships_and_escape_regex(self):
        with patch.object(workflow,'Repository') as repository:
            repo=repository.return_value
            repo.get=AsyncMock(return_value={'project_id':'project'})
            repo.page=AsyncMock(return_value={'items':[]})
            await workflow.list_findings(project_id='project',assessment_id='assessment',search=' .* ',
                severity='high',status='open',scanner='semgrep',offset=1000,limit=25,ctx=self.ctx)
            repo.get.assert_any_await('projects','project')
            repo.get.assert_any_await('assessments','assessment')
            args,kwargs=repo.page.call_args
            self.assertEqual(kwargs,{'offset':1000,'limit':25})
            self.assertEqual(args[1]['$or'][0],{'title':{'$regex':r'\.\*','$options':'i'}})
            self.assertEqual(args[1]['severity'],'high')
            self.assertEqual(args[1]['assessment_id'],'assessment')

    async def test_foreign_assessment_project_pair_is_denied(self):
        with patch.object(workflow,'Repository') as repository:
            repo=repository.return_value
            repo.get=AsyncMock(return_value={'project_id':'different'})
            with self.assertRaises(HTTPException) as error:
                await workflow.list_findings(project_id='project',assessment_id='assessment',ctx=self.ctx)
            self.assertEqual(error.exception.status_code,404)
            repo.page.assert_not_called()

    async def test_repository_counts_and_pages_inside_organization(self):
        with patch('repository.db') as database:
            collection=database.__getitem__.return_value
            collection.count_documents=AsyncMock(return_value=1050)
            cursor=MagicMock()
            collection.find.return_value=cursor
            cursor.sort.return_value=cursor
            cursor.skip.return_value=cursor
            cursor.limit.return_value=cursor
            cursor.to_list=AsyncMock(return_value=[{'_id':'f','org_id':'org-one','created_by':'creator','created_at':'2026-01-01'}])
            result=await Repository(self.ctx).page('findings',{'org_id':'foreign','severity':'high'},offset=1000,limit=25)
            collection.count_documents.assert_awaited_once_with({'org_id':'org-one','severity':'high'})
            collection.find.assert_called_once_with({'org_id':'org-one','severity':'high'},{'triage_history':0})
            cursor.sort.assert_called_once_with([('created_at',-1),('_id',-1)])
            cursor.skip.assert_called_once_with(1000)
            self.assertEqual(result['items'][0]['id'],'f')
            self.assertEqual(result['total'],1050)
            self.assertTrue(result['has_more'])

    def test_route_rejects_invalid_bounds_and_filters(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        app=FastAPI()
        app.include_router(workflow.router)
        app.dependency_overrides[workflow.get_ctx]=lambda: self.ctx
        client=TestClient(app)
        for params in ({'limit':101},{'offset':-1},{'severity':'bogus'},
                       {'status':'bogus'},{'search':'x'*121},{'offset':1000001}):
            response=client.get('/api/findings',params=params)
            self.assertEqual(response.status_code,422,response.text)
