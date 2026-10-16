import unittest
from unittest.mock import AsyncMock,patch
import test_projects
from core import Ctx
from fastapi import HTTPException
from pydantic import ValidationError
from pymongo.errors import ConnectionFailure
import workflow

class BulkTemplateTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.ctx=Ctx({'id':'analyst'},'org','analyst')
        self.row={'project_id':'project','scope_id':'scope','target':'training://local','name':'Synthetic asset'}

    async def test_preflight_rejects_scope_mismatch_before_any_writes(self):
        with patch.object(workflow,'Repository') as repository:
            repo=repository.return_value
            repo.get=AsyncMock(return_value={'project_id':'foreign','host':'training://local'})
            with self.assertRaises(HTTPException) as error:
                await workflow.bulk_assets(workflow.BulkAssetInput(assets=[self.row]),self.ctx)
            self.assertEqual(error.exception.status_code,403);repo.add.assert_not_called()

    async def test_duplicates_and_storage_failures_have_row_receipts(self):
        with patch.object(workflow,'Repository') as repository:
            repo=repository.return_value
            repo.get=AsyncMock(return_value={'project_id':'project','host':'training://local'})
            repo.list=AsyncMock(side_effect=[[],[{'id':'existing'}],ConnectionFailure('Synthetic outage')])
            repo.add=AsyncMock(return_value={'id':'new'})
            result=await workflow.bulk_assets(workflow.BulkAssetInput(assets=[self.row]*3),self.ctx)
            self.assertEqual((result['created'],result['duplicate'],result['failed']),(1,1,1))
            self.assertEqual(result['results'][2]['index'],2)
            self.assertNotIn('Synthetic outage',str(result))

    async def test_template_copies_description_without_scope_or_access(self):
        with patch.object(workflow,'Repository') as repository:
            repo=repository.return_value
            repo.get=AsyncMock(return_value={'description':'Reusable context','scope_id':'must-not-copy','status':'archived'})
            repo.add=AsyncMock()
            await workflow.create_project(workflow.ProjectInput(name='New project',template_id='template'),self.ctx)
            fields=repo.add.call_args.args[1]
            self.assertEqual(fields['description'],'Reusable context');self.assertEqual(fields['status'],'active')
            self.assertNotIn('scope_id',fields)
            repo.get.assert_awaited_once_with('project_templates','template')

    async def test_foreign_template_and_readonly_bulk_denied(self):
        with patch.object(workflow,'Repository') as repository:
            repo=repository.return_value;repo.get=AsyncMock(side_effect=HTTPException(404,'Resource not found'))
            with self.assertRaises(HTTPException):
                await workflow.create_project(workflow.ProjectInput(name='New project',template_id='foreign'),self.ctx)
            repo.add.assert_not_called()
            with self.assertRaises(HTTPException) as error:
                await workflow.bulk_assets(workflow.BulkAssetInput(assets=[self.row]),Ctx({'id':'viewer'},'org','viewer'))
            self.assertEqual(error.exception.status_code,403)

    def test_batch_size_and_nested_validation(self):
        for rows in ([],[self.row]*101,[{**self.row,'kind':'unsupported'}]):
            with self.assertRaises(ValidationError):workflow.BulkAssetInput(assets=rows)
