import unittest
from unittest.mock import AsyncMock,patch
import test_projects
from core import Ctx
from fastapi import HTTPException
from pydantic import ValidationError
import workflow

class BulkTriageTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):self.ctx=Ctx({'id':'analyst'},'org','analyst')
    async def test_all_ids_validated_before_mutation(self):
        with patch.object(workflow,'Repository') as repository,patch.object(workflow,'triage',new_callable=AsyncMock) as triage:
            repository.return_value.get=AsyncMock(side_effect=[{'id':'one'},HTTPException(404,'Resource not found')])
            with self.assertRaises(HTTPException):
                await workflow.bulk_triage(workflow.BulkTriageInput(finding_ids=['one','foreign'],status='confirmed'),self.ctx)
            triage.assert_not_awaited()
    async def test_deduplicated_ids_preserve_notes_and_report_conflicts(self):
        with patch.object(workflow,'Repository') as repository,patch.object(workflow,'triage',new_callable=AsyncMock) as triage:
            repository.return_value.get=AsyncMock(return_value={'id':'finding'})
            triage.side_effect=[{},HTTPException(409,'Concurrent update')]
            result=await workflow.bulk_triage(workflow.BulkTriageInput(finding_ids=['one','one','two'],status='confirmed',owner='Team'),self.ctx)
            self.assertEqual(result['updated'],1);self.assertEqual(result['failed'],1)
            self.assertEqual(triage.await_count,2)
            self.assertIsNone(triage.call_args_list[0].args[1].notes)
            self.assertEqual(triage.call_args_list[0].args[1].owner,'Team')
    async def test_readonly_bulk_denied(self):
        with patch.object(workflow,'Repository') as repository:
            with self.assertRaises(HTTPException) as error:
                await workflow.bulk_triage(workflow.BulkTriageInput(finding_ids=['one'],status='open'),Ctx({'id':'viewer'},'org','viewer'))
            self.assertEqual(error.exception.status_code,403);repository.assert_not_called()
    def test_selection_bounds(self):
        for ids in ([],['x']*101):
            with self.assertRaises(ValidationError):workflow.BulkTriageInput(finding_ids=ids,status='open')
