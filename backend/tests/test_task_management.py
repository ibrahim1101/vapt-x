import unittest
from unittest.mock import AsyncMock, patch
import test_projects
from core import Ctx
from fastapi import HTTPException
from pydantic import ValidationError
import workflow

class TaskManagementTests(unittest.IsolatedAsyncioTestCase):
    async def test_partial_assignment_progress_and_completion(self):
        current={'status':'todo','progress':0}
        with patch.object(workflow,'Repository') as repository:
            repo=repository.return_value;repo.get=AsyncMock(return_value=current);repo.update=AsyncMock()
            ctx=Ctx({'id':'analyst'},'org','analyst')
            await workflow.update_task('task',workflow.TaskUpdate(assignee='Team',due_date='2027-01-01'),ctx)
            fields=repo.update.call_args.args[2]
            self.assertEqual(fields['assignee'],'Team');self.assertNotIn('status',fields)
            current.update(status='in_progress',progress=60)
            await workflow.update_task('task',workflow.TaskUpdate(status='done'),ctx)
            fields=repo.update.call_args.args[2]
            self.assertEqual(fields['progress'],100);self.assertIsInstance(fields['completed_at'],str)
            current.update(status='done',progress=100)
            await workflow.update_task('task',workflow.TaskUpdate(status='in_progress'),ctx)
            self.assertEqual(repo.update.call_args.args[2]['progress'],0)
            self.assertIsNone(repo.update.call_args.args[2]['completed_at'])

    async def test_invalid_and_empty_updates_do_not_write(self):
        with patch.object(workflow,'Repository') as repository:
            repo=repository.return_value;repo.get=AsyncMock(return_value={'status':'todo','progress':0});repo.update=AsyncMock()
            for body in (workflow.TaskUpdate(),workflow.TaskUpdate(assignee=None),workflow.TaskUpdate(progress=50)):
                with self.assertRaises(HTTPException) as error:
                    await workflow.update_task('task',body,Ctx({'id':'analyst'},'org','analyst'))
                self.assertEqual(error.exception.status_code,422)
            repo.update.assert_not_awaited()

    def test_valid_calendar_dates_and_progress_bounds(self):
        for values in ({'due_date':'2026-02-30'},{'due_date':'tomorrow'},{'progress':101},{'progress':-1}):
            with self.assertRaises(ValidationError): workflow.TaskUpdate(**values)
        self.assertEqual(workflow.TaskUpdate(due_date='').due_date,'')
        with self.assertRaises(ValidationError): workflow.TaskInput(finding_id='finding',title='Task',due_date='not a date')

    async def test_readonly_user_denied(self):
        with patch.object(workflow,'Repository') as repository:
            with self.assertRaises(HTTPException) as error:
                await workflow.update_task('task',workflow.TaskUpdate(assignee='Team'),Ctx({'id':'viewer'},'org','viewer'))
            self.assertEqual(error.exception.status_code,403);repository.assert_not_called()
