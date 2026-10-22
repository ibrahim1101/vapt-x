"""Metadata edits cannot reassign historical observations to a new target."""
from unittest.mock import AsyncMock, patch
import test_projects  # initializes synthetic test environment
import unittest
from core import Ctx
from fastapi import HTTPException
from pydantic import ValidationError
import workflow

class AssetTests(unittest.IsolatedAsyncioTestCase):
    async def test_asset_metadata_only(self):
        body = workflow.AssetUpdate(name=' Asset ', owner='Team', criticality='high',
            tags=[' production ', 'api', 'api'], target='https://different.example', scope_id='foreign')
        with patch.object(workflow, 'Repository') as repository:
            repo = repository.return_value
            repo.update = AsyncMock(return_value={'id':'asset'})
            result = await workflow.update_asset('asset', body, Ctx({'id':'analyst'}, 'org-one', 'analyst'))
            self.assertEqual(result, {'id':'asset'})
            repo.update.assert_awaited_once_with('assets', 'asset', {
                'name':'Asset', 'owner':'Team', 'criticality':'high', 'tags':['production','api']})

    async def test_readonly_roles_cannot_edit(self):
        for role in ('viewer','auditor'):
            with patch.object(workflow, 'Repository') as repository:
                with self.assertRaises(HTTPException) as error:
                    await workflow.update_asset('asset', workflow.AssetUpdate(name='Asset'),
                        Ctx({'id':'reader'}, 'org-one', role))
                self.assertEqual(error.exception.status_code,403)
                repository.assert_not_called()

    def test_invalid_metadata(self):
        for values in ({'name':'  '}, {'name':'Asset','criticality':'unknown'},
                       {'name':'Asset','tags':['']}, {'name':'Asset','tags':['x'*51]},
                       {'name':'Asset','tags':[str(i) for i in range(21)]}):
            with self.assertRaises(ValidationError):
                workflow.AssetUpdate(**values)
