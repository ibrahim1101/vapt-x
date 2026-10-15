"""Project writes preserve tenant and historical resource identity."""
import os
import unittest
from unittest.mock import AsyncMock, patch
os.environ.update(MONGO_URL='mongodb://127.0.0.1:27018', DB_NAME='vaptx_test',
    JWT_SECRET='test-only-' * 8, ADMIN_EMAIL='owner@example.com',
    ADMIN_PASSWORD='test-only-password', FRONTEND_URL='http://localhost:3000',
    INTERNAL_API_URL='http://127.0.0.1:8001', NMAP_BINARY='nmap', VAPTX_LOCAL_HTTP='1')
from fastapi import HTTPException
from pydantic import ValidationError
from core import Ctx
import workflow

class ProjectTests(unittest.IsolatedAsyncioTestCase):
    async def test_edit_archive_restore_tenant_and_audit(self):
        ctx = Ctx({'id': 'analyst'}, 'org-one', 'analyst')
        document = {'_id': 'project', 'org_id': 'org-one', 'created_by': 'creator',
                    'created_at': '2026-01-01', 'name': 'Before'}
        with patch('repository.db') as database, patch('repository.audit', new_callable=AsyncMock) as audit:
            collection = database.__getitem__.return_value
            collection.find_one = AsyncMock(return_value=document)
            collection.update_one = AsyncMock()
            for status in ('archived', 'active'):
                await workflow.update_project('project', workflow.ProjectUpdate(
                    name=' Updated ', description='Context', owner='Security team', status=status), ctx)
                query, update = collection.update_one.call_args.args
                self.assertEqual(query, {'_id': 'project', 'org_id': 'org-one'})
                self.assertEqual(update['$set']['status'], status)
                self.assertEqual(update['$set']['name'], 'Updated')
                self.assertEqual(update['$set']['owner'], 'Security team')
                self.assertNotIn('created_by', update['$set'])
            self.assertEqual(audit.await_count, 2)

    async def test_missing_or_foreign_project_is_not_written(self):
        with patch('repository.db') as database:
            collection = database.__getitem__.return_value
            collection.find_one = AsyncMock(return_value=None)
            collection.update_one = AsyncMock()
            with self.assertRaises(HTTPException) as error:
                await workflow.update_project('foreign', workflow.ProjectUpdate(name='Updated'),
                    Ctx({'id': 'analyst'}, 'org-one', 'analyst'))
            self.assertEqual(error.exception.status_code, 404)
            collection.update_one.assert_not_called()

    async def test_viewer_cannot_edit_project(self):
        with patch.object(workflow, 'Repository') as repo:
            with self.assertRaises(HTTPException) as error:
                await workflow.update_project('project', workflow.ProjectUpdate(name='Updated'),
                    Ctx({'id': 'viewer'}, 'org-one', 'viewer'))
            self.assertEqual(error.exception.status_code, 403)
            repo.assert_not_called()

    def test_invalid_metadata(self):
        for values in ({'name': '  '}, {'name': 'Valid', 'status': 'deleted'},
                       {'name': 'Valid', 'owner': 'x' * 151}):
            with self.assertRaises(ValidationError):
                workflow.ProjectUpdate(**values)
