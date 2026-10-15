"""Mocked regression coverage for atomic, tenant-scoped triage history."""
import copy
import os
import unittest
from unittest.mock import AsyncMock, patch

os.environ.update({'MONGO_URL': 'mongodb://127.0.0.1:27018', 'DB_NAME': 'vaptx_test',
    'JWT_SECRET': 'test-only-' * 8, 'ADMIN_EMAIL': 'owner@example.com',
    'ADMIN_PASSWORD': 'test-only-password', 'FRONTEND_URL': 'http://localhost:3000',
    'INTERNAL_API_URL': 'http://127.0.0.1:8001', 'NMAP_BINARY': 'nmap', 'VAPTX_LOCAL_HTTP': '1'})
from fastapi import HTTPException
from pymongo import ReturnDocument
from core import Ctx
import workflow

NOW = '2026-01-02T00:00:00+00:00'
DOCUMENT = {'_id': 'finding-one', 'org_id': 'org-one', 'created_by': 'creator',
    'created_at': '2026-01-01T00:00:00+00:00', 'status': 'open', 'notes': '',
    'verification': 'imported-unverified', 'source': 'import', 'severity': 'high'}


class FindingHistoryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.ctx = Ctx({'id': 'analyst-one', 'email': 'analyst@example.com'}, 'org-one', 'analyst')
        self.repo_db = self.enterContext(patch('repository.db'))
        self.read = self.repo_db.__getitem__.return_value.find_one = AsyncMock(return_value=copy.deepcopy(DOCUMENT))
        self.write_db = self.enterContext(patch.object(workflow, 'db'))
        self.write = self.write_db.findings.find_one_and_update = AsyncMock(return_value=copy.deepcopy(DOCUMENT))
        self.audit = self.enterContext(patch.object(workflow, 'audit', new_callable=AsyncMock))

    async def test_atomic_tenant_query_event_and_provenance(self):
        with patch.object(workflow, 'iso', return_value=NOW):
            result = await workflow.triage('finding-one', workflow.TriageInput(status='confirmed', notes='Reviewed'), self.ctx)
        self.repo_db.__getitem__.assert_called_with('findings')
        self.read.assert_awaited_once_with({'_id': 'finding-one', 'org_id': 'org-one'})
        args, kwargs = self.write.call_args
        self.assertEqual(args[0], {'_id': 'finding-one', 'org_id': 'org-one', 'status': 'open', 'notes': '', 'history_total': {'$exists': False}})
        self.assertEqual(kwargs, {'return_document': ReturnDocument.AFTER})
        self.assertEqual(args[1], {
            '$set': {'status': 'confirmed', 'notes': 'Reviewed', 'updated_at': NOW},
            '$push': {'triage_history': {'$each': [{'previous_status': 'open', 'status': 'confirmed',
                'previous_notes': '', 'notes': 'Reviewed', 'actor_id': 'analyst-one',
                'actor_email': 'analyst@example.com', 'created_at': NOW}], '$slice': -100}},
            '$inc': {'history_total': 1}})
        for key in ('verification', 'source', 'severity', 'org_id', 'created_by'):
            self.assertEqual(result[key], DOCUMENT[key])
            self.assertNotIn(key, args[1]['$set'])
        self.audit.assert_awaited_once_with(self.ctx, 'finding.triaged', 'findings', 'finding-one', {'previous_status': 'open', 'status': 'confirmed'})

    async def test_conflict_does_not_retry_or_audit(self):
        self.write.return_value = None
        with self.assertRaises(HTTPException) as error:
            await workflow.triage('finding-one', workflow.TriageInput(status='resolved'), self.ctx)
        self.assertEqual(error.exception.status_code, 409)
        self.write.assert_awaited_once()
        self.audit.assert_not_awaited()

    async def test_unchanged_update_is_idempotent(self):
        result = await workflow.triage('finding-one', workflow.TriageInput(status='open', notes=''), self.ctx)
        self.assertEqual(result['id'], 'finding-one')
        self.write.assert_not_awaited()
        self.audit.assert_not_awaited()

    async def test_notes_only_update_and_counter_guard(self):
        self.read.return_value = {**DOCUMENT, 'notes': 'First', 'history_total': 103}
        await workflow.triage('finding-one', workflow.TriageInput(status='open', notes='Second'), self.ctx)
        query, update = self.write.call_args.args
        self.assertEqual(query['history_total'], 103)
        self.assertEqual(query['notes'], 'First')
        event = update['$push']['triage_history']['$each'][0]
        self.assertEqual(event['previous_status'], event['status'])
        self.assertEqual((event['previous_notes'], event['notes']), ('First', 'Second'))

    async def test_legacy_absent_notes_compared_exactly(self):
        self.read.return_value = {key: value for key, value in DOCUMENT.items() if key != 'notes'}
        await workflow.triage('finding-one', workflow.TriageInput(status='accepted_risk'), self.ctx)
        self.assertEqual(self.write.call_args.args[0]['notes'], {'$exists': False})

    async def test_foreign_or_missing_finding_returns_404(self):
        self.read.return_value = None
        for operation in (lambda: workflow.triage('foreign', workflow.TriageInput(status='confirmed'), self.ctx), lambda: workflow.finding_history('foreign', self.ctx)):
            with self.assertRaises(HTTPException) as error:
                await operation()
            self.assertEqual(error.exception.status_code, 404)
        self.write.assert_not_awaited()
        self.audit.assert_not_awaited()
        self.assertEqual(self.read.call_args.args[0], {'_id': 'foreign', 'org_id': 'org-one'})

    async def test_read_history_chronological_bounded_and_reports_truncation(self):
        events = [{'status': 'open', 'notes': str(i)} for i in range(101)]
        self.read.return_value = {**DOCUMENT, 'triage_history': events, 'history_total': 120}
        self.assertEqual(await workflow.finding_history('finding-one', self.ctx), {'events': events[-100:], 'has_more': True, 'total': 120})
        self.write.assert_not_awaited()

    async def test_existing_document_starts_at_zero(self):
        self.assertEqual(await workflow.finding_history('finding-one', self.ctx), {'events': [], 'has_more': False, 'total': 0})

    async def test_viewer_can_read_but_cannot_triage(self):
        viewer = Ctx({'id': 'viewer', 'email': 'viewer@example.com'}, 'org-one', 'viewer')
        self.assertEqual((await workflow.finding_history('finding-one', viewer))['events'], [])
        with patch('core.audit', new_callable=AsyncMock), self.assertRaises(HTTPException) as error:
            await workflow.triage('finding-one', workflow.TriageInput(status='confirmed'), viewer)
        self.assertEqual(error.exception.status_code, 403)
        self.write.assert_not_awaited()
