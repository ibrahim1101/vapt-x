from datetime import datetime,timezone
import unittest
from unittest.mock import AsyncMock,patch
import test_projects
from core import Ctx
from fastapi import HTTPException
from pydantic import ValidationError
import governance as gov

class GovernanceTests(unittest.IsolatedAsyncioTestCase):
    def test_sla_uses_calendar_days_and_excludes_inactive_triage(self):
        finding={'created_at':'2026-01-01T00:00:00+00:00','severity':'high','status':'confirmed'}
        policy={'days':gov.DEFAULT_DAYS}
        state=gov.sla_state(finding,policy,datetime(2026,1,9,tzinfo=timezone.utc))
        self.assertTrue(state['breached']);self.assertEqual(state['due_at'],'2026-01-08T00:00:00+00:00')
        for status in ('resolved','false_positive','accepted_risk'):
            self.assertFalse(gov.sla_state({**finding,'status':status},policy)['applicable'])
        self.assertFalse(gov.sla_state(finding,{'days':{'high':0}})['applicable'])
        self.assertFalse(gov.sla_state({**finding,'created_at':'invalid'},policy)['applicable'])
    async def test_policy_update_enforces_role_and_tenant(self):
        with patch.object(gov,'db') as database,patch.object(gov,'audit',new_callable=AsyncMock):
            database.sla_policies.find_one=AsyncMock(return_value=None)
            database.sla_policies.update_one=AsyncMock()
            with self.assertRaises(HTTPException):await gov.update_sla_policy(gov.SLAPolicyInput(),Ctx({'id':'analyst'},'org','analyst'))
            database.sla_policies.update_one.assert_not_awaited()
            await gov.update_sla_policy(gov.SLAPolicyInput(high=14),Ctx({'id':'lead'},'org','security_lead'))
            query,operation=database.sla_policies.update_one.call_args.args
            self.assertEqual(query,{'org_id':'org'});self.assertEqual(operation['$set']['days']['high'],14)
    async def test_comment_preflight_and_readonly_permissions(self):
        with patch.object(gov,'Repository') as repository:
            repo=repository.return_value;repo.get=AsyncMock(side_effect=HTTPException(404,'Resource not found'))
            with self.assertRaises(HTTPException):await gov.add_comment('foreign',gov.CommentInput(text='Synthetic comment'),Ctx({'id':'analyst'},'org','analyst'))
            repo.add.assert_not_called()
            with self.assertRaises(HTTPException):await gov.add_comment('finding',gov.CommentInput(text='Synthetic comment'),Ctx({'id':'viewer'},'org','viewer'))
    def test_policy_and_comment_validation(self):
        with self.assertRaises(ValidationError):gov.SLAPolicyInput(high=366)
        with self.assertRaises(ValidationError):gov.CommentInput(text='  ')
        self.assertEqual(gov.CommentInput(text=' Synthetic ').text,'Synthetic')
