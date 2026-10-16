"""Severity changes are reasoned, conditional and preserve source assertions."""
import unittest
from unittest.mock import AsyncMock,patch
import test_projects
from core import Ctx
from fastapi import HTTPException
from pydantic import ValidationError
import finding_severity as module
class SeverityTests(unittest.IsolatedAsyncioTestCase):
 def test_reason_and_version_validation(self):
  for values in ({'severity':'invalid','reason':'Valid reason'},{'severity':'high','reason':'     '},{'severity':None,'reason':'Valid reason','expected_version':-1}):
   with self.subTest(values=values),self.assertRaises(ValidationError):module.SeverityDecision(**values)
 async def test_override_has_conditional_write_and_preserves_scanner_severity(self):
  ctx=Ctx({'id':'analyst','email':'synthetic@example.com'},'org','analyst');ctx.project_ids=['project']
  with patch.object(module,'Repository') as repository,patch.object(module,'db') as db,patch.object(module,'audit',new_callable=AsyncMock) as audit:
   repository.return_value.get=AsyncMock(return_value={'id':'finding','severity':'low','scanner_severity':'low','severity_version':2})
   repository.return_value.query.side_effect=lambda q,**kwargs:q
   db.findings.find_one_and_update=AsyncMock(return_value={'_id':'finding','org_id':'org','created_by':'analyst','severity':'high','scanner_severity':'low'})
   result=await module.decide_severity('finding',module.SeverityDecision(severity='high',reason='Synthetic assessed impact',expected_version=2),ctx)
   query,update=db.findings.find_one_and_update.call_args.args
   self.assertEqual(query['severity_version'],2);self.assertEqual(query['severity'],'low')
   self.assertEqual(update['$set']['scanner_severity'],'low');self.assertEqual(result['severity'],'high')
   self.assertNotIn('verification',update['$set']);self.assertNotIn('scanner_cvss',update['$set'])
   self.assertEqual(update['$push']['severity_history']['$slice'],-100);audit.assert_awaited_once()
 async def test_stale_editor_conflict_and_unauthorized_source_do_not_write(self):
  ctx=Ctx({'id':'analyst'},'org','analyst')
  with patch.object(module,'Repository') as repository,patch.object(module,'db') as db:
   repository.return_value.get=AsyncMock(return_value={'id':'finding','severity':'low','severity_version':1})
   with self.assertRaises(HTTPException) as error:await module.decide_severity('finding',module.SeverityDecision(severity='high',reason='Synthetic reason'),ctx)
   self.assertEqual(error.exception.status_code,409);db.findings.find_one_and_update.assert_not_called()
   repository.return_value.get.side_effect=HTTPException(404,'Resource not found')
   with self.assertRaises(HTTPException):await module.decide_severity('foreign',module.SeverityDecision(severity='high',reason='Synthetic reason'),ctx)
   with self.assertRaises(HTTPException):await module.decide_severity('finding',module.SeverityDecision(severity='high',reason='Synthetic reason'),Ctx({'id':'viewer'},'org','viewer'))
 async def test_restore_uses_preserved_source_and_lost_write_race_conflicts(self):
  with patch.object(module,'Repository') as repository,patch.object(module,'db') as db:
   repository.return_value.get=AsyncMock(return_value={'id':'finding','severity':'critical','scanner_severity':'low','severity_version':1})
   repository.return_value.query.side_effect=lambda q,**kwargs:q
   db.findings.find_one_and_update=AsyncMock(return_value=None)
   with self.assertRaises(HTTPException) as error:await module.decide_severity('finding',module.SeverityDecision(severity=None,reason='Restore original scanner rating',expected_version=1),Ctx({'id':'u'},'org','analyst'))
   self.assertEqual(error.exception.status_code,409)
   update=db.findings.find_one_and_update.call_args.args[1]
   self.assertEqual(update['$set']['severity'],'low');self.assertIsNone(update['$set']['severity_override'])
