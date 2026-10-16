import unittest
from unittest.mock import AsyncMock,patch
from datetime import date
import test_projects
from core import Ctx
from fastapi import HTTPException
import audit_navigation
class AuditNavigationTests(unittest.IsolatedAsyncioTestCase):
    async def test_filters_utc_inclusive_end_and_allowlisted_events(self):
        with patch.object(audit_navigation,'Repository') as repository:
            repository.return_value.page=AsyncMock(return_value={'items':[{'id':'event','action':'fixture','password_hash':'must-not-return','details':{'reason':'Synthetic'}}],'total':1005})
            result=await audit_navigation.list_events('literal.*','finding.triaged','actor.*','findings','allow',date(2020,1,1),date(2020,1,2),1000,25,Ctx({'id':'u'},'tenant','viewer'))
            query=repository.return_value.page.call_args.args[1]
            self.assertEqual(query['$or'][0]['action']['$regex'],r'literal\.\*');self.assertEqual(query['actor_email']['$regex'],r'actor\.\*')
            self.assertEqual(query['created_at'],{'$gte':'2020-01-01T00:00:00+00:00','$lt':'2020-01-03T00:00:00+00:00'})
            self.assertNotIn('password_hash',result['items'][0]);self.assertEqual(result['total'],1005)
    async def test_reversed_or_overflowing_date_ranges_are_rejected(self):
        for start,end in ((date(2020,1,2),date(2020,1,1)),(None,date.max)):
            with patch.object(audit_navigation,'Repository') as repository:
                with self.assertRaises(HTTPException) as error:await audit_navigation.list_events('','','','',None,start,end,0,25,Ctx({'id':'u'},'tenant','viewer'))
                self.assertEqual(error.exception.status_code,422);repository.assert_not_called()
