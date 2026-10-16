import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import test_projects
from core import Ctx
import auth

class MemberDirectoryTests(unittest.IsolatedAsyncioTestCase):
    async def test_organization_match_precedes_metadata_only_lookup_and_literal_search(self):
        with patch.object(auth,'db') as db:
            cursor=MagicMock();cursor.to_list=AsyncMock(return_value=[{'count':[{'total':1005}],'items':[{'id':'old','email':'fixture@example.com','role':'viewer'}]}]);db.memberships.aggregate.return_value=cursor
            result=await auth.member_directory('literal.*','viewer',1000,25,Ctx({'id':'u'},'tenant','viewer'))
            pipeline=db.memberships.aggregate.call_args.args[0]
            self.assertEqual(pipeline[0],{'$match':{'org_id':'tenant','role':'viewer'}})
            self.assertEqual(pipeline[1]['$lookup']['pipeline'],[{'$project':{'name':1,'email':1}}])
            self.assertEqual(pipeline[3]['$match']['$or'][0]['account.name']['$regex'],r'literal\.\*')
            self.assertEqual(result['total'],1005);self.assertTrue(result['has_more'])
    async def test_empty_directory_has_no_fabricated_members(self):
        with patch.object(auth,'db') as db:
            cursor=MagicMock();cursor.to_list=AsyncMock(return_value=[]);db.memberships.aggregate.return_value=cursor
            page=await auth.member_directory('',None,0,25,Ctx({'id':'u'},'tenant','viewer'))
            self.assertEqual(page['items'],[]);self.assertEqual(page['total'],0);self.assertFalse(page['has_more'])
