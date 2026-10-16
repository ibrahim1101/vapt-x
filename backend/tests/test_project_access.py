"""Project access cannot be broadened by caller predicates, roles or legacy blobs."""
import unittest
from unittest.mock import AsyncMock,patch,MagicMock
from types import SimpleNamespace
import test_projects
from core import Ctx
from repository import Repository
from project_access import membership_projects,metadata
from fastapi import HTTPException
from pydantic import ValidationError
import project_membership

class ProjectAccessTests(unittest.IsolatedAsyncioTestCase):
 def context(self,ids=None,role='analyst'):
  ctx=Ctx({'id':'u'},'org',role);ctx.project_ids=['allowed'] if ids is None else ids;return ctx
 def test_membership_defaults_empty_and_malformed_fail_closed(self):
  self.assertIsNone(membership_projects({'role':'analyst'}))
  self.assertIsNone(membership_projects({'role':'org_admin','project_access':{'mode':'selected','project_ids':[]}}))
  for value in (None,{'mode':'all','project_ids':['ambiguous']},{'mode':'selected','project_ids':[]},'invalid',{'mode':'unknown'},{'mode':'selected','project_ids':[None]}):
   self.assertEqual(membership_projects({'role':'viewer','project_access':value}),[])
  self.assertEqual(membership_projects({'role':'viewer','project_access':{'mode':'selected','project_ids':['b','a','a']}}),['a','b'])
 def test_filters_cannot_replace_access_predicate_and_org_metadata_is_explicit(self):
  repo=Repository(self.context())
  query=repo.query({'org_id':'foreign','project_id':'forbidden','$or':[{'project_id':'forbidden'},{}]})
  self.assertEqual(query['$and'][0]['org_id'],'org');self.assertEqual(query['$and'][1],{'project_id':{'$in':['allowed']}})
  self.assertEqual(repo.query({'_id':'forbidden'},'projects')['$and'][1],{'_id':{'$in':['allowed']}})
  self.assertEqual(repo.query({},'api_tokens'),{'org_id':'org'})
  self.assertEqual(Repository(self.context([])).query({})['$and'][1],{'project_id':{'$in':[]}})
 def test_restricted_security_lead_cannot_manage_org_integrations(self):
  ctx=self.context(role='security_lead');self.assertTrue(ctx.can('scan'));self.assertFalse(ctx.can('integrations'))
 async def test_legacy_blob_parent_is_authoritative_for_get_and_list(self):
  repo=Repository(self.context())
  with patch('repository.db') as db:
   db.__getitem__.return_value.find_one=AsyncMock(side_effect=[None,{'_id':'blob','org_id':'org','report_id':'foreign' },None])
   with self.assertRaises(HTTPException):await repo.get('report_files','blob')
   db.__getitem__.return_value.find_one=AsyncMock(return_value={'_id':'allowed-report','org_id':'org','created_by':'u','project_id':'allowed'})
   query=await repo.read_query('report_files',{'report_id':'allowed-report'})
   self.assertEqual(query,{'report_id':'allowed-report','org_id':'org'})
 async def test_restricted_writes_cannot_create_projects_or_insert_foreign_data(self):
  repo=Repository(self.context())
  with patch('repository.db') as db:
   for collection,fields in [('projects',{'name':'new'}),('project_templates',{'name':'new'}),('findings',{'project_id':'foreign'})]:
    with self.assertRaises(HTTPException):await repo.add(collection,fields)
   db.__getitem__.return_value.insert_one.assert_not_called()
 async def test_project_grant_fresh_actor_admin_protection_and_conditional_write(self):
  ctx=Ctx({'id':'admin','credential_version':2},'org','org_admin');ctx.membership_id='actor'
  with patch.object(project_membership,'db') as db,patch.object(project_membership,'audit',new_callable=AsyncMock):
   actor={'_id':'actor','role':'org_admin'};target={'_id':'member','role':'analyst'}
   db.memberships.find_one=AsyncMock(side_effect=[actor,target]);db.users.find_one=AsyncMock(return_value={'credential_version':2})
   db.projects.count_documents=AsyncMock(return_value=1);db.memberships.update_one=AsyncMock(return_value=SimpleNamespace(matched_count=1))
   result=await project_membership.set_project_access('member-user',project_membership.ProjectAccessInput(mode='selected',project_ids=['allowed']),ctx)
   self.assertEqual(result['project_access']['project_ids'],['allowed'])
   query,update=db.memberships.update_one.call_args.args;self.assertEqual(query['project_access'],{'$exists':False});self.assertEqual(query['_id'],'member')
   db.memberships.find_one=AsyncMock(side_effect=[actor,{'_id':'target','role':'org_admin'}])
   with self.assertRaises(HTTPException):await project_membership.set_project_access('other',project_membership.ProjectAccessInput(mode='selected'),ctx)
   db.users.find_one.return_value={'credential_version':3};db.memberships.find_one=AsyncMock(return_value=actor)
   with self.assertRaises(HTTPException):await project_membership.set_project_access('other',project_membership.ProjectAccessInput(mode='all'),ctx)
 def test_grant_validation_bounds_and_deduplication(self):
  self.assertEqual(project_membership.ProjectAccessInput(mode='selected',project_ids=['b','a','b']).project_ids,['a','b'])
  for values in ({'mode':'all','project_ids':['a']},{'mode':'selected','project_ids':['a']*501},{'mode':'unknown'}):
   with self.assertRaises(ValidationError):project_membership.ProjectAccessInput(**values)

class QueuedScanAccessTests(unittest.IsolatedAsyncioTestCase):
 async def test_revoked_project_is_rejected_before_any_network_check(self):
  import scanners
  ctx=Ctx({'id':'u'},'org','analyst');ctx.membership_id='membership'
  job={'id':'job','project_id':'allowed','status':'queued','scanner':'safe'}
  with patch.object(scanners,'Repository') as repository,patch.object(scanners,'db') as db,patch.object(scanners,'audit',new_callable=AsyncMock),patch.object(scanners,'safe_checks',new_callable=AsyncMock) as checks:
   repository.return_value.get=AsyncMock(return_value=job);repository.return_value.update=AsyncMock()
   db.memberships.find_one=AsyncMock(return_value={'_id':'membership','role':'analyst','project_access':{'mode':'selected','project_ids':[]}})
   await scanners.run_job(ctx,'job')
   checks.assert_not_awaited()
   update=repository.return_value.update.call_args.args[2]
   self.assertEqual(update['status'],'failed');self.assertIn('Project access was revoked',update['error'])
