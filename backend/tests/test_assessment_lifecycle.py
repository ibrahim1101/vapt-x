import asyncio
import copy
import unittest
from unittest.mock import AsyncMock, patch, MagicMock
import test_projects
from core import Ctx
from fastapi import HTTPException
import workflow
import scanners

class AssessmentLifecycleTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.ctx=Ctx({'id':'analyst','email':'analyst@example.com'},'org-one','analyst')
        self.records={('assessments','assessment'):{'id':'assessment','project_id':'project','name':'Baseline','asset_ids':['asset'],'status':'draft','baseline_id':None},
            ('assets','asset'):{'id':'asset','project_id':'project','target':'training://local'},
            ('jobs','job'):{'id':'job','assessment_id':'assessment','asset_id':'asset','scanner':'safe','source':'execution','status':'queued'}}
        self.repo=AsyncMock()
        async def get(coll,oid):
            if (coll,oid) not in self.records: raise HTTPException(404,'Resource not found')
            return copy.deepcopy(self.records[coll,oid])
        async def update(coll,oid,fields,**kwargs):
            self.records[coll,oid].update(fields)
            return copy.deepcopy(self.records[coll,oid])
        async def jobs(coll,filters):
            return [copy.deepcopy(v) for (c,k),v in self.records.items() if c==coll and v.get('assessment_id')==filters['assessment_id'] and v['status'] in filters['status']['$in']]
        self.repo.get.side_effect=get;self.repo.update.side_effect=update;self.repo.complete_list.side_effect=jobs
        self.enterContext(patch.object(workflow,'Repository',return_value=self.repo))
        self.enterContext(patch.object(scanners,'Repository',return_value=self.repo))
        lock=asyncio.Lock()
        self.enterContext(patch.object(workflow,'JOB_LOCK',lock));self.enterContext(patch.object(scanners,'JOB_LOCK',lock))
        self.enterContext(patch.dict(scanners.ACTIVE_CHECKS,{},clear=True))
        self.enterContext(patch.object(workflow,'audit',new_callable=AsyncMock))
        self.enterContext(patch.object(scanners,'audit',new_callable=AsyncMock))
        self.scope=self.enterContext(patch.object(scanners,'validate_scope',new_callable=AsyncMock))
        self.store=self.enterContext(patch.object(scanners,'store_findings',new_callable=AsyncMock,return_value=0))
        database=self.enterContext(patch.object(scanners,'db'))
        database.memberships.find_one=AsyncMock(return_value={'role':'analyst'})
        database.users.find_one=AsyncMock(return_value={'_id':'analyst'})
        database.sessions.find_one=AsyncMock(return_value={'credential_version':0})

    async def cancel(self):
        return await workflow.cancel_assessment('assessment',workflow.ScopeRevocationInput(reason='Synthetic cancellation'),self.ctx)

    async def test_running_check_is_stopped_and_cannot_publish_findings(self):
        started=asyncio.Event();stopped=asyncio.Event()
        async def check(*args):
            started.set()
            try: await asyncio.Event().wait()
            finally: stopped.set()
        with patch.object(scanners,'safe_checks',side_effect=check):
            runner=asyncio.create_task(scanners.run_job(self.ctx,'job'))
            await asyncio.wait_for(started.wait(),1)
            await self.cancel()
            await asyncio.wait_for(runner,1)
        self.assertTrue(stopped.is_set())
        self.assertEqual(self.records['jobs','job']['status'],'cancelled')
        self.assertEqual(self.records['assessments','assessment']['status'],'cancelled')
        self.store.assert_not_awaited()
        self.assertNotIn(('org-one','job'),scanners.ACTIVE_CHECKS)

    async def test_queued_cancel_is_idempotent_and_worker_does_not_start(self):
        await self.cancel()
        original=copy.deepcopy(self.records['assessments','assessment'])
        await self.cancel()
        self.assertEqual(self.records['assessments','assessment'],original)
        await scanners.run_job(self.ctx,'job')
        self.scope.assert_not_awaited();self.store.assert_not_awaited()

    async def test_retry_preserves_old_assessment_and_creates_separate_draft(self):
        with self.assertRaises(HTTPException):
            await workflow.retry_assessment('assessment',self.ctx)
        await self.cancel()
        await workflow.retry_assessment('assessment',self.ctx)
        fields=self.repo.add.call_args.args[1]
        self.assertEqual(fields['retry_of'],'assessment');self.assertEqual(fields['status'],'draft')
        self.assertEqual(self.records['assessments','assessment']['status'],'cancelled')
        self.assertEqual(fields['asset_ids'],['asset'])

    async def test_foreign_and_readonly_cancellation_denied(self):
        with self.assertRaises(HTTPException) as error:
            await workflow.cancel_assessment('foreign',workflow.ScopeRevocationInput(reason='Synthetic cancellation'),self.ctx)
        self.assertEqual(error.exception.status_code,404)
        with self.assertRaises(HTTPException) as error:
            await workflow.cancel_assessment('assessment',workflow.ScopeRevocationInput(reason='Synthetic cancellation'),Ctx({'id':'viewer'},'org-one','viewer'))
        self.assertEqual(error.exception.status_code,403)
        self.repo.update.assert_not_awaited()

    async def test_cancelled_scope_rejects_new_scan_or_import(self):
        assessment={**self.records['assessments','assessment'],'status':'cancelled'}
        with self.assertRaises(HTTPException) as error:
            await self.scope_original(assessment)
        self.assertEqual(error.exception.status_code,409)

    async def scope_original(self,assessment):
        return await ORIGINAL_VALIDATE(self.repo,assessment,self.records['assets','asset'],'safe')

    async def test_nmap_cancellation_kills_and_reaps_process(self):
        process=MagicMock();process.returncode=None
        process.communicate=AsyncMock(side_effect=asyncio.CancelledError)
        process.wait=AsyncMock()
        with patch.object(scanners.shutil,'which',return_value='/synthetic/nmap'),patch.object(scanners.asyncio,'create_subprocess_exec',AsyncMock(return_value=process)):
            with self.assertRaises(asyncio.CancelledError):
                await scanners.nmap_scan({'target':'training://local'},'127.0.0.1')
        process.kill.assert_called_once();process.wait.assert_awaited_once()

ORIGINAL_VALIDATE=scanners.validate_scope
