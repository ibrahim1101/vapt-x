"""Mongo-backed checks for atomic durable scan ownership and restart recovery."""
import os
import subprocess
import sys
import textwrap
import unittest
from core import Ctx
from scanners import execution_actor
from repository import public_document


class DurableExecutionActorTests(unittest.TestCase):
    def test_actor_snapshot_keeps_authority_references_without_secrets(self):
        ctx=Ctx({'id':'user-one','credential_version':4,'_sid':'session-ref'},'org-one','analyst')
        ctx.membership_id='membership-ref'
        actor=execution_actor(ctx)
        self.assertEqual(actor,{'org_id':'org-one','user_id':'user-one','kind':'session',
            'session_id':'session-ref','credential_version':4,'membership_id':'membership-ref'})
        service=Ctx({'id':'identity-one','_service_identity_id':'identity-one',
            '_service_credential_id':'credential-ref','_service_owner_id':'owner-one',
            'token':'must-not-be-persisted'},'org-one','service')
        self.assertEqual(execution_actor(service),{'org_id':'org-one','user_id':'identity-one',
            'kind':'service','identity_id':'identity-one','credential_id':'credential-ref','owner_id':'owner-one'})

    def test_repository_documents_hide_queue_authority_and_leases(self):
        result=public_document({'_id':'job-one','org_id':'org-one','created_by':'user-one',
            'created_at':'2026-10-21T00:00:00+00:00','status':'queued',
            '_execution_actor':{'session_id':'private-session'},'_worker_lease_owner':'private-worker',
            '_worker_lease_expires_at':'2026-10-21T00:00:30+00:00'})
        self.assertEqual(result['id'],'job-one')
        self.assertNotIn('_execution_actor',result)
        self.assertFalse(any(key.startswith('_worker_lease_') for key in result))


@unittest.skipUnless(os.environ.get('MONGO_TEST_URL'),'Set MONGO_TEST_URL to a disposable MongoDB server')
class DurableScanQueueTests(unittest.TestCase):
    def test_atomic_claim_private_authority_and_expired_lease_recovery(self):
        code=textwrap.dedent('''
            import asyncio,os,uuid
            from datetime import datetime,timezone,timedelta
            from pymongo import MongoClient
            database='vaptx_durable_scans_'+uuid.uuid4().hex
            os.environ.update(MONGO_URL=os.environ['MONGO_TEST_URL'],DB_NAME=database,
                JWT_SECRET='synthetic-durable-scan-'*3,ADMIN_EMAIL='owner@example.com',
                ADMIN_PASSWORD='synthetic-owner-password',FRONTEND_URL='http://localhost:3000',
                INTERNAL_API_URL='http://127.0.0.1:8001',NMAP_BINARY='nmap',VAPTX_LOCAL_HTTP='1')
            import scanners
            from core import db,iso
            from repository import public_document
            mongo=MongoClient(os.environ['MONGO_TEST_URL'])
            now=iso()
            queued={'_id':'queued-one','org_id':'org-one','created_by':'user-one','created_at':now,
                'status':'queued','_execution_actor':{'kind':'session','session_id':'private-session'},
                'project_id':'project-one'}
            stale={'_id':'stale-one','org_id':'org-one','created_by':'user-one','created_at':now,
                'status':'running','_worker_lease_owner':'dead-worker',
                '_worker_lease_expires_at':iso(datetime.now(timezone.utc)-timedelta(seconds=5))}
            async def verify():
                await db.jobs.insert_many([queued,stale])
                claims=await asyncio.gather(scanners.claim_queued_scan('worker-a'),scanners.claim_queued_scan('worker-b'))
                winners=[claim for claim in claims if claim]
                assert len(winners)==1 and winners[0]['_id']=='queued-one'
                assert winners[0]['_execution_actor']['session_id']=='private-session'
                safe=public_document(winners[0])
                assert '_execution_actor' not in safe and not any(key.startswith('_worker_lease_') for key in safe)
                await scanners.recover_expired_scan_leases()
                recovered=await db.jobs.find_one({'_id':'stale-one'})
                assert recovered['status']=='interrupted' and '_worker_lease_owner' not in recovered
                assert (await db.jobs.find_one({'_id':'queued-one'}))['status']=='queued'
            try:asyncio.run(verify())
            finally:mongo.drop_database(database);mongo.close()
        ''')
        result=subprocess.run([sys.executable,'-c',code],text=True,capture_output=True,env=os.environ.copy())
        self.assertEqual(result.returncode,0,result.stdout+'\n'+result.stderr)

    def test_distributed_lease_excludes_contenders_and_rejects_stale_release(self):
        code=textwrap.dedent('''
            import asyncio,os,uuid,subprocess,sys
            from datetime import datetime,timezone,timedelta
            from pymongo import MongoClient
            database='vaptx_distributed_locks_'+uuid.uuid4().hex
            os.environ.update(MONGO_URL=os.environ['MONGO_TEST_URL'],DB_NAME=database,
                JWT_SECRET='synthetic-distributed-lock-'*3,ADMIN_EMAIL='owner@example.com',
                ADMIN_PASSWORD='synthetic-owner-password',FRONTEND_URL='http://localhost:3000',
                INTERNAL_API_URL='http://127.0.0.1:8001',NMAP_BINARY='nmap',VAPTX_LOCAL_HTTP='1')
            from core import db
            import distributed_locks
            from distributed_locks import distributed_lock
            from fastapi import HTTPException
            mongo=MongoClient(os.environ['MONGO_TEST_URL'])
            async def verify():
                distributed_locks.LEASE_SECONDS=.2
                distributed_locks.RENEW_SECONDS=.04
                heartbeat=distributed_lock('test','heartbeat',wait_seconds=.05)
                await heartbeat.__aenter__()
                try:
                    await asyncio.sleep(.45)
                    contender=distributed_lock('test','heartbeat',wait_seconds=.05)
                    try:await contender.__aenter__()
                    except HTTPException as error:assert error.status_code==503
                    else:raise AssertionError('An actively renewed lease expired')
                finally:await heartbeat.__aexit__(None,None,None)
                distributed_locks.LEASE_SECONDS=120
                distributed_locks.RENEW_SECONDS=20
                first=distributed_lock('test','org-one',wait_seconds=.1)
                second=distributed_lock('test','org-one',wait_seconds=.1)
                await first.__aenter__()
                try:
                    contender_code='import asyncio\\nfrom distributed_locks import distributed_lock\\nfrom fastapi import HTTPException\\nasync def verify():\\n try: await distributed_lock("test","org-one",wait_seconds=.05).__aenter__()\\n except HTTPException as error: assert error.status_code==503\\n else: raise AssertionError("Another process acquired the active lease")\\nasyncio.run(verify())'
                    contender=subprocess.run([sys.executable,'-c',contender_code],text=True,capture_output=True,
                        env=os.environ.copy(),timeout=15)
                    assert contender.returncode==0,contender.stdout+chr(10)+contender.stderr
                    try:await second.__aenter__()
                    except HTTPException as error:assert error.status_code==503
                    else:raise AssertionError('A concurrent process acquired an active lease')
                    await db.coordination_locks.update_one({'_id':first.key,'owner_id':first.owner},
                        {'$set':{'lease_expires_at':datetime.now(timezone.utc)-timedelta(seconds=1)}})
                    await second.__aenter__()
                    await first.__aexit__(None,None,None)
                    current=await db.coordination_locks.find_one({'_id':first.key})
                    assert current['owner_id']==second.owner
                finally:await second.__aexit__(None,None,None)
            try:asyncio.run(verify())
            finally:mongo.drop_database(database);mongo.close()
        ''')
        result=subprocess.run([sys.executable,'-c',code],text=True,capture_output=True,env=os.environ.copy())
        self.assertEqual(result.returncode,0,result.stdout+'\n'+result.stderr)
