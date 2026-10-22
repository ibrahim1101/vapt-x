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

    def test_scan_admission_is_org_wide_across_api_processes(self):
        code=textwrap.dedent('''
            import json,os,subprocess,sys,textwrap,uuid
            from datetime import datetime,timezone,timedelta
            from pymongo import MongoClient
            database='vaptx_multiworker_admission_'+uuid.uuid4().hex
            os.environ.update(MONGO_URL=os.environ['MONGO_TEST_URL'],DB_NAME=database,
                JWT_SECRET='synthetic-multiworker-admission-'*3,ADMIN_EMAIL='owner@example.com',
                ADMIN_PASSWORD='synthetic-owner-password',FRONTEND_URL='http://localhost:3000',
                INTERNAL_API_URL='http://127.0.0.1:8001',NMAP_BINARY='nmap',VAPTX_LOCAL_HTTP='1')
            mongo=MongoClient(os.environ['MONGO_TEST_URL'])
            db=mongo[database]
            now=datetime.now(timezone.utc)
            db.projects.insert_one({'_id':'visible-project','org_id':'org-one','created_by':'owner','created_at':now.isoformat(),'name':'Visible'})
            db.scopes.insert_one({'_id':'scope-one','org_id':'org-one','project_id':'visible-project','created_by':'owner',
                'created_at':now.isoformat(),'host':'training://local','authorized':True,
                'starts_at':(now-timedelta(minutes=1)).isoformat(),'ends_at':(now+timedelta(hours=1)).isoformat(),
                'allowed_scanners':['safe']})
            db.assets.insert_one({'_id':'asset-one','org_id':'org-one','project_id':'visible-project','created_by':'owner',
                'created_at':now.isoformat(),'scope_id':'scope-one','target':'training://local'})
            db.assessments.insert_one({'_id':'assessment-one','org_id':'org-one','project_id':'visible-project',
                'created_by':'owner','created_at':now.isoformat(),'asset_ids':['asset-one'],'status':'draft'})
            # A member limited to visible-project must still count activity in another project.
            db.jobs.insert_one({'_id':'hidden-active-job','org_id':'org-one','project_id':'hidden-project',
                'assessment_id':'hidden-assessment','asset_id':'hidden-asset','created_by':'owner',
                'created_at':now.isoformat(),'status':'queued','source':'execution','scanner':'safe'})
            worker_code=textwrap.dedent("""
                import asyncio,json,os,sys,time
                from core import Ctx,db
                from fastapi import HTTPException
                from workflow import ScanInput,create_scan
                worker=sys.argv[1]
                async def run():
                    await db.multiworker_admission_barrier.insert_one({'_id':worker})
                    deadline=time.monotonic()+10
                    while await db.multiworker_admission_barrier.count_documents({})<2:
                        if time.monotonic()>deadline:raise TimeoutError('peer did not reach admission barrier')
                        await asyncio.sleep(.02)
                    ctx=Ctx({'id':worker},'org-one','analyst')
                    ctx.project_ids=['visible-project']
                    try:
                        job=await create_scan(ScanInput(assessment_id='assessment-one',asset_id='asset-one',scanner='safe'),ctx)
                        return {'status':201,'job_id':job['id']}
                    except HTTPException as error:return {'status':error.status_code}
                print(json.dumps(asyncio.run(run())))
            """)
            processes=[subprocess.Popen([sys.executable,'-c',worker_code,name],text=True,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=os.environ.copy()) for name in ('api-a','api-b')]
            try:
                results=[]
                for process in processes:
                    stdout,stderr=process.communicate(timeout=30)
                    assert process.returncode==0,stdout+'\\n'+stderr
                    results.append(json.loads(stdout.strip().splitlines()[-1]))
                assert sorted(result['status'] for result in results)==[201,429],results
                assert db.jobs.count_documents({'org_id':'org-one','status':{'$in':['queued','running','cancelling']}})==2
                created=[result['job_id'] for result in results if result['status']==201]
                assert len(created)==1 and db.jobs.count_documents({'_id':created[0],'project_id':'visible-project'})==1
            finally:
                for process in processes:
                    if process.poll() is None:process.kill();process.wait()
                mongo.drop_database(database);mongo.close()
        ''')
        result=subprocess.run([sys.executable,'-c',code],text=True,capture_output=True,env=os.environ.copy(),timeout=45)
        self.assertEqual(result.returncode,0,result.stdout+'\n'+result.stderr)

    def test_live_api_servers_serialize_scan_admission_over_http(self):
        code=textwrap.dedent('''
            import asyncio,concurrent.futures,json,os,socket,subprocess,sys,textwrap,time,urllib.error,urllib.request,uuid
            from datetime import datetime,timezone,timedelta
            from pymongo import MongoClient
            database='vaptx_live_api_admission_'+uuid.uuid4().hex
            os.environ.update(MONGO_URL=os.environ['MONGO_TEST_URL'],DB_NAME=database,
                JWT_SECRET='synthetic-live-api-admission-'*3,ADMIN_EMAIL='owner@example.com',
                ADMIN_PASSWORD='synthetic-owner-password',FRONTEND_URL='http://localhost:3000',
                INTERNAL_API_URL='http://127.0.0.1:8001',NMAP_BINARY='nmap',VAPTX_LOCAL_HTTP='1')
            mongo=MongoClient(os.environ['MONGO_TEST_URL']);db=mongo[database]
            from auth import seed_admin
            asyncio.run(seed_admin())
            now=datetime.now(timezone.utc)
            db.projects.insert_one({'_id':'visible-project','org_id':'org-one','created_by':'owner','created_at':now.isoformat(),'name':'Visible'})
            db.scopes.insert_one({'_id':'scope-one','org_id':'org-one','project_id':'visible-project','created_by':'owner',
                'created_at':now.isoformat(),'host':'training://local','authorized':True,
                'starts_at':(now-timedelta(minutes=1)).isoformat(),'ends_at':(now+timedelta(hours=1)).isoformat(),
                'allowed_scanners':['safe']})
            db.assets.insert_one({'_id':'asset-one','org_id':'org-one','project_id':'visible-project','created_by':'owner',
                'created_at':now.isoformat(),'scope_id':'scope-one','target':'training://local'})
            db.assessments.insert_one({'_id':'assessment-one','org_id':'org-one','project_id':'visible-project',
                'created_by':'owner','created_at':now.isoformat(),'asset_ids':['asset-one'],'status':'draft'})
            db.jobs.insert_one({'_id':'hidden-active-job','org_id':'org-one','project_id':'hidden-project',
                'assessment_id':'hidden-assessment','asset_id':'hidden-asset','created_by':'owner',
                'created_at':now.isoformat(),'status':'running','source':'execution','scanner':'safe',
                '_worker_lease_owner':'synthetic-existing-worker',
                '_worker_lease_expires_at':(now+timedelta(minutes=1)).isoformat()})
            db.jobs.insert_one({'_id':'expired-before-api-start','org_id':'org-one','project_id':'visible-project',
                'assessment_id':'assessment-one','asset_id':'asset-one','created_by':'owner',
                'created_at':now.isoformat(),'status':'running','source':'execution','scanner':'safe',
                '_worker_lease_owner':'synthetic-abandoned-worker',
                '_worker_lease_expires_at':(now-timedelta(minutes=1)).isoformat()})
            server_code=textwrap.dedent("""
                import asyncio,sys,uvicorn
                import core,server
                from core import Ctx
                async def fixed_context():
                    ctx=Ctx({'id':'synthetic-analyst'},'org-one','analyst')
                    ctx.project_ids=['visible-project']
                    return ctx
                async def idle_worker(worker_id):
                    await asyncio.Event().wait()
                server.app.dependency_overrides[core.get_ctx]=fixed_context
                server.scan_worker_loop=idle_worker
                uvicorn.run(server.app,host='127.0.0.1',port=int(sys.argv[1]),log_level='error')
            """)
            servers=[]
            try:
                ports=[]
                for _ in range(2):
                    with socket.socket() as sock:
                        sock.bind(('127.0.0.1',0));ports.append(sock.getsockname()[1])
                for port in ports:
                    servers.append(subprocess.Popen([sys.executable,'-c',server_code,str(port)],
                        text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=os.environ.copy()))
                for port,process in zip(ports,servers):
                    deadline=time.monotonic()+20
                    while True:
                        if process.poll() is not None:
                            stdout,stderr=process.communicate();raise AssertionError(stdout+'\\n'+stderr)
                        try:
                            with urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health',timeout=.5) as response:
                                if response.status==200:break
                        except Exception:
                            if time.monotonic()>deadline:raise TimeoutError('API server did not become healthy')
                            time.sleep(.05)
                recovered=db.jobs.find_one({'_id':'expired-before-api-start'})
                assert recovered['status']=='interrupted',recovered
                assert '_worker_lease_owner' not in recovered and '_worker_lease_expires_at' not in recovered,recovered
                barrier=__import__('threading').Barrier(2)
                def request_scan(port):
                    payload=json.dumps({'assessment_id':'assessment-one','asset_id':'asset-one','scanner':'safe'}).encode()
                    request=urllib.request.Request(f'http://127.0.0.1:{port}/api/scans',data=payload,
                        headers={'Content-Type':'application/json','Origin':'http://localhost:3000',
                            'Cookie':'csrf=synthetic-csrf','X-CSRF-Token':'synthetic-csrf'},method='POST')
                    barrier.wait(timeout=10)
                    try:
                        with urllib.request.urlopen(request,timeout=10) as response:
                            return response.status,json.loads(response.read())
                    except urllib.error.HTTPError as error:return error.code,json.loads(error.read())
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    results=list(pool.map(request_scan,ports))
                assert sorted(status for status,_ in results)==[200,429],results
                assert db.jobs.count_documents({'org_id':'org-one','status':{'$in':['queued','running','cancelling']}})==2
                admitted=[body for status,body in results if status==200]
                assert len(admitted)==1 and admitted[0]['project_id']=='visible-project',admitted
            finally:
                for process in servers:
                    if process.poll() is None:process.terminate()
                for process in servers:
                    try:process.communicate(timeout=10)
                    except subprocess.TimeoutExpired:process.kill();process.wait()
                mongo.drop_database(database);mongo.close()
        ''')
        result=subprocess.run([sys.executable,'-c',code],text=True,capture_output=True,env=os.environ.copy(),timeout=90)
        self.assertEqual(result.returncode,0,result.stdout+'\n'+result.stderr)

    def test_remote_process_cancellation_terminal_result_and_recovery(self):
        code=textwrap.dedent('''
            import json,os,subprocess,sys,textwrap,time,uuid
            from datetime import datetime,timezone,timedelta
            from pymongo import MongoClient
            database='vaptx_multiworker_cancel_'+uuid.uuid4().hex
            os.environ.update(MONGO_URL=os.environ['MONGO_TEST_URL'],DB_NAME=database,
                JWT_SECRET='synthetic-multiworker-cancel-'*3,ADMIN_EMAIL='owner@example.com',
                ADMIN_PASSWORD='synthetic-owner-password',FRONTEND_URL='http://localhost:3000',
                INTERNAL_API_URL='http://127.0.0.1:8001',NMAP_BINARY='nmap',VAPTX_LOCAL_HTTP='1')
            mongo=MongoClient(os.environ['MONGO_TEST_URL'])
            db=mongo[database]
            now=datetime.now(timezone.utc)
            future=(now+timedelta(minutes=5)).isoformat()
            expired=(now-timedelta(seconds=1)).isoformat()
            db.projects.insert_one({'_id':'project-one','org_id':'org-one','created_by':'owner','created_at':now.isoformat(),'name':'Synthetic'})
            db.scopes.insert_one({'_id':'scope-one','org_id':'org-one','project_id':'project-one','created_by':'owner',
                'created_at':now.isoformat(),'host':'training://local','authorized':True,
                'starts_at':(now-timedelta(minutes=1)).isoformat(),'ends_at':future,'allowed_scanners':['safe']})
            db.assets.insert_one({'_id':'asset-one','org_id':'org-one','project_id':'project-one','created_by':'owner',
                'created_at':now.isoformat(),'scope_id':'scope-one','target':'training://local'})
            db.assessments.insert_one({'_id':'assessment-one','org_id':'org-one','project_id':'project-one',
                'created_by':'owner','created_at':now.isoformat(),'asset_ids':['asset-one'],'status':'draft'})
            db.assessments.insert_one({'_id':'assessment-success','org_id':'org-one','project_id':'project-one',
                'created_by':'owner','created_at':now.isoformat(),'asset_ids':['asset-one'],'status':'draft'})
            db.users.insert_one({'_id':'analyst','name':'Synthetic Analyst','email':'analyst@example.com',
                'credential_version':0,'disabled':False})
            db.memberships.insert_one({'_id':'membership-one','org_id':'org-one','user_id':'analyst','role':'analyst',
                'project_access':{'mode':'selected','project_ids':['project-one']}})
            db.sessions.insert_one({'_id':'session-one','user_id':'analyst','credential_version':0,'revoked':False,'expires_at':future})
            actor={'org_id':'org-one','user_id':'analyst','kind':'session','session_id':'session-one',
                'credential_version':0,'membership_id':'membership-one'}
            db.jobs.insert_one({'_id':'job-one','org_id':'org-one','project_id':'project-one',
                'assessment_id':'assessment-one','asset_id':'asset-one','created_by':'analyst',
                'created_at':now.isoformat(),'scanner':'safe','source':'execution','status':'queued',
                '_execution_actor':actor,'_worker_lease_owner':'worker-one',
                '_worker_lease_expires_at':future})
            db.jobs.insert_one({'_id':'job-success','org_id':'org-one','project_id':'project-one',
                'assessment_id':'assessment-success','asset_id':'asset-one','created_by':'analyst',
                'created_at':now.isoformat(),'scanner':'safe','source':'execution','status':'queued',
                '_execution_actor':actor,'_worker_lease_owner':'worker-success',
                '_worker_lease_expires_at':future})
            db.jobs.insert_one({'_id':'job-abandoned','org_id':'org-one','project_id':'project-one',
                'assessment_id':'assessment-abandoned','asset_id':'asset-one','created_by':'analyst',
                'created_at':now.isoformat(),'scanner':'safe','source':'execution','status':'running',
                '_worker_lease_owner':'dead-worker','_worker_lease_expires_at':expired})
            child_code=textwrap.dedent("""
                import asyncio,json,sys
                from core import Ctx,db
                import scanners
                async def hold_check(*args):
                    await db.worker_signals.update_one({'_id':'check-started'}, {'$set':{'ready':True}},upsert=True)
                    await asyncio.Event().wait()
                async def successful_check(*args):return [],[]
                async def run():
                    if sys.argv[1] in {'worker','complete'}:
                        job_id='job-one' if sys.argv[1]=='worker' else 'job-success'
                        worker_id='worker-one' if sys.argv[1]=='worker' else 'worker-success'
                        scanners.safe_checks=hold_check if sys.argv[1]=='worker' else successful_check
                        job=await db.jobs.find_one({'_id':job_id})
                        ctx=await scanners.execution_context(job['_execution_actor'])
                        await scanners.run_job(ctx,job_id,worker_id=worker_id)
                        current=await db.jobs.find_one({'_id':job_id})
                        return {'job_status':current['status']}
                    if sys.argv[1]=='recover':
                        await scanners.recover_expired_scan_leases()
                        current=await db.jobs.find_one({'_id':'job-abandoned'})
                        return {'job_status':current['status'],'worker_owner':current.get('_worker_lease_owner')}
                    from workflow import ScopeRevocationInput,cancel_assessment
                    ctx=Ctx({'id':'analyst','email':'analyst@example.com'},'org-one','analyst')
                    result=await cancel_assessment('assessment-one',ScopeRevocationInput(reason='Synthetic cross-process cancellation'),ctx)
                    return {'assessment_status':result['status']}
                print(json.dumps(asyncio.run(run())))
            """)
            worker=subprocess.Popen([sys.executable,'-c',child_code,'worker'],text=True,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=os.environ.copy())
            try:
                deadline=time.monotonic()+20
                while not db.worker_signals.find_one({'_id':'check-started'}):
                    if worker.poll() is not None:raise AssertionError('Worker exited before scanner execution')
                    if time.monotonic()>deadline:raise TimeoutError('Worker did not reach scanner execution')
                    time.sleep(.05)
                cancelled=subprocess.run([sys.executable,'-c',child_code,'cancel'],text=True,
                    capture_output=True,env=os.environ.copy(),timeout=15)
                assert cancelled.returncode==0,cancelled.stdout+'\\n'+cancelled.stderr
                assert json.loads(cancelled.stdout.strip().splitlines()[-1])=={'assessment_status':'cancelled'}
                stdout,stderr=worker.communicate(timeout=15)
                assert worker.returncode==0,stdout+'\\n'+stderr
                assert json.loads(stdout.strip().splitlines()[-1])=={'job_status':'cancelled'}
                assert db.assessments.find_one({'_id':'assessment-one'})['status']=='cancelled'
                assert db.jobs.find_one({'_id':'job-one'})['status']=='cancelled'
                assert db.findings.count_documents({'job_id':'job-one'})==0
                completed=subprocess.run([sys.executable,'-c',child_code,'complete'],text=True,
                    capture_output=True,env=os.environ.copy(),timeout=20)
                assert completed.returncode==0,completed.stdout+'\\n'+completed.stderr
                assert json.loads(completed.stdout.strip().splitlines()[-1])=={'job_status':'completed'}
                assert db.jobs.find_one({'_id':'job-success'})['status']=='completed'
                assert db.assessments.find_one({'_id':'assessment-success'})['status']=='review'
                assert db.jobs.find_one({'_id':'job-success'})['finding_count']==0
                recovered=subprocess.run([sys.executable,'-c',child_code,'recover'],text=True,
                    capture_output=True,env=os.environ.copy(),timeout=20)
                assert recovered.returncode==0,recovered.stdout+'\\n'+recovered.stderr
                assert json.loads(recovered.stdout.strip().splitlines()[-1])=={'job_status':'interrupted','worker_owner':None}
                abandoned=db.jobs.find_one({'_id':'job-abandoned'})
                assert abandoned['status']=='interrupted' and '_worker_lease_owner' not in abandoned
                assert '_worker_lease_expires_at' not in abandoned
            finally:
                if worker.poll() is None:worker.kill();worker.wait()
                mongo.drop_database(database);mongo.close()
        ''')
        result=subprocess.run([sys.executable,'-c',code],text=True,capture_output=True,env=os.environ.copy(),timeout=60)
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
