"""Real Mongo admission and failure persistence; synthetic jobs, no network."""
import os,subprocess,sys,textwrap,unittest
@unittest.skipUnless(os.environ.get('MONGO_TEST_URL'),'Set MONGO_TEST_URL to a disposable MongoDB server')
class ExecutionCredentialPersistenceTests(unittest.TestCase):
 def test_revocation_and_expiry_before_execution_with_real_records(self):
  code=textwrap.dedent('''
   import asyncio,os,uuid
   from datetime import timedelta
   from unittest.mock import AsyncMock,patch
   database='vaptx_execution_'+uuid.uuid4().hex
   os.environ.update(MONGO_URL=os.environ['MONGO_TEST_URL'],DB_NAME=database,JWT_SECRET='synthetic-execution-'*5,
    ADMIN_EMAIL='owner@example.com',ADMIN_PASSWORD='synthetic-owner-password',FRONTEND_URL='http://localhost:3000',
    INTERNAL_API_URL='http://127.0.0.1:8001',NMAP_BINARY='nmap',VAPTX_LOCAL_HTTP='1')
   from core import db,client,Ctx,iso,now
   import scanners
   async def main():
    try:
     for case in ('disabled','rotated','session_revoked','session_expired','token_revoked','token_expired','token_foreign','token_epoch','token_scope','token_projects','token_membership','valid_session','valid_token'):
      for name in ('users','sessions','api_tokens','memberships','jobs','assessments','assets','audit_events'):
       await db[name].delete_many({})
      await db.users.insert_one({'_id':'u','credential_version':2 if case=='rotated' else 1,'disabled':case=='disabled'})
      await db.memberships.insert_one({'_id':'membership','user_id':'u','org_id':'org','role':'analyst'})
      await db.sessions.insert_one({'_id':'session','user_id':'u','credential_version':1,'revoked':case=='session_revoked','expires_at':iso(now()+timedelta(hours=-1 if case=='session_expired' else 1))})
      await db.api_tokens.insert_one({'_id':'token','org_id':'foreign' if case=='token_foreign' else 'org','created_by':'u','membership_id':'different' if case=='token_membership' else 'membership','credential_version':0 if case=='token_epoch' else 1,'revoked':case=='token_revoked','expires_at':iso(now()+timedelta(hours=-1 if case=='token_expired' else 1)),'scopes':['read'] if case=='token_scope' else ['scan'],'project_ids':[] if case=='token_projects' else ['project']})
      common={'org_id':'org','created_by':'u','project_id':'project'}
      await db.jobs.insert_one({'_id':'job',**common,'status':'queued','assessment_id':'assessment','asset_id':'asset','scanner':'safe','source':'execution'})
      await db.assessments.insert_one({'_id':'assessment',**common,'status':'queued'})
      await db.assets.insert_one({'_id':'asset',**common,'target':'training://local'})
      await db.projects.replace_one({'_id':'project'},{'_id':'project','org_id':'org','created_by':'u'},upsert=True)
      identity={'id':'u','credential_version':1,'_sid':'session'}
      if 'token' in case:identity.update(_api_token_id='token',_token_membership_id='membership',_token_scopes=['scan'],_token_project_ids=['project'])
      ctx=Ctx(identity,'org','analyst');ctx.membership_id='membership'
      with patch.object(scanners,'validate_scope',new_callable=AsyncMock) as scope,patch.object(scanners,'safe_checks',new_callable=AsyncMock,return_value=([],[])) as checks,patch.object(scanners,'resolve_public',new_callable=AsyncMock) as resolve:
       await scanners.run_job(ctx,'job')
       job=await db.jobs.find_one({'_id':'job'})
       if case.startswith('valid_'):
        assert job['status']=='completed',(case,job)
        checks.assert_awaited_once();scope.assert_awaited_once()
       else:
        assert job['status']=='failed' and job.get('error'),(case,job)
        scope.assert_not_awaited();checks.assert_not_awaited()
        assert (await db.assessments.find_one({'_id':'assessment'}))['status']=='queued',case
       resolve.assert_not_awaited()
      event=await db.audit_events.find_one({'action':'scan.completed' if case.startswith('valid_') else 'scan.failed'})
      assert event is not None,case
    finally:
     await client.drop_database(database)
     client.close()
   asyncio.run(main())
  ''')
  result=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,timeout=60)
  self.assertEqual(result.returncode,0,result.stdout+result.stderr)
