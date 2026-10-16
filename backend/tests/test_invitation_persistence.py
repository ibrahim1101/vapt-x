"""Invitation lifecycle acceptance uses disposable Mongo and mocked SMTP only."""
import os
import subprocess
import sys
import textwrap
import unittest

@unittest.skipUnless(os.environ.get('MONGO_TEST_URL'),'Set MONGO_TEST_URL to a disposable MongoDB server')
class InvitationPersistenceTests(unittest.TestCase):
    def test_matching_account_replay_authority_role_preservation_and_tenant_boundaries(self):
        code=textwrap.dedent('''
            import os,uuid,hashlib
            from datetime import datetime,timedelta,timezone
            from concurrent.futures import ThreadPoolExecutor
            from urllib.parse import urlsplit,parse_qs
            from unittest.mock import patch
            from pymongo import MongoClient
            from fastapi.testclient import TestClient
            database='vaptx_invite_'+uuid.uuid4().hex
            os.environ.update(MONGO_URL=os.environ['MONGO_TEST_URL'],DB_NAME=database,JWT_SECRET='synthetic-invitation-'*4,
                ADMIN_EMAIL='owner@example.com',ADMIN_PASSWORD='synthetic-owner-password',FRONTEND_URL='http://localhost:3000',
                INTERNAL_API_URL='http://127.0.0.1:8001',NMAP_BINARY='nmap',VAPTX_LOCAL_HTTP='1',
                ACCOUNT_RECOVERY_ENABLED='0',ORG_INVITATIONS_ENABLED='1',RECOVERY_SMTP_HOST='smtp.synthetic.invalid',RECOVERY_SMTP_FROM='operator@example.com')
            from server import app
            mongo=MongoClient(os.environ['MONGO_TEST_URL'],serverSelectionTimeoutMS=5000);links=[]
            try:
                with patch('invitations.send_invitation_mail',side_effect=lambda config,email,link:links.append(link)),TestClient(app) as client:
                    origin={'origin':'http://localhost:3000'}
                    def headers(org=None):return {**origin,'x-csrf-token':client.cookies.get('csrf'),**({'x-org-id':org} if org else {})}
                    def switch(cookies):client.cookies.clear();client.cookies.update(cookies)
                    def register(email):
                        r=client.post('/api/auth/register',headers=origin,json={'email':email,'password':'synthetic-password'})
                        assert r.status_code==200,r.text
                        return r.json()
                    def invite(email,role='viewer'):
                        r=client.post('/api/invitations',headers=headers(org['id']),json={'email':email,'role':role})
                        assert r.status_code==202,r.text
                        return r.json(),parse_qs(urlsplit(links[-1]).fragment)['invite_token'][0]
                    def accept(raw):return client.post('/api/auth/invitations/accept',headers=headers(),json={'token':raw})
                    admin=register('inviter@example.com')
                    org=client.post('/api/organizations',headers=headers(),json={'name':'Invitation organization'}).json()
                    other=client.post('/api/organizations',headers=headers(),json={'name':'Other organization'}).json()
                    admin_cookies=dict(client.cookies)
                    item,raw=invite('recipient@example.com')
                    stored=mongo[database].invitations.find_one({'_id':item['id']})
                    assert stored['token_hash']==hashlib.sha256(raw.encode()).hexdigest() and raw not in str(stored)
                    assert 'token_hash' not in item and raw not in str(item)
                    assert client.get('/api/invitations',headers={'x-org-id':other['id']}).json()['total']==0
                    assert client.post('/api/invitations/'+item['id']+'/revoke',headers=headers(other['id'])).status_code==404
                    wrong=register('wrong@example.com')
                    assert accept(raw).status_code==403
                    recipient=register('recipient@example.com')
                    personal=client.post('/api/organizations',headers=headers(),json={'name':'Recipient personal organization'}).json()
                    personal_token=client.post('/api/api-tokens',headers=headers(personal['id']),json={'name':'Personal token','scopes':['read']}).json()['token']
                    recipient_cookies=dict(client.cookies)
                    preview=client.post('/api/auth/invitations/preview',headers=headers(),json={'token':raw})
                    assert preview.status_code==200 and preview.json()['organization_name']=='Invitation organization',preview.text
                    assert not mongo[database].memberships.find_one({'org_id':org['id'],'user_id':recipient['id']})
                    assert client.post('/api/auth/invitations/accept',headers=origin,json={'token':raw}).status_code==403
                    with ThreadPoolExecutor(max_workers=2) as pool:
                        results=list(pool.map(lambda _:accept(raw).status_code,range(2)))
                    assert sorted(results)==[200,400],results
                    member=mongo[database].memberships.find_one({'org_id':org['id'],'user_id':recipient['id']})
                    assert member['role']=='viewer'
                    assert mongo[database].memberships.count_documents({'user_id':recipient['id']})==2
                    assert accept(raw).status_code==400
                    assert client.get('/api/projects',headers={'authorization':'Bearer '+personal_token}).status_code==200
                    assert client.get('/api/invitations',headers={'authorization':'Bearer '+personal_token}).status_code==403
                    old_token=client.post('/api/api-tokens',headers=headers(org['id']),json={'name':'Pre-removal token','scopes':['read']}).json()['token']
                    switch(admin_cookies)
                    assert client.post('/api/members/'+recipient['id']+'/remove',headers=headers(org['id']),json={'reason':'Synthetic reinvitation fixture'}).status_code==200
                    again,new_raw=invite('recipient@example.com','auditor')
                    switch(recipient_cookies);assert accept(new_raw).status_code==200
                    assert mongo[database].memberships.find_one({'org_id':org['id'],'user_id':recipient['id']})['role']=='auditor'
                    assert client.get('/api/projects',headers={'authorization':'Bearer '+old_token}).status_code==401
                    assert client.get('/api/projects',headers={'authorization':'Bearer '+personal_token}).status_code==200
                    switch(admin_cookies);existing,pending=invite('existing@example.com','viewer')
                    existing_user=register('existing@example.com');existing_cookies=dict(client.cookies)
                    switch(admin_cookies)
                    assert client.post('/api/members',headers=headers(org['id']),json={'email':'existing@example.com','role':'security_lead'}).status_code==200
                    switch(existing_cookies);assert accept(pending).status_code==200
                    assert mongo[database].memberships.find_one({'org_id':org['id'],'user_id':existing_user['id']})['role']=='security_lead'
                    switch(admin_cookies);revoked,revoke_raw=invite('revoked@example.com')
                    assert client.post('/api/invitations/'+revoked['id']+'/revoke',headers=headers(org['id'])).status_code==200
                    register('revoked@example.com');assert accept(revoke_raw).status_code==400
                    switch(admin_cookies);expired,expired_raw=invite('expired@example.com')
                    mongo[database].invitations.update_one({'_id':expired['id']},{'$set':{'expires_at':datetime.now(timezone.utc)-timedelta(minutes=1)}})
                    register('expired@example.com');assert accept(expired_raw).status_code==400
                    switch(admin_cookies);stale,stale_raw=invite('stale@example.com')
                    stale_user=register('stale@example.com');stale_cookies=dict(client.cookies)
                    mongo[database].memberships.update_one({'org_id':org['id'],'user_id':admin['id']},{'$set':{'role':'viewer'}})
                    assert accept(stale_raw).status_code==400
                    mongo[database].memberships.update_one({'org_id':org['id'],'user_id':admin['id']},{'$set':{'role':'org_admin'}})
                    switch(admin_cookies)
                    r=client.post('/api/auth/password',headers=headers(),json={'current_password':'synthetic-password','new_password':'synthetic-new-password'})
                    assert r.status_code==200,r.text
                    admin_cookies=dict(client.cookies);switch(stale_cookies);assert accept(stale_raw).status_code==400
                    switch(admin_cookies)
                    mongo[database].invitations.insert_many([{'_id':'invite-page-'+str(i),'org_id':org['id'],'created_by':admin['id'],
                        'created_at':'2020-01-01T12:00:00+00:00','email':'nav.*@example.com','role':'viewer','status':'pending',
                        'expires_at':datetime.now(timezone.utc)+timedelta(days=1),'token_hash':'synthetic-page-'+str(i)} for i in range(1005)])
                    page=client.get('/api/invitations',headers={'x-org-id':org['id']},params={'search':'nav.*','offset':1000,'status':'pending'}).json()
                    assert page['total']==1005 and len(page['items'])==5 and not page['has_more'],page
                    assert all('token_hash' not in row for row in page['items'])
            finally:
                mongo.drop_database(database);mongo.close()
        ''')
        result=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,timeout=60)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
