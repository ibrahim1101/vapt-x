"""Admission policy with real disposable Mongo; mail remains mocked."""
import os
import subprocess
import sys
import textwrap
import unittest

@unittest.skipUnless(os.environ.get('MONGO_TEST_URL'),'Set MONGO_TEST_URL to a disposable MongoDB server')
class IdentityPolicyPersistenceTests(unittest.TestCase):
    def test_limited_session_verification_and_closed_registration(self):
        code=textwrap.dedent('''
            import os,uuid
            from unittest.mock import patch
            from urllib.parse import urlsplit,parse_qs
            from pymongo import MongoClient
            from fastapi.testclient import TestClient
            database='vaptx_policy_'+uuid.uuid4().hex
            os.environ.update(MONGO_URL=os.environ['MONGO_TEST_URL'],DB_NAME=database,JWT_SECRET='synthetic-policy-'*5,
                ADMIN_EMAIL='owner@example.com',ADMIN_PASSWORD='synthetic-owner-password',FRONTEND_URL='http://localhost:3000',
                INTERNAL_API_URL='http://127.0.0.1:8001',NMAP_BINARY='nmap',VAPTX_LOCAL_HTTP='1',
                REGISTRATION_MODE='open',REQUIRE_VERIFIED_EMAIL='1',EMAIL_VERIFICATION_ENABLED='1',ORG_INVITATIONS_ENABLED='1',
                RECOVERY_SMTP_HOST='smtp.synthetic.invalid',RECOVERY_SMTP_FROM='operator@example.com')
            from server import app
            mongo=MongoClient(os.environ['MONGO_TEST_URL']);links=[];invitations=[]
            try:
                with patch('account_verification.send_verification_mail',side_effect=lambda config,email,link:links.append(link)),patch('invitations.send_invitation_mail',side_effect=lambda config,email,link:invitations.append(link)),TestClient(app) as client:
                    origin={'origin':'http://localhost:3000'}
                    def headers():return {**origin,'x-csrf-token':client.cookies.get('csrf')}
                    assert client.get('/api/auth/policy').json()=={'registration_mode':'open','require_verified_email':True}
                    account=client.post('/api/auth/register',headers=origin,json={'email':'new@example.com','password':'synthetic-password'})
                    assert account.status_code==200,account.text
                    assert account.json()['verification_required'] is True
                    assert client.get('/api/auth/me').json()['verification_required'] is True
                    for path in ('/api/projects','/api/auth/mfa'):
                        result=client.get(path)
                        assert result.status_code==403 and result.json()['detail']['code']=='email_verification_required',(path,result.text)
                    assert client.post('/api/organizations',headers=headers(),json={'name':'Blocked organization'}).status_code==403
                    assert client.post('/api/auth/email-verification/request',headers=headers()).status_code==202
                    token=parse_qs(urlsplit(links[-1]).fragment)['verify_email_token'][0]
                    assert client.post('/api/auth/email-verification/confirm',headers=origin,json={'token':token}).status_code==200
                    assert client.get('/api/auth/me').json()['verification_required'] is False
                    organization=client.post('/api/organizations',headers=headers(),json={'name':'Synthetic policy organization'})
                    assert organization.status_code==200,organization.text
                    org_id=organization.json()['id']
                    sent=client.post('/api/invitations',headers={**headers(),'x-org-id':org_id},json={'email':'invited@example.com','role':'viewer'})
                    assert sent.status_code==202,sent.text
                    invite=parse_qs(urlsplit(invitations[-1]).fragment)['invite_token'][0]
                    with patch.dict(os.environ,{'REGISTRATION_MODE':'invite_only'}):
                        values={'email':'invited@example.com','password':'synthetic-password'}
                        assert client.post('/api/auth/register',headers=origin,json=values).status_code==403
                        assert client.post('/api/auth/register',headers=origin,json={**values,'email':'wrong@example.com','invitation_token':invite}).status_code==403
                        registered=client.post('/api/auth/register',headers=origin,json={**values,'invitation_token':invite})
                        assert registered.status_code==200,registered.text
                        assert client.get('/api/auth/me').json()['organizations']==[]
                        assert mongo[database].invitations.find_one({'email':'invited@example.com'})['status']=='pending'
                        assert client.post('/api/auth/invitations/accept',headers=headers(),json={'token':invite}).status_code==403
                        assert client.post('/api/auth/email-verification/request',headers=headers()).status_code==202
                        proof=parse_qs(urlsplit(links[-1]).fragment)['verify_email_token'][0]
                        assert client.post('/api/auth/email-verification/confirm',headers=origin,json={'token':proof}).status_code==200
                        accepted=client.post('/api/auth/invitations/accept',headers=headers(),json={'token':invite})
                        assert accepted.status_code==200,accepted.text
                    with patch.dict(os.environ,{'REGISTRATION_MODE':'closed'}):
                        denied=client.post('/api/auth/register',headers=origin,json={'email':'blocked@example.com','password':'synthetic-password'})
                        assert denied.status_code==403,denied.text
                        assert mongo[database].users.count_documents({'email':'blocked@example.com'})==0
                        assert client.post('/api/auth/login',headers=origin,json={'email':'new@example.com','password':'synthetic-password'}).status_code==200
                    # A fresh access JWT must not survive expiry of its stored session.
                    from core import decode_token
                    sid=decode_token(client.cookies.get('access_token'))['sid']
                    mongo[database].sessions.update_one({'_id':sid},{'$set':{'expires_at':'2000-01-01T00:00:00+00:00'}})
                    assert client.get('/api/auth/me').status_code==401
                    assert client.post('/api/auth/refresh',headers=headers()).status_code==401
                    mongo[database].sessions.update_one({'_id':sid},{'$unset':{'expires_at':''}})
                    assert client.get('/api/auth/me').status_code==401
            finally:
                mongo.drop_database(database);mongo.close()
        ''')
        result=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,timeout=60)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
