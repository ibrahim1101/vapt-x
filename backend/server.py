import asyncio
import logging
import secrets
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from starlette.middleware.cors import CORSMiddleware
from core import db, client, iso, settings, get_current_user
from pymongo.errors import PyMongoError
from request_limits import RequestBodyLimitMiddleware
from auth import router as auth_router, seed_admin
from workflow import router as workflow_router
from analytics import router as analytics_router
from evidence import router as evidence_router
from reporting import router as reporting_router
from analyst import router as analyst_router
from intelligence import router as intelligence_router
from inventory_imports import router as inventory_router
from governance import router as governance_router
from api_tokens import router as tokens_router
from webhooks import router as webhooks_router,configured as webhooks_configured,delivery_loop


@asynccontextmanager
async def lifespan(app):
    webhook_worker=None
    try:
        from account_recovery import mail_configuration
        mail_configuration('EMAIL_VERIFICATION_ENABLED')
        mail_configuration('ORG_INVITATIONS_ENABLED')
        mail_configuration()  # Enabled mail delivery must be valid before accepting requests.
        await db.command('ping')
        await seed_admin()
        await db.sessions.create_index([('user_id', 1), ('revoked', 1), ('created_at', -1)])
        for collection in ('project_templates', 'projects', 'scopes', 'assets', 'assessments', 'jobs', 'findings', 'tasks', 'evidence', 'evidence_chunks', 'reports', 'report_files', 'audit_events', 'ai_sessions'):
            await db[collection].create_index([('org_id', 1), ('created_at', -1)])
        await db.audit_events.create_index([('org_id',1),('created_at',-1),('_id',-1)])
        await db.findings.create_index([('org_id', 1), ('project_id', 1), ('created_at', -1), ('_id', -1)])
        await db.webhook_deliveries.create_index([('status',1),('next_attempt_at',1),('lease_expires_at',1),('created_at',1)])
        await db.webhook_deliveries.create_index([('org_id',1),('webhook_id',1),('created_at',-1)])
        await db.api_tokens.create_index('token_hash',unique=True)
        await db.account_recovery.create_index('token_hash',unique=True)
        await db.account_recovery.create_index('expires_at',expireAfterSeconds=0)
        await db.email_verifications.create_index('token_hash',unique=True)
        await db.email_verifications.create_index('expires_at',expireAfterSeconds=0)
        await db.invitations.create_index('token_hash',unique=True)
        await db.invitations.create_index('expires_at',expireAfterSeconds=0)
        await db.invitations.create_index([('org_id',1),('created_at',-1),('_id',-1)])
        await db.api_tokens.create_index([('org_id',1),('created_by',1),('revoked',1),('expires_at',1)])
        await db.sla_policies.create_index('org_id',unique=True)
        await db.finding_comments.create_index([('org_id',1),('finding_id',1),('created_at',-1),('_id',-1)])
        await db.inventory_items.create_index([('org_id',1),('asset_id',1),('fingerprint',1)],unique=True)
        await db.evidence_chunks.create_index([('org_id', 1), ('evidence_id', 1), ('index', 1)], unique=True)
        await db.jobs.update_many({'status': {'$in': ['queued', 'running', 'cancelling']}}, {'$set': {'status': 'interrupted', 'error': 'Worker restarted before completion; run again.', 'finished_at': iso()}})
        if webhooks_configured():webhook_worker=asyncio.create_task(delivery_loop())
        logging.getLogger(__name__).info('VAPT-X database initialization completed')
        yield
    finally:
        if webhook_worker:
            webhook_worker.cancel()
            await asyncio.gather(webhook_worker,return_exceptions=True)
        client.close()


app = FastAPI(title='VAPT-X API', version='1.0.0', lifespan=lifespan)
origin = settings.frontend_origin
app.add_middleware(CORSMiddleware, allow_credentials=True, allow_origins=[origin], allow_methods=['GET', 'POST', 'PATCH', 'PUT', 'DELETE'], allow_headers=['Content-Type', 'X-CSRF-Token', 'X-Org-Id'])


@app.middleware('http')
async def request_security(request: Request, call_next):
    bearer=bool(request.headers.get('authorization'))
    if bearer:
        try:
            await get_current_user(request)
        except HTTPException as exc:
            return JSONResponse({'detail':exc.detail},status_code=exc.status_code)
        # API tokens never enter account/session/organization administration or
        # mint credentials. New domain families must be explicitly enabled here.
        family=request.url.path.removeprefix('/api/').split('/')[0]
        if not request.url.path.startswith('/api/') or family not in {'workspace','capabilities','projects','project-templates','assets','assessments','scopes','scans','imports','inventory-imports','jobs','findings','tasks','evidence','reports','sla-policy','ai','analytics','audit-events'}:
            return JSONResponse({'detail':'API token is not permitted on this endpoint'},status_code=403)
    if not bearer and request.method in {'POST', 'PATCH', 'PUT', 'DELETE'}:

        if request.headers.get('origin') != origin:
            return JSONResponse({'detail': 'Untrusted request origin'}, status_code=403)
        if request.url.path not in {'/api/auth/login', '/api/auth/register', '/api/auth/recovery/request', '/api/auth/recovery/complete', '/api/auth/email-verification/confirm'}:
            csrf = request.cookies.get('csrf', '')
            if not csrf or not secrets.compare_digest(csrf, request.headers.get('x-csrf-token', '')):
                return JSONResponse({'detail': 'CSRF verification failed'}, status_code=403)
    response = await call_next(request)
    if not request.url.path.startswith('/api/lab/'):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Cache-Control'] = 'no-store'
    return response


app.add_middleware(RequestBodyLimitMiddleware)


@app.get('/api/live')
async def live():
    return {'status': 'ok', 'service': 'VAPT-X'}


@app.get('/api/health')
async def health():
    try:
        await db.command('ping')
    except PyMongoError:
        return JSONResponse({'status': 'unavailable', 'service': 'VAPT-X'}, status_code=503)
    return {'status': 'ok', 'service': 'VAPT-X'}


@app.get('/api/lab/target', response_class=HTMLResponse)
async def training_target():
    # Deliberately minimal, non-sensitive application-owned training response.
    return HTMLResponse('<html><body><h1>VAPT-X controlled training target</h1><p>No user data or external services. Headers intentionally omitted for safe-check verification.</p></body></html>', headers={'Set-Cookie': 'training_marker=non-sensitive; SameSite=Lax'})


@app.get('/api/lab/security.txt')
async def training_security_policy():
    return JSONResponse({'detail': 'No policy configured on training target'}, status_code=404)


for router in (auth_router, workflow_router, evidence_router, reporting_router, analyst_router):
    app.include_router(router)
app.include_router(intelligence_router)

app.include_router(inventory_router)

app.include_router(governance_router)

app.include_router(tokens_router)

app.include_router(webhooks_router)

app.include_router(analytics_router)

from mfa import router as mfa_router
app.include_router(mfa_router)

from account_admin import router as account_admin_router
app.include_router(account_admin_router)

from audit_navigation import router as audit_navigation_router
app.include_router(audit_navigation_router)

from register_navigation import router as register_navigation_router
app.include_router(register_navigation_router)

from account_recovery import router as account_recovery_router
app.include_router(account_recovery_router)

from account_verification import router as account_verification_router
app.include_router(account_verification_router)

from invitations import router as invitations_router
app.include_router(invitations_router)
