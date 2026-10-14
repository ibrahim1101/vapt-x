import os
import secrets
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, HTMLResponse
from starlette.middleware.cors import CORSMiddleware
from core import db, client, iso
from auth import router as auth_router, seed_admin
from workflow import router as workflow_router
from evidence import router as evidence_router
from reporting import router as reporting_router
from analyst import router as analyst_router


@asynccontextmanager
async def lifespan(app):
    await seed_admin()
    for collection in ('projects', 'scopes', 'assets', 'assessments', 'jobs', 'findings', 'tasks', 'evidence', 'evidence_chunks', 'reports', 'report_files', 'audit_events', 'ai_sessions'):
        await db[collection].create_index([('org_id', 1), ('created_at', -1)])
    await db.evidence_chunks.create_index([('org_id', 1), ('evidence_id', 1), ('index', 1)], unique=True)
    await db.jobs.update_many({'status': {'$in': ['queued', 'running']}}, {'$set': {'status': 'interrupted', 'error': 'Worker restarted before completion; run again.', 'finished_at': iso()}})
    yield
    client.close()


app = FastAPI(title='VAPT-X API', version='1.0.0', lifespan=lifespan)
origin = os.environ['FRONTEND_URL'].rstrip('/')
app.add_middleware(CORSMiddleware, allow_credentials=True, allow_origins=[origin], allow_methods=['GET', 'POST', 'PATCH', 'PUT', 'DELETE'], allow_headers=['Content-Type', 'X-CSRF-Token', 'X-Org-Id'])


@app.middleware('http')
async def request_security(request: Request, call_next):
    if request.method in {'POST', 'PATCH', 'PUT', 'DELETE'}:
        if request.headers.get('origin') != origin:
            return JSONResponse({'detail': 'Untrusted request origin'}, status_code=403)
        if request.url.path not in {'/api/auth/login', '/api/auth/register'}:
            csrf = request.cookies.get('csrf', '')
            if not csrf or not secrets.compare_digest(csrf, request.headers.get('x-csrf-token', '')):
                return JSONResponse({'detail': 'CSRF verification failed'}, status_code=403)
        if int(request.headers.get('content-length', '0')) > 3_000_000:
            return JSONResponse({'detail': 'Request too large; use chunked evidence upload'}, status_code=413)
    response = await call_next(request)
    if not request.url.path.startswith('/api/lab/'):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Cache-Control'] = 'no-store'
    return response


@app.get('/api/health')
async def health():
    await db.command('ping')
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