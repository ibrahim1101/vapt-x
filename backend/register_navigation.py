"""Metadata-only navigation for private evidence, reports and scope authorizations."""
import re
from typing import Literal
from fastapi import APIRouter, Depends, Query
from core import get_ctx
from repository import Repository

router = APIRouter(prefix='/api')
FIELDS = {
    'evidence': ('project_id','finding_id','filename','size','content_type','status','sha256','created_at'),
    'reports': ('project_id','assessment_id','name','version','template','sha256','snapshot_sha256','finding_count','status','created_at'),
    'scopes': ('project_id','target','authorization_reference','starts_at','ends_at','authorized','allowed_scanners','created_at'),
}

async def metadata_page(collection, ctx, project_id, search, filters, offset, limit):
    ctx.require('read')
    repo = Repository(ctx)
    if project_id:
        await repo.get('projects', project_id)
        filters['project_id'] = project_id
    if search.strip():
        keys = {'evidence': ('filename','sha256','finding_id'), 'reports': ('name','assessment_id'),
                'scopes': ('target','authorization_reference')}[collection]
        filters['$or'] = [{key: {'$regex': re.escape(search.strip()), '$options': 'i'}} for key in keys]
    allowed = FIELDS[collection]
    result = await repo.page(collection, filters, offset=offset, limit=limit,
                             projection={key: 1 for key in (*allowed,'org_id','created_by')})
    result['items'] = [{'id': row['id'], **{key: row.get(key) for key in allowed}} for row in result['items']]
    return result

@router.get('/evidence')
async def evidence_page(project_id: str | None = None, search: str = Query(default='',max_length=120),
    status: Literal['uploading','ready'] | None = None, offset: int = Query(default=0,ge=0,le=1_000_000),
    limit: int = Query(default=25,ge=1,le=100), ctx=Depends(get_ctx)):
    return await metadata_page('evidence',ctx,project_id,search,{'status':status} if status else {},offset,limit)

@router.get('/reports')
async def reports_page(project_id: str | None = None, assessment_id: str | None = None, search: str = Query(default='',max_length=120),
    status: Literal['generating','ready'] | None = None, template: Literal['technical','executive','remediation'] | None = None,
    offset: int = Query(default=0,ge=0,le=1_000_000),limit: int = Query(default=25,ge=1,le=100),ctx=Depends(get_ctx)):
    filters = {}
    if assessment_id:
        ctx.require('read')
        await Repository(ctx).get('assessments',assessment_id)
        filters['assessment_id'] = assessment_id
    if status: filters['status'] = status
    if template: filters['template'] = template
    return await metadata_page('reports',ctx,project_id,search,filters,offset,limit)

@router.get('/scopes')
async def scopes_page(project_id: str | None = None, search: str = Query(default='',max_length=120),
    authorized: bool | None = None, offset: int = Query(default=0,ge=0,le=1_000_000),
    limit: int = Query(default=25,ge=1,le=100),ctx=Depends(get_ctx)):
    return await metadata_page('scopes',ctx,project_id,search,{'authorized':authorized} if authorized is not None else {},offset,limit)
