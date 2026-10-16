"""Complete-collection operational counts; observations are not a security score."""
import asyncio
from fastapi import APIRouter, Depends
from core import db, get_ctx, iso
from repository import Repository

router = APIRouter(prefix='/api')
SEVERITIES = ('critical','high','medium','low','info')

@router.get('/analytics/summary')
async def summary(project_id: str | None = None, ctx=Depends(get_ctx)):
    ctx.require('read')
    repo = Repository(ctx)
    if project_id:
        await repo.get('projects', project_id)
    query = repo.query({'project_id':project_id} if project_id else {})
    # Bounded groups, rather than fetching documents or applying workspace row limits.
    async def groups(collection, field, known, extra=None):
        rows = await db[collection].aggregate([
            {'$match':{**query, **(extra or {})}},
            {'$group':{'_id':{'$cond':[{'$in':['$'+field,list(known)]},'$'+field,'unspecified']}, 'count':{'$sum':1}}},
        ], maxTimeMS=10000).to_list(100)
        return {row['_id']:row['count'] for row in rows}
    severities, jobs, verification, assets, projects, findings = await asyncio.gather(
        groups('findings','severity',SEVERITIES,{'status':{'$nin':['resolved','false_positive']}}),
        groups('jobs','status',('queued','running','completed','failed','interrupted','cancelled','cancelling')), groups('findings','verification',('observed','imported-unverified','analyst-confirmed')),
        db.assets.count_documents(query, maxTimeMS=10000),
        db.projects.count_documents(repo.query({'_id':project_id} if project_id else {},collection='projects'),maxTimeMS=10000),
        db.findings.count_documents(query,maxTimeMS=10000),
    )
    counts = {severity:severities.get(severity,0) for severity in SEVERITIES}
    return {'generated_at':iso(), 'project_id':project_id, 'complete_collection_counts':True,
        'assets':assets,'projects':projects,'findings':findings,
        'open_findings':sum(severities.values()), 'by_severity':counts,
        'unclassified_open':sum(value for key,value in severities.items() if key not in SEVERITIES),
        'critical_high':counts['critical']+counts['high'],
        'active_jobs':jobs.get('queued',0)+jobs.get('running',0), 'completed_jobs':jobs.get('completed',0),
        'by_verification':{str(key or 'unspecified'):value for key,value in verification.items()},
        'notice':'Counts cover stored records in projects accessible under your current membership at query time. Accepted-risk findings remain open. Imports and checks do not establish complete security coverage. Concurrent writes may occur between counts.'}
