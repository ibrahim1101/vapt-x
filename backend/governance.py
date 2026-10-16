"""Organization-scoped remediation policy and analyst discussion."""
from datetime import datetime,timedelta,timezone
from fastapi import APIRouter,Depends,HTTPException,Query
from pydantic import BaseModel,Field,field_validator
from core import db,get_ctx,iso,audit
from repository import Repository

router=APIRouter(prefix='/api')
DEFAULT_DAYS={'critical':1,'high':7,'medium':30,'low':90,'info':0}
class SLAPolicyInput(BaseModel):
    critical:int=Field(default=1,ge=0,le=365)
    high:int=Field(default=7,ge=0,le=365)
    medium:int=Field(default=30,ge=0,le=365)
    low:int=Field(default=90,ge=0,le=365)
    info:int=Field(default=0,ge=0,le=365)

async def sla_policy(ctx):
    doc=await db.sla_policies.find_one({'org_id':ctx.org_id})
    return {'days':{**DEFAULT_DAYS,**(doc or {}).get('days',{})},
        'updated_at':(doc or {}).get('updated_at'),'updated_by':(doc or {}).get('updated_by'),
        'notice':'Calendar-day deadlines for open/confirmed findings; 0 disables a severity. Policy changes recalculate existing deadlines.'}

def sla_state(finding,policy,now=None):
    days=policy['days'].get(finding.get('severity'),0)
    if not days:return {'applicable':False,'breached':False}
    try:
        created=datetime.fromisoformat(finding['created_at'])
        if created.tzinfo is None:raise ValueError('Missing timezone')
        due=created+timedelta(days=days)
    except (ValueError,TypeError,KeyError):return {'applicable':False,'breached':False,'error':'Creation date unavailable'}
    active=finding.get('status') in {'open','confirmed'}
    return {'applicable':active,'due_at':due.isoformat(),'days':days,
        'breached':active and (now or datetime.now(timezone.utc))>due}

@router.get('/sla-policy')
async def get_sla_policy(ctx=Depends(get_ctx)):
    ctx.require('read')
    return await sla_policy(ctx)

@router.put('/sla-policy')
async def update_sla_policy(body:SLAPolicyInput,ctx=Depends(get_ctx)):
    ctx.require('authorize')
    from project_access import require_all_projects
    require_all_projects(ctx)
    await db.sla_policies.update_one({'org_id':ctx.org_id},{'$set':{'days':body.model_dump(),
        'updated_at':iso(),'updated_by':ctx.uid}},upsert=True)
    await audit(ctx,'sla.policy_updated','sla_policies',ctx.org_id,{'days':body.model_dump()})
    return await sla_policy(ctx)

class CommentInput(BaseModel):
    text:str=Field(min_length=1,max_length=5000)
    @field_validator('text')
    @classmethod
    def meaningful(cls,value):
        if not value.strip():raise ValueError('Comment must not be empty')
        return value.strip()

@router.post('/findings/{finding_id}/comments')
async def add_comment(finding_id:str,body:CommentInput,ctx=Depends(get_ctx)):
    ctx.require('triage')
    repo=Repository(ctx)
    finding=await repo.get('findings',finding_id)
    return await repo.add('finding_comments',{'finding_id':finding_id,'project_id':finding['project_id'],
        'text':body.text,'actor_email':ctx.user.get('email')})

@router.get('/findings/{finding_id}/comments')
async def list_comments(finding_id:str,offset:int=Query(default=0,ge=0,le=1_000_000),
    limit:int=Query(default=25,ge=1,le=100),ctx=Depends(get_ctx)):
    ctx.require('read')
    repo=Repository(ctx)
    await repo.get('findings',finding_id)
    return await repo.page('finding_comments',{'finding_id':finding_id},offset=offset,limit=limit)
