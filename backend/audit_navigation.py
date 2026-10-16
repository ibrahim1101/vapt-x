"""Organization-wide audit navigation; application events are not a tamper-proof ledger."""
import re
from datetime import date, datetime, timedelta, timezone
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Query
from core import get_ctx
from repository import Repository
router=APIRouter(prefix='/api')

@router.get('/audit-events')
async def list_events(search:str=Query(default='',max_length=120),action:str=Query(default='',max_length=120),
    actor:str=Query(default='',max_length=254),resource_type:str=Query(default='',max_length=100),
    outcome:Literal['allow','deny']|None=None,from_date:date|None=None,to_date:date|None=None,
    offset:int=Query(default=0,ge=0,le=1_000_000),limit:int=Query(default=25,ge=1,le=100),ctx=Depends(get_ctx)):
    # Preserve the existing workspace-audit visibility for organization readers.
    ctx.require('read')
    if from_date and to_date and from_date>to_date:raise HTTPException(422,'Start date must not follow end date')
    if to_date==date.max:raise HTTPException(422,'End date is outside the supported range')
    query={}
    if search.strip():query['$or']=[{key:{'$regex':re.escape(search.strip()),'$options':'i'}} for key in ('action','actor_email','actor_id','resource_type','resource_id')]
    if action.strip():query['action']=action.strip()
    if actor.strip():query['actor_email']={'$regex':re.escape(actor.strip()),'$options':'i'}
    if resource_type.strip():query['resource_type']=resource_type.strip()
    if outcome:query['outcome']=outcome
    def midnight(value):return datetime(value.year,value.month,value.day,tzinfo=timezone.utc).isoformat()
    if from_date or to_date:
        query['created_at']={}
        if from_date:query['created_at']['$gte']=midnight(from_date)
        if to_date:query['created_at']['$lt']=midnight(to_date+timedelta(days=1))
    page=await Repository(ctx).page('audit_events',query,offset=offset,limit=limit)
    allowed=('id','action','actor_id','actor_email','api_token_id','resource_type','resource_id','outcome','created_at','details')
    page['items']=[{key:row.get(key) for key in allowed} for row in page['items']]
    return {**page,'notice':'Organization-wide events; the project selector does not narrow this trail. Dates use UTC and include the end date. No application edit/delete controls; records are not a tamper-proof external ledger.'}
