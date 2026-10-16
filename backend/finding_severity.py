"""Explicit analyst severity decisions preserve the original scanner assertion."""
from typing import Literal
from fastapi import APIRouter,Depends,HTTPException
from pydantic import BaseModel,Field,field_validator
from pymongo import ReturnDocument
from core import db,get_ctx,iso,audit,DomainDocument
from repository import Repository

router=APIRouter(prefix='/api')
class SeverityDecision(BaseModel):
    severity:Literal['critical','high','medium','low','info']|None
    reason:str=Field(min_length=5,max_length=2000)
    expected_version:int=Field(default=0,ge=0,le=2_147_483_647)
    @field_validator('reason')
    @classmethod
    def meaningful(cls,value):
        if len(value.strip())<5:raise ValueError('A meaningful severity decision reason is required')
        return value.strip()


@router.post('/findings/{finding_id}/severity')
async def decide_severity(finding_id:str,body:SeverityDecision,ctx=Depends(get_ctx)):
    ctx.require('triage')
    repo=Repository(ctx)
    finding=await repo.get('findings',finding_id)
    version=finding.get('severity_version',0)
    if version!=body.expected_version:raise HTTPException(409,'Severity changed. Reload the finding before saving.')
    scanner=finding.get('scanner_severity',finding['severity'])
    if scanner not in {'critical','high','medium','low','info'}:raise HTTPException(409,'Original scanner severity is unavailable')
    stamp=iso()
    event={'previous_severity':finding['severity'],'severity':body.severity or scanner,
           'decision':'restore_scanner' if body.severity is None else 'override','reason':body.reason,
           'actor_id':ctx.uid,'actor_email':ctx.user.get('email',''),'created_at':stamp,'version':version+1}
    filters={'_id':finding_id,'severity':finding['severity']}
    if version==0:filters['$or']=[{'severity_version':{'$exists':False}},{'severity_version':0}]
    else:filters['severity_version']=version
    filters['scanner_severity']=finding['scanner_severity'] if 'scanner_severity' in finding else {'$exists':False}
    updated=await db.findings.find_one_and_update(repo.query(filters,collection='findings'),
        {'$set':{'severity':event['severity'],'scanner_severity':scanner,
                 'severity_override':None if body.severity is None else {key:event[key] for key in ('severity','reason','actor_id','actor_email','created_at')},
                 'updated_at':stamp},'$inc':{'severity_version':1,'severity_history_total':1},
         '$push':{'severity_history':{'$each':[event],'$slice':-100}}},return_document=ReturnDocument.AFTER)
    if not updated:raise HTTPException(409,'Severity changed. Reload the finding before saving.')
    await audit(ctx,'finding.severity_decision','findings',finding_id,
                {'previous_severity':event['previous_severity'],'severity':event['severity'],'decision':event['decision'],'version':version+1})
    return DomainDocument.from_mongo(updated).model_dump()


@router.get('/findings/{finding_id}/severity-history')
async def severity_history(finding_id:str,ctx=Depends(get_ctx)):
    ctx.require('read')
    finding=await Repository(ctx).get('findings',finding_id)
    events=finding.get('severity_history',[])
    total=finding.get('severity_history_total',len(events))
    return {'events':events,'total':total,'has_more':total>len(events),
            'notice':'Most recent 100 severity decisions. Original scanner severity and analyst decisions are separate.'}
