"""One-time, hash-only organization API tokens; browser sessions manage tokens."""
import asyncio
import secrets
from datetime import datetime,timedelta,timezone
from typing import Literal
from fastapi import APIRouter,Depends,HTTPException
from pydantic import BaseModel,Field,field_validator
from core import get_ctx,db,iso,sha256_hex,audit,DomainDocument
from pymongo import ReturnDocument
from repository import Repository

router=APIRouter(prefix='/api')
TOKEN_LOCK=asyncio.Lock()
SCOPES=Literal['read','write','scan','triage','remediate','report','evidence','ai']
class TokenInput(BaseModel):
    name:str=Field(min_length=2,max_length=100)
    scopes:list[SCOPES]=Field(min_length=1,max_length=8)
    expires_days:int=Field(default=30,ge=1,le=90)
    @field_validator('name')
    @classmethod
    def meaningful(cls,value):
        if len(value.strip())<2:raise ValueError('Provide a meaningful token name')
        return value.strip()

def metadata(row):
    return {key:row.get(key) for key in ('id','name','scopes','token_prefix','created_at','expires_at','revoked','revoked_at')}

def browser_only(ctx):
    if ctx.user.get('_token_scopes') is not None:raise HTTPException(403,'Use a browser session to manage API tokens')

@router.post('/api-tokens')
async def create_token(body:TokenInput,ctx=Depends(get_ctx)):
    browser_only(ctx);ctx.require('read')
    scopes=list(dict.fromkeys(body.scopes))
    if any(not ctx.can(scope) for scope in scopes):raise HTTPException(403,'Cannot grant permissions your current role does not have')
    async with TOKEN_LOCK:
        count=await db.api_tokens.count_documents({'org_id':ctx.org_id,'created_by':ctx.uid,'revoked':False,'expires_at':{'$gt':iso()}})
        if count>=100:raise HTTPException(409,'Revoke an existing token before creating another (maximum 100 active)')
        token='vaptx_'+secrets.token_urlsafe(32)
        row=await Repository(ctx).add('api_tokens',{'name':body.name,'scopes':scopes,'credential_version':ctx.user.get('credential_version',0),'membership_id':ctx.membership_id,'token_hash':sha256_hex(token.encode()),
            'token_prefix':token[:12],'expires_at':(datetime.now(timezone.utc)+timedelta(days=body.expires_days)).isoformat(),'revoked':False})
    return {**metadata(row),'token':token,'notice':'Shown once. Store securely; only its hash is retained. Scope is fixed to this organization and current owner permissions.'}

@router.get('/api-tokens')
async def list_tokens(ctx=Depends(get_ctx)):
    browser_only(ctx);ctx.require('read')
    rows=await Repository(ctx).list('api_tokens',{'created_by':ctx.uid,'revoked':False,'expires_at':{'$gt':iso()}},limit=101)
    return {'tokens':[metadata(row) for row in rows[:100]],'has_more':len(rows)>100}

@router.post('/api-tokens/{token_id}/revoke')
async def revoke_token(token_id:str,ctx=Depends(get_ctx)):
    browser_only(ctx);ctx.require('read')
    repo=Repository(ctx)
    row=await repo.get('api_tokens',token_id)
    if row['created_by']!=ctx.uid:raise HTTPException(404,'Token not found')
    if not row.get('revoked'):
        updated=await db.api_tokens.find_one_and_update(repo.query({'_id':token_id,'created_by':ctx.uid,'revoked':False}),
            {'$set':{'revoked':True,'revoked_at':iso()}},return_document=ReturnDocument.AFTER)
        if updated:
            row=DomainDocument.from_mongo(updated).model_dump()
            await audit(ctx,'api_token.revoked','api_tokens',token_id)
        else:row=await repo.get('api_tokens',token_id)
    return metadata(row)
