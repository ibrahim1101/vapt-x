"""Encrypted, opt-in HTTPS webhooks with a durable single-worker outbox."""
import asyncio
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from datetime import datetime,timedelta,timezone
from typing import Literal
from urllib.parse import urlsplit
from cryptography.fernet import Fernet,MultiFernet
import httpx
from fastapi import APIRouter,Depends,HTTPException,Query
from pydantic import BaseModel,Field
from pymongo import ReturnDocument
from core import db,get_ctx,iso,audit,DomainDocument
from repository import Repository
from scanners import resolve_public

router=APIRouter(prefix='/api')
EVENTS={'finding.triaged','scan.completed','reports.created','assessment.cancelled'}
Event=Literal['finding.triaged','scan.completed','reports.created','assessment.cancelled']
OUTBOX_LOCK=asyncio.Lock()

def cipher():
    keys=[key.strip() for key in os.environ.get('WEBHOOK_ENCRYPTION_KEYS','').split(',') if key.strip()]
    if not keys:raise ValueError('Webhook encryption is not configured')
    return MultiFernet([Fernet(key.encode()) for key in keys])

def configured():
    try:cipher();return True
    except (ValueError,TypeError):return False

def validate_url(url):
    if any(ord(c)<32 or ord(c)==127 for c in url):raise ValueError('Control characters are not allowed')
    parsed=urlsplit(url)
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.port not in {None,443}:
        raise ValueError('Use HTTPS on port 443 without credentials, query or fragment')
    return parsed

async def destination(url):
    parsed=validate_url(url)
    ip=await asyncio.wait_for(resolve_public(parsed.hostname),timeout=5)
    return parsed,ip

def public(hook):
    return {key:hook.get(key) for key in ('id','name','destination_origin','events','enabled','created_at','dropped_events')}

def sign(secret,body,timestamp):
    return 'sha256='+hmac.new(secret.encode(),timestamp.encode()+b'.'+body,hashlib.sha256).hexdigest()

class HookInput(BaseModel):
    name:str=Field(min_length=2,max_length=100)
    url:str=Field(min_length=10,max_length=1500)
    events:list[Event]=Field(min_length=1,max_length=4)
    enabled:bool=False
class HookUpdate(BaseModel):
    name:str|None=Field(default=None,min_length=2,max_length=100)
    events:list[Event]|None=Field(default=None,min_length=1,max_length=4)
    enabled:bool|None=None

@router.get('/webhooks')
async def list_hooks(ctx=Depends(get_ctx)):
    ctx.require('integrations')
    rows=await Repository(ctx).list('webhooks',{'deleted':False},limit=21)
    return {'configured':configured(),'events':sorted(EVENTS),'hooks':[public(row) for row in rows[:20]],'has_more':len(rows)>20}

@router.post('/webhooks')
async def create_hook(body:HookInput,ctx=Depends(get_ctx)):
    ctx.require('integrations')
    if not configured():raise HTTPException(503,'Operator must configure WEBHOOK_ENCRYPTION_KEYS before enabling integrations')
    try:parsed,_=await destination(body.url)
    except (ValueError,OSError,asyncio.TimeoutError):raise HTTPException(422,'Destination must resolve exclusively to public addresses and use HTTPS port 443')
    repo=Repository(ctx)
    async with OUTBOX_LOCK:
        if len(await repo.list('webhooks',{'deleted':False},limit=20))>=20:raise HTTPException(409,'Maximum 20 webhook configurations per organization')
        secret=secrets.token_urlsafe(32)
        encrypted=cipher().encrypt(json.dumps({'url':body.url,'secret':secret}).encode()).decode()
        row=await repo.add('webhooks',{'name':body.name,'destination_origin':'https://'+parsed.netloc,
            'encrypted_configuration':encrypted,'events':list(dict.fromkeys(body.events)),'enabled':body.enabled,'deleted':False,'dropped_events':0})
    return {**public(row),'signing_secret':secret,'notice':'Signing secret shown once. Verify HMAC-SHA256(timestamp + dot + raw body), enforce timestamp freshness, and deduplicate delivery IDs.'}

@router.patch('/webhooks/{hook_id}')
async def update_hook(hook_id:str,body:HookUpdate,ctx=Depends(get_ctx)):
    ctx.require('integrations');repo=Repository(ctx)
    fields=body.model_dump(exclude_unset=True)
    if not fields or any(value is None for value in fields.values()):raise HTTPException(422,'Provide non-null configuration fields')
    hook=await repo.get('webhooks',hook_id)
    if hook.get('deleted'):raise HTTPException(404,'Webhook not found')
    if fields.get('enabled') and not configured():raise HTTPException(503,'Webhook encryption key is unavailable')
    if 'events' in fields:fields['events']=list(dict.fromkeys(fields['events']))
    row=await repo.update('webhooks',hook_id,fields)
    if fields.get('enabled') is False:
        await db.webhook_deliveries.update_many(repo.query({'webhook_id':hook_id,'status':'queued'}),{'$set':{'status':'cancelled','finished_at':iso()}})
    return public(row)

async def enqueue(hook,event,event_id,metadata):
    async with OUTBOX_LOCK:
        pending=await db.webhook_deliveries.count_documents({'org_id':hook['org_id'],'status':{'$in':['queued','running']}})
        if pending>=1000:
            await db.webhooks.update_one({'_id':hook['id'],'org_id':hook['org_id']},{'$inc':{'dropped_events':1}})
            return None
        delivery_id=str(uuid.uuid4())
        payload={'schema_version':1,'delivery_id':delivery_id,'event':event,'event_id':event_id,
            'org_id':hook['org_id'],'occurred_at':metadata.get('created_at',iso()),
            'resource_type':metadata.get('resource_type',''),'resource_id':metadata.get('resource_id','')}
        row=DomainDocument(id=delivery_id,org_id=hook['org_id'],created_by='system',webhook_id=hook['id'],
            event=event,event_id=event_id,payload=payload,status='queued',attempts=0,cycle_attempts=0,next_attempt_at=iso())
        await db.webhook_deliveries.insert_one(row.to_mongo())
        return row.model_dump()

async def dispatch_event(org_id,event,payload):
    if not configured() or event not in EVENTS:return
    docs=await db.webhooks.find({'org_id':org_id,'enabled':True,'deleted':False,'events':event}).limit(20).to_list(20)
    for doc in docs:
        hook=DomainDocument.from_mongo(doc).model_dump()
        await enqueue(hook,event,payload.get('id',str(uuid.uuid4())),payload)

@router.post('/webhooks/{hook_id}/test')
async def test_hook(hook_id:str,ctx=Depends(get_ctx)):
    ctx.require('integrations')
    hook=await Repository(ctx).get('webhooks',hook_id)
    if not configured() or not hook.get('enabled') or hook.get('deleted'):raise HTTPException(409,'Enable a configured webhook before requesting a test delivery')
    result=await enqueue(hook,'integration.test',str(uuid.uuid4()),{'resource_type':'webhooks','resource_id':hook_id})
    if result is None:raise HTTPException(429,'Organization delivery queue is full')
    return result

@router.get('/webhooks/{hook_id}/deliveries')
async def delivery_history(hook_id:str,offset:int=Query(default=0,ge=0,le=1_000_000),limit:int=Query(default=25,ge=1,le=100),ctx=Depends(get_ctx)):
    ctx.require('integrations');repo=Repository(ctx)
    await repo.get('webhooks',hook_id)
    return await repo.page('webhook_deliveries',{'webhook_id':hook_id},offset=offset,limit=limit)

@router.post('/webhooks/{hook_id}/deliveries/{delivery_id}/retry')
async def retry_delivery(hook_id:str,delivery_id:str,ctx=Depends(get_ctx)):
    ctx.require('integrations');repo=Repository(ctx)
    hook=await repo.get('webhooks',hook_id)
    if not configured() or not hook.get('enabled') or hook.get('deleted'):raise HTTPException(409,'Enable the webhook before retrying')
    async with OUTBOX_LOCK:
        pending=await db.webhook_deliveries.count_documents(repo.query({'status':{'$in':['queued','running']}}))
        if pending>=1000:raise HTTPException(429,'Organization delivery queue is full')
        result=await db.webhook_deliveries.find_one_and_update(repo.query({'_id':delivery_id,'webhook_id':hook_id,'status':'failed'}),
            {'$set':{'status':'queued','cycle_attempts':0,'next_attempt_at':iso(),'last_error':None}},return_document=ReturnDocument.AFTER)
        if result is None:raise HTTPException(409,'Delivery is not failed in this webhook')
    await audit(ctx,'webhook.delivery_retried','webhook_deliveries',delivery_id)
    return DomainDocument.from_mongo(result).model_dump()


async def send(hook,delivery):
    config=json.loads(cipher().decrypt(hook['encrypted_configuration'].encode()))
    parsed,ip=await destination(config['url'])
    address='['+ip+']' if ':' in ip else ip
    url='https://'+address+':443'+(parsed.path or '/')
    body=json.dumps(delivery['payload'],sort_keys=True,separators=(',',':')).encode()
    timestamp=str(int(time.time()))
    headers={'Host':parsed.netloc,'Content-Type':'application/json','X-VAPTX-Event':delivery['event'],
        'X-VAPTX-Delivery':str(delivery['_id']),'X-VAPTX-Timestamp':timestamp,'X-VAPTX-Signature':sign(config['secret'],body,timestamp)}
    async with httpx.AsyncClient(timeout=10,follow_redirects=False,trust_env=False) as client:
        async with client.stream('POST',url,content=body,headers=headers,extensions={'sni_hostname':parsed.hostname}) as response:
            if not 200<=response.status_code<300:raise ValueError('Destination returned non-success status')
            return response.status_code

async def deliver_one():
    now=iso()
    delivery=await db.webhook_deliveries.find_one_and_update({'$or':[{'status':'queued','next_attempt_at':{'$lte':now}},
        {'status':'running','lease_expires_at':{'$lte':now}}]},
        {'$set':{'status':'running','lease_expires_at':(datetime.now(timezone.utc)+timedelta(seconds=60)).isoformat(),'lease_id':str(uuid.uuid4())},'$inc':{'attempts':1,'cycle_attempts':1}},
        sort=[('created_at',1)],return_document=ReturnDocument.AFTER)
    if not delivery:return False
    hook=await db.webhooks.find_one({'_id':delivery['webhook_id'],'org_id':delivery['org_id'],'enabled':True,'deleted':False})
    query={'_id':delivery['_id'],'org_id':delivery['org_id'],'lease_id':delivery['lease_id']}
    if delivery['cycle_attempts']>5:
        await db.webhook_deliveries.update_one(query,{'$set':{'status':'failed','finished_at':iso(),'last_error':'Retry budget exhausted after interrupted attempts'}})
        return True
    if not hook:
        await db.webhook_deliveries.update_one(query,{'$set':{'status':'cancelled','finished_at':iso()}});return True
    try:
        code=await asyncio.wait_for(send(hook,delivery),timeout=20)
        update={'status':'delivered','response_code':code,'finished_at':iso(),'last_error':None}
    except Exception:
        terminal=delivery['cycle_attempts']>=5
        update={'status':'failed' if terminal else 'queued','last_error':'Destination unavailable, invalid, or returned a non-success status'}
        if terminal:update['finished_at']=iso()
        else:update['next_attempt_at']=(datetime.now(timezone.utc)+timedelta(seconds=5*2**delivery['cycle_attempts'])).isoformat()
    await db.webhook_deliveries.update_one(query,{'$set':update})
    return True

async def delivery_loop():
    while True:
        try:
            if not await deliver_one():await asyncio.sleep(1)
        except asyncio.CancelledError:raise
        except Exception:
            # Preserve queued/leased state for recovery; never log destination secrets.
            await asyncio.sleep(1)
