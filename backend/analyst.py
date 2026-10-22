import asyncio
from fastapi import APIRouter,Depends,HTTPException
from pydantic import BaseModel,Field
from pymongo import ReturnDocument
from core import get_ctx,audit,db,DomainDocument,iso
from repository import Repository
from ai_providers import answer,configuration,public_configuration,health,redact
from intelligence import cves_for,fresh

router=APIRouter(prefix='/api')
HEALTH_LOCK=asyncio.Lock()
HEALTH_LAST=0.0

class MessageInput(BaseModel):
    project_id:str
    session_id:str|None=None
    message:str=Field(min_length=1,max_length=4000)
    provider:str=Field(default='claude',max_length=30)
    model:str|None=Field(default=None,max_length=120)

@router.get('/ai/providers')
async def providers(ctx=Depends(get_ctx)):
    ctx.require('ai')
    return public_configuration()

@router.post('/ai/providers/{provider}/health')
async def provider_health(provider:str,ctx=Depends(get_ctx)):
    ctx.require('ai')
    global HEALTH_LAST
    async with HEALTH_LOCK:
        now=asyncio.get_running_loop().time()
        if now-HEALTH_LAST<5:raise HTTPException(429,'Wait five seconds before another health check')
        HEALTH_LAST=now
        try:return await health(provider)
        except Exception:raise HTTPException(502,'Provider health check failed; no project data was sent')

@router.get('/ai/sessions')
async def sessions(project_id:str,ctx=Depends(get_ctx)):
    ctx.require('ai');repo=Repository(ctx)
    await repo.get('projects',project_id)
    return await repo.list('ai_sessions',{'project_id':project_id,'created_by':ctx.uid},limit=30)

@router.post('/ai/messages')
async def message(body:MessageInput,ctx=Depends(get_ctx)):
    ctx.require('ai');repo=Repository(ctx)
    project=await repo.get('projects',body.project_id)
    try:config=configuration(body.provider)
    except ValueError:raise HTTPException(422,'Unknown AI provider')
    model=body.model or (config['models'][0] if config['models'] else '')
    if not config['available'] or model not in config['models']:raise HTTPException(503,'Selected AI provider/model is not configured')
    session=None
    if body.session_id:
        session=await repo.get('ai_sessions',body.session_id)
        if session['created_by']!=ctx.uid or session['project_id']!=body.project_id:raise HTTPException(404,'Conversation not found')
        if session.get('provider','claude')!=body.provider or session.get('model',model)!=model:
            raise HTTPException(409,'Start a new conversation to change provider or model')
    findings=await repo.list('findings',{'project_id':body.project_id},limit=30)
    fields=('id','title','severity','status','verification','description','remediation')
    context={'project':project['name'],'findings':[{key:str(f.get(key,''))[:800] for key in fields} for f in findings],
        'notice':'At most 30 recent findings; text is truncated. No raw evidence or comments sent. Secret redaction is heuristic; review sensitive data.'}
    cached={}
    for cve in list(dict.fromkeys(cve for finding in findings for cve in cves_for(finding)))[:10]:
        sources={}
        for source in ('epss','kev','nvd'):
            item=await db.vulnerability_intelligence.find_one({'_id':source+':'+cve})
            if item and item.get('facts'):
                facts=item['facts']
                sources[source]={'fetched_at':item.get('fetched_at'),'stale':not fresh(item),
                    'facts':{key:value for key,value in facts.items() if key in {'probability','percentile','listed','cvss','cwe_ids'}}}
        if sources:cached[cve]=sources
    context['cached_public_intelligence']=cached
    history=[{'role':row['role'],'content':row['content'][:2000]} for row in (session or {}).get('messages',[])[-12:]]
    try:result=await answer(body.provider,model,context,history,body.message)
    except Exception:raise HTTPException(502,'AI provider could not complete this request; no findings were changed')
    # Track provider-reported token counts separately; no fabricated cost estimates.
    await repo.add('ai_usage',{'project_id':body.project_id,'provider':body.provider,'model':model,'usage':result['usage']},log=False)
    new_messages=[{'role':'user','content':redact(body.message)},{'role':'assistant','content':result['text']}]
    if session is None:
        session=await repo.add('ai_sessions',{'project_id':body.project_id,'name':redact(body.message)[:70],
            'provider':body.provider,'model':model,'messages':new_messages,'message_count':2,'last_usage':result['usage']})
    else:
        expected=session.get('message_count',{'$exists':False})
        updated=await db.ai_sessions.find_one_and_update(repo.query({'_id':session['id'],'created_by':ctx.uid,'message_count':expected}),
            {'$set':{'messages':(session['messages']+new_messages)[-100:],'provider':body.provider,'model':model,
                'last_usage':result['usage'],'updated_at':iso(),**({'message_count':len(session['messages'])+2} if 'message_count' not in session else {})},**({'$inc':{'message_count':2}} if 'message_count' in session else {})},return_document=ReturnDocument.AFTER)
        if updated is None:raise HTTPException(409,'Conversation changed during generation. Reload it; the provider may have processed the request.')
        session=DomainDocument.from_mongo(updated).model_dump()
    await audit(ctx,'ai.interpretation','ai_sessions',session['id'],{'provider':body.provider,'model':model})
    return session
