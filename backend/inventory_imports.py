"""Bounded JSON inventory imports; specifications never become scan authority."""
import json
import re
from typing import Literal
from urllib.parse import urlsplit
from fastapi import APIRouter,Depends,HTTPException,Query
from pydantic import BaseModel,Field
from pymongo.errors import DuplicateKeyError,PyMongoError
from core import get_ctx,iso,sha256_hex
from repository import Repository
from scanners import target_host,validate_scope,JOB_LOCK
from importers import _object,_array,_required,_text,_json,MAX_REPORT_BYTES

router=APIRouter(prefix='/api')
FORMATS={'openapi','cyclonedx','spdx'}


def parse_inventory(format,content,host):
    if format not in FORMATS:raise ValueError('Unsupported inventory format')
    if len(content.encode('utf-8'))>MAX_REPORT_BYTES:raise ValueError('Maximum inventory size is 2 MB')
    data=_object(_json(content),'inventory document')
    rows=[]
    def append(row):
        if len(rows)>=2000:raise ValueError('Maximum 2,000 inventory items per import')
        for key,value in row.items():
            if not isinstance(value,str) or len(value)>2000:raise ValueError('Inventory fields must be text of at most 2,000 characters')
        identity={key:row.get(key,'') for key in (('kind','path','method') if row['kind']=='api_operation' else ('kind','name','version','purl'))}
        if row['kind']=='component' and not row.get('purl'):identity['format']=format
        row['fingerprint']=sha256_hex(json.dumps(identity,sort_keys=True).encode())
        rows.append(row)
    def servers(container):
        for server in _array(container.get('servers',[]),'OpenAPI servers'):
            url=_required(_object(server,'OpenAPI server').get('url'),'OpenAPI server URL')
            parsed=urlsplit(url)
            if parsed.scheme or parsed.netloc:
                absolute='https:'+url if not parsed.scheme else url
                if target_host(absolute)!=host:raise ValueError('OpenAPI server is outside the authorized exact host')
    if format=='openapi':
        version=data.get('openapi','')
        if not (isinstance(version,str) and version.startswith('3.')) and data.get('swagger')!='2.0':
            raise ValueError('Expected OpenAPI 3.x or Swagger 2.0 JSON')
        servers(data)
        if data.get('host') and target_host('https://'+_required(data['host'],'Swagger host'))!=host:
            raise ValueError('Swagger host is outside the authorized exact host')
        for path,item in _object(data.get('paths'),'OpenAPI paths').items():
            if not path.startswith('/') or len(path)>500:raise ValueError('Invalid OpenAPI path')
            item=_object(item,'OpenAPI path item');servers(item)
            for method,operation in item.items():
                if method not in {'get','put','post','delete','options','head','patch','trace'}:continue
                operation=_object(operation,'OpenAPI operation');servers(operation)
                append({'kind':'api_operation','name':_text(operation.get('summary'),'OpenAPI summary',method.upper()+' '+path),
                    'method':method.upper(),'path':path,'version':str(version or data['swagger']),
                    'source_id':_text(operation.get('operationId'),'OpenAPI operationId')})
    elif format=='cyclonedx':
        if data.get('bomFormat')!='CycloneDX' or not re.fullmatch(r'1\.[4-7]',str(data.get('specVersion',''))):
            raise ValueError('Expected CycloneDX 1.4–1.7 JSON')
        def components(values,depth=0):
            if depth>32:raise ValueError('Component nesting exceeds 32 levels')
            for item in _array(values,'CycloneDX components'):
                item=_object(item,'CycloneDX component')
                append({'kind':'component','name':(_text(item.get('group'),'component group')+'/' if item.get('group') else '')+_required(item.get('name'),'component name'),
                    'version':_text(item.get('version'),'component version'),
                    'purl':_text(item.get('purl'),'component purl'),
                    'source_id':_text(item.get('bom-ref'),'component reference')})
                components(item.get('components',[]),depth+1)
        components(data.get('components',[]))
    else:
        if not re.fullmatch(r'SPDX-2\.[23](?:\.\d+)?',str(data.get('spdxVersion',''))):
            raise ValueError('Expected SPDX 2.2/2.3 JSON')
        for item in _array(data.get('packages',[]),'SPDX packages'):
            item=_object(item,'SPDX package');purl=''
            for reference in _array(item.get('externalRefs',[]),'SPDX externalRefs'):
                reference=_object(reference,'SPDX external reference')
                if reference.get('referenceType')=='purl':purl=_required(reference.get('referenceLocator'),'SPDX purl')
            append({'kind':'component','name':_required(item.get('name'),'SPDX package name'),
                'version':_text(item.get('versionInfo'),'SPDX package version'),'purl':purl,
                'source_id':_required(item.get('SPDXID'),'SPDX package ID')})
    return rows


class InventoryImportInput(BaseModel):
    assessment_id:str
    asset_id:str
    format:Literal['openapi','cyclonedx','spdx']
    content:str=Field(min_length=2,max_length=2_000_000)


@router.post('/inventory-imports')
async def import_inventory(body:InventoryImportInput,ctx=Depends(get_ctx)):
    ctx.require('scan')
    repo=Repository(ctx)
    assessment=await repo.get('assessments',body.assessment_id)
    asset=await repo.get('assets',body.asset_id)
    await validate_scope(repo,assessment,asset,body.format)
    try:rows=parse_inventory(body.format,body.content,target_host(asset['target']))
    except (ValueError,RecursionError) as exc:raise HTTPException(422,str(exc)[:200])
    async with JOB_LOCK:
        assessment=await repo.get('assessments',body.assessment_id)
        await validate_scope(repo,assessment,asset,body.format)
        job=await repo.add('jobs',{'assessment_id':assessment['id'],'asset_id':asset['id'],
            'project_id':assessment['project_id'],'scanner':body.format,'source':'import','status':'running',
            'finding_count':0,'checks':[],'logs':['Inventory import only. No endpoints executed, external references fetched or vulnerabilities inferred.']})
        created=duplicate=0
        try:
            for row in rows:
                existing=await repo.list('inventory_items',{'asset_id':asset['id'],'fingerprint':row['fingerprint']},limit=1)
                if existing:duplicate+=1;continue
                try:
                    await repo.add('inventory_items',{**row,'asset_id':asset['id'],'project_id':assessment['project_id'],
                        'assessment_id':assessment['id'],'job_id':job['id'],'format':body.format,
                        'verification':'imported-inventory-unverified'},log=False)
                    created+=1
                except DuplicateKeyError:duplicate+=1
        except PyMongoError:
            await repo.update('jobs',job['id'],{'status':'failed','inventory_count':created,'duplicate_count':duplicate,
                'finished_at':iso(),'error':'Storage unavailable; partial inventory retained. Retry safely skips duplicates.'},log=False)
            raise HTTPException(503,'Inventory storage failed. Partial rows are retained; retry skips duplicates.')
        return await repo.update('jobs',job['id'],{'status':'completed','inventory_count':created,
            'duplicate_count':duplicate,'finished_at':iso()},log=False)


@router.get('/assets/{asset_id}/inventory')
async def asset_inventory(asset_id:str,offset:int=Query(default=0,ge=0,le=1_000_000),
    limit:int=Query(default=25,ge=1,le=100),ctx=Depends(get_ctx)):
    ctx.require('read')
    repo=Repository(ctx)
    await repo.get('assets',asset_id)
    result=await repo.page('inventory_items',{'asset_id':asset_id},offset=offset,limit=limit)
    result['notice']='Uploaded inventory assertions, not verified vulnerabilities. External references are never fetched.'
    return result
