"""Opt-in public vulnerability intelligence. Never mutates scanner observations.

Schemas: https://api.first.org/epss/ ; https://nvd.nist.gov/developers/vulnerabilities
https://github.com/cisagov/kev-data ; https://google.github.io/osv.dev/get-v1-vulns/
"""
import asyncio
import json
import math
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
import httpx
from fastapi import APIRouter, Depends, HTTPException
from core import db, get_ctx, iso, audit
from repository import Repository

router=APIRouter(prefix='/api')
CVE=re.compile(r'^CVE-\d{4}-\d{4,19}$')
SOURCES={'epss':'https://api.first.org/data/v1/epss',
    'kev':'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    'osv':'https://api.osv.dev/v1/vulns/',
    'nvd':'https://services.nvd.nist.gov/rest/json/cves/2.0'}
REFRESH_LOCK=asyncio.Lock()
LAST_REFRESH=0.0
NVD_LAST_CALL=0.0
TTL=timedelta(hours=6)


def cves_for(finding):
    declared=finding.get('cve_ids',[])
    if not isinstance(declared,list):declared=[]
    text=' '.join(str(finding.get(key,'')) for key in ('title','rule_id','description'))
    inferred=re.findall(r'\bCVE-\d{4}-\d{4,19}\b',text.upper())
    return sorted({value for value in [*declared,*inferred] if isinstance(value,str) and CVE.fullmatch(value)})[:20]


def safe_references(rows):
    urls=[]
    for row in rows[:100]:
        value=row.get('url') if isinstance(row,dict) else None
        if isinstance(value,str) and len(value)<=2000:
            parsed=urlsplit(value)
            if parsed.scheme in {'https','http'} and parsed.hostname and not parsed.username and not parsed.password:
                urls.append(value)
    return list(dict.fromkeys(urls))[:30]


def probability(value):
    number=float(value)
    if not math.isfinite(number) or not 0<=number<=1:
        raise ValueError('Invalid probability')
    return number


def normalize(source,payload,cve):
    if not isinstance(payload,dict): raise ValueError('Expected source object')
    if source=='epss':
        rows=payload.get('data')
        if not isinstance(rows,list):raise ValueError('Expected EPSS data array')
        rows=[row for row in rows if row.get('cve')==cve]
        if not rows:return None
        row=rows[0]
        return {'probability':probability(row['epss']),'percentile':probability(row['percentile']),'date':str(row.get('date',''))[:30]}
    if source=='kev':
        rows=payload.get('vulnerabilities')
        if not isinstance(rows,list):raise ValueError('Expected KEV catalog')
        row=next((row for row in rows if row.get('cveID')==cve),None)
        return {'listed':row is not None,'catalog_version':str(payload.get('catalogVersion',''))[:100],
            **({key:str(row.get(key,''))[:2000] for key in ('dateAdded','requiredAction','dueDate','knownRansomwareCampaignUse')} if row else {})}
    if source=='osv':
        if payload.get('id')!=cve and cve not in payload.get('aliases',[]):raise ValueError('OSV identifier mismatch')
        return {'id':payload['id'],'aliases':[str(v)[:100] for v in payload.get('aliases',[])[:30]],
            'summary':str(payload.get('summary',''))[:2000], 'modified':str(payload.get('modified',''))[:100],
            'references':safe_references(payload.get('references',[])),
            'notice':'Direct ID lookup; an absent record does not exclude OSV aliases or affected packages.'}
    records=payload.get('vulnerabilities')
    if not isinstance(records,list):raise ValueError('Expected NVD vulnerability array')
    record=next((row['cve'] for row in records if row.get('cve',{}).get('id')==cve),None)
    if not record:return None
    scores=[]
    for group in ('cvssMetricV31','cvssMetricV40'):
        for metric in record.get('metrics',{}).get(group,[])[:10]:
            data=metric.get('cvssData',{})
            score=float(data.get('baseScore',-1))
            version=data.get('version')
            vector=data.get('vectorString','')
            if math.isfinite(score) and 0<=score<=10 and version in {'3.1','4.0'} and isinstance(vector,str) and vector.startswith('CVSS:'+version+'/'):
                scores.append({'version':version,'base_score':score,'vector':vector[:500],
                    'source':str(metric.get('source',''))[:200],'type':str(metric.get('type',''))[:50]})
    cwes=sorted({d['value'] for row in record.get('weaknesses',[]) for d in row.get('description',[]) if re.fullmatch(r'CWE-\d{1,6}',str(d.get('value','')))})
    return {'cvss':scores,'cwe_ids':cwes[:30],'published':str(record.get('published',''))[:100],
        'modified':str(record.get('lastModified',''))[:100],'references':safe_references(record.get('references',[]))}


async def fetch_source(source,cve):
    global NVD_LAST_CALL
    if source=='nvd':
        now=time.monotonic()
        if now-NVD_LAST_CALL<7:raise ValueError('NVD request budget exhausted')
        NVD_LAST_CALL=now
    url=SOURCES[source]+cve if source=='osv' else SOURCES[source]
    params={'cve':cve} if source=='epss' else {'cveId':cve} if source=='nvd' else None
    # Fixed HTTPS destinations only; no user URL, redirect, proxy or credentials.
    async with httpx.AsyncClient(timeout=httpx.Timeout(15),follow_redirects=False,trust_env=False) as client:
        async with client.stream('GET',url,params=params,headers={'Accept':'application/json','User-Agent':'VAPT-X vulnerability intelligence'}) as response:
            if response.status_code==404 and source=='osv':return None
            response.raise_for_status()
            content=bytearray()
            async for chunk in response.aiter_bytes():
                content.extend(chunk)
                if len(content)>8_000_000:raise ValueError('Source response exceeds size limit')
    return json.loads(content)


def fresh(item):
    try:return datetime.now(timezone.utc)-datetime.fromisoformat(item['fetched_at'])<TTL
    except (KeyError,ValueError,TypeError):return False


def priority(sources):
    # Explicit derived heuristic, separate from source-provided facts.
    kev=sources.get('kev',{}).get('facts',{})
    epss=sources.get('epss',{}).get('facts',{})
    if kev.get('listed') is True:return {'level':'urgent','reason':'Listed in the cached CISA KEV catalog'}
    if epss.get('probability',0)>=0.1:return {'level':'high','reason':'EPSS probability meets the local 0.10 threshold'}
    return {'level':'unrated','reason':'Insufficient high-priority signals; this does not establish low risk'}


async def read_intelligence(cve):
    result={}
    for source in SOURCES:
        item=await db.vulnerability_intelligence.find_one({'_id':source+':'+cve})
        if item:
            item.pop('_id',None);item['stale']=not fresh(item);result[source]=item
        else:result[source]={'status':'unavailable','stale':True,'source_url':SOURCES[source]}
    return {'cve':cve,'sources':result,'derived_priority':priority(result),
        'notice':'Public source facts and a local derived heuristic. No finding or exploitability is confirmed. Refresh sends only this CVE identifier to fixed public providers.'}


async def checked_finding(finding_id,cve,ctx):
    if not CVE.fullmatch(cve):raise HTTPException(422,'Invalid CVE identifier')
    finding=await Repository(ctx).get('findings',finding_id)
    if cve not in cves_for(finding):raise HTTPException(422,'CVE is not associated with this scanner observation')
    return finding


@router.get('/findings/{finding_id}/intelligence/{cve}')
async def get_intelligence(finding_id:str,cve:str,ctx=Depends(get_ctx)):
    ctx.require('read')
    await checked_finding(finding_id,cve,ctx)
    return await read_intelligence(cve)


@router.post('/findings/{finding_id}/intelligence/{cve}/refresh')
async def refresh_intelligence(finding_id:str,cve:str,ctx=Depends(get_ctx)):
    ctx.require('triage')
    await checked_finding(finding_id,cve,ctx)
    global LAST_REFRESH
    async with REFRESH_LOCK:
        now=time.monotonic()
        # Global single-worker floor also respects NVD's unauthenticated budget.
        if now-LAST_REFRESH<7:raise HTTPException(429,'Intelligence refresh is limited to one request every seven seconds')
        LAST_REFRESH=now
        for source in SOURCES:
            key=source+':'+cve
            old=await db.vulnerability_intelligence.find_one({'_id':key})
            if old and fresh(old):continue
            try:
                # Cache the public KEV catalog separately to avoid refetching it per CVE.
                feed=await db.vulnerability_intelligence.find_one({'_id':'kev:catalog'}) if source=='kev' else None
                payload=feed['payload'] if feed and fresh(feed) else await asyncio.wait_for(fetch_source(source,cve),timeout=20)
                facts=normalize(source,payload,cve) if payload is not None else None
                fetched_at=feed['fetched_at'] if feed and fresh(feed) else iso()
                if source=='kev' and (not feed or not fresh(feed)):
                    await db.vulnerability_intelligence.update_one({'_id':'kev:catalog'},{'$set':{'payload':payload,'fetched_at':fetched_at}},upsert=True)
                await db.vulnerability_intelligence.update_one({'_id':key},{'$set':{
                    'source':source,'source_url':SOURCES[source],'status':'available' if facts is not None else 'not_found',
                    'facts':facts or {},'fetched_at':fetched_at,'last_error':None}},upsert=True)
            except (httpx.HTTPError,ValueError,TypeError,KeyError,AttributeError,RecursionError,asyncio.TimeoutError):
                # Preserve prior facts and their original timestamp on failure.
                await db.vulnerability_intelligence.update_one({'_id':key},{'$set':{
                    'source':source,'source_url':SOURCES[source],'last_error':'Source unavailable or invalid; cached facts retained',
                    'last_attempt_at':iso()},'$setOnInsert':{'status':'unavailable','facts':{}}},upsert=True)
    await audit(ctx,'intelligence.refreshed','findings',finding_id,{'cve':cve})
    return await read_intelligence(cve)
