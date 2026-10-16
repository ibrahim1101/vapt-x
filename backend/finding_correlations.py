"""Read-only, explainable cross-scanner candidates; observations stay independent."""
import re
from fastapi import APIRouter,Depends,Query
from core import get_ctx
from repository import Repository

router=APIRouter(prefix='/api')
NOTICE='Candidates share a normalized CVE and the same stored asset/project, from a different scanner. This does not establish equivalence, exploitability or remediation. Historical assessments and analyst statuses remain independent.'


def declared_cves(row):
    values=row.get('cve_ids',[])
    if not isinstance(values,list):return []
    return sorted({v for v in values if isinstance(v,str) and re.fullmatch(r'CVE-\d{4}-\d{4,19}',v)})[:20]


@router.get('/findings/{finding_id}/correlations')
async def correlations(finding_id:str,search:str=Query(default='',max_length=120),
                       offset:int=Query(default=0,ge=0,le=1_000_000),limit:int=Query(default=25,ge=1,le=100),ctx=Depends(get_ctx)):
    ctx.require('read')
    repo=Repository(ctx)
    source=await repo.get('findings',finding_id)
    cves=declared_cves(source)
    if not cves or not source.get('asset_id') or not source.get('project_id') or not source.get('scanner'):
        return {'items':[],'total':0,'offset':offset,'limit':limit,'has_more':False,'notice':NOTICE}
    filters={'project_id':source['project_id'],'asset_id':source['asset_id'],
             'cve_ids':{'$in':cves},'scanner':{'$ne':source['scanner']},'_id':{'$ne':source['id']}}
    if search.strip():
        filters['$or']=[{field:{'$regex':re.escape(search.strip()),'$options':'i'}} for field in ('title','scanner','assessment_id')]
    fields=('_id','org_id','created_by','created_at','project_id','asset_id','assessment_id','title','severity','status','verification','source','scanner','target','cve_ids')
    page=await repo.page('findings',filters,offset,limit,projection={field:1 for field in fields})
    for row in page['items']:
        row['common_cve_ids']=sorted(set(cves)&set(declared_cves(row)))
    return {**page,'notice':NOTICE}
