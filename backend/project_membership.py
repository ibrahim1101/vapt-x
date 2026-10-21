"""Administrator-controlled, live membership project grants."""
from typing import Literal,Annotated
from fastapi import APIRouter,Depends,HTTPException
from pydantic import BaseModel,Field,model_validator
from core import db,get_ctx,iso,audit
from auth import membership_lock
from project_access import metadata

router=APIRouter(prefix='/api')
class ProjectAccessInput(BaseModel):
    expected_version:int=Field(default=0,ge=0,le=2_147_483_647)
    mode:Literal['all','selected']
    project_ids:list[Annotated[str,Field(min_length=1,max_length=100)]]=Field(default_factory=list,max_length=500)
    @model_validator(mode='after')
    def normalize(self):
        if self.mode=='all' and self.project_ids:raise ValueError('All-project access must not include a selection')
        self.project_ids=sorted(set(self.project_ids))
        return self

async def current_admin(ctx):
    ctx.require('members')
    if ctx.scopes is not None:raise HTTPException(403,'Use a browser session to manage project access')
    actor=await db.memberships.find_one({'org_id':ctx.org_id,'user_id':ctx.uid,'role':'org_admin'})
    user=await db.users.find_one({'_id':ctx.uid,'disabled':{'$ne':True}})
    if not actor or not user or user.get('credential_version',0)!=ctx.user.get('credential_version',0) or (ctx.membership_id and str(actor['_id'])!=ctx.membership_id):
        raise HTTPException(403,'Administrator authority changed; reload before continuing')

@router.post('/members/{user_id}/project-access')
async def set_project_access(user_id:str,body:ProjectAccessInput,ctx=Depends(get_ctx)):
    async with membership_lock(ctx.org_id):
        await current_admin(ctx)
        target=await db.memberships.find_one({'org_id':ctx.org_id,'user_id':user_id})
        if not target:raise HTTPException(404,'Organization membership not found')
        if target['role']=='org_admin' and body.mode!='all':raise HTTPException(409,'Organization administrators retain all-project access')
        if target.get('project_access_version',0)!=body.expected_version:raise HTTPException(409,'Project access changed; reload the member before saving')
        if body.project_ids:
            count=await db.projects.count_documents({'org_id':ctx.org_id,'_id':{'$in':body.project_ids}})
            if count!=len(body.project_ids):raise HTTPException(404,'A selected project is unavailable in this organization')
        value=body.model_dump(exclude={'expected_version'})
        version={'project_access_version':body.expected_version} if body.expected_version else {'$or':[{'project_access_version':0},{'project_access_version':{'$exists':False}}]}
        expected=target.get('project_access',{'$exists':False})
        result=await db.memberships.update_one({'_id':target['_id'],'org_id':ctx.org_id,'user_id':user_id,
            'role':target['role'],'project_access':expected,**version},{'$set':{'project_access':value,'project_access_updated_at':iso()},'$inc':{'project_access_version':1}})
        if result.matched_count!=1:raise HTTPException(409,'Membership changed; reload before continuing')
        await audit(ctx,'membership.project_access_changed','users',user_id,{'mode':body.mode,'project_count':len(body.project_ids)})
    return {'project_access':metadata({**target,'project_access':value,'project_access_version':body.expected_version+1}),
        'notice':'Applies on subsequent requests, including existing API tokens. Queued scans recheck access before execution; in-flight requests/checks may finish.'}
