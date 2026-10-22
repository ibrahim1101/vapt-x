"""Platform-owner account lifecycle. Organization roles confer no platform access."""
import re
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field, StrictBool, field_validator
from pymongo import ReturnDocument
from core import db, get_current_user, iso
from mfa import Reauthenticate, reauthenticate, version_query
from auth import account_event

router=APIRouter(prefix='/api/platform/accounts')

def require_owner(user):
    if user.get('_token_scopes') is not None or user.get('platform_role')!='platform_admin':
        raise HTTPException(403,'Platform-owner browser session required')

def public_account(document):
    return {'id':str(document['_id']),**{key:document.get(key) for key in ('email','name','platform_role','created_at','state_changed_at','state_changed_by','state_change_reason')},
        'disabled':bool(document.get('disabled'))}

class AccountState(Reauthenticate):
    disabled:StrictBool
    expected_disabled:StrictBool
    reason:str=Field(min_length=5,max_length=500)
    @field_validator('reason')
    @classmethod
    def meaningful(cls,value):
        if len(value.strip())<5:raise ValueError('Provide a reason of at least five characters')
        return value.strip()

@router.get('')
async def list_accounts(search:str=Query(default='',max_length=120),status:Literal['active','disabled']|None=None,
    offset:int=Query(default=0,ge=0,le=1_000_000),limit:int=Query(default=25,ge=1,le=100),user=Depends(get_current_user)):
    require_owner(user)
    query={}
    if status:query['disabled']=True if status=='disabled' else {'$ne':True}
    if search.strip():query['$or']=[{key:{'$regex':re.escape(search.strip()),'$options':'i'}} for key in ('email','name')]
    total=await db.users.count_documents(query)
    projection={key:1 for key in ('email','name','platform_role','created_at','disabled','state_changed_at','state_changed_by','state_change_reason')}
    rows=await db.users.find(query,projection).sort([('created_at',-1),('_id',-1)]).skip(offset).limit(limit).to_list(limit)
    return {'items':[public_account(row) for row in rows],'total':total,'offset':offset,'limit':limit,'has_more':offset+len(rows)<total}

@router.post('/{user_id}/state')
async def change_state(user_id:str,body:AccountState,user=Depends(get_current_user)):
    require_owner(user)
    if user_id==user['id']:raise HTTPException(409,'You cannot disable or reactivate your own account here')
    if body.disabled==body.expected_disabled:raise HTTPException(422,'Choose a different account state')
    operator=await reauthenticate(body,user,require_mfa=bool(user.get('mfa_enabled')))
    # Recheck the platform role on the credential record used for step-up.
    if operator.get('platform_role')!='platform_admin':raise HTTPException(403,'Platform-owner permission is unavailable')
    target=await db.users.find_one({'_id':user_id})
    if not target:raise HTTPException(404,'Account not found')
    if target.get('platform_role')=='platform_admin':raise HTTPException(409,'Platform-owner accounts are protected from this operation')
    if bool(target.get('disabled'))!=body.expected_disabled:raise HTTPException(409,'Account state changed; reload before trying again')
    changed=await db.users.find_one_and_update({'_id':user_id,'platform_role':{'$ne':'platform_admin'},
        'disabled':True if body.expected_disabled else {'$ne':True},**version_query(target)},
        {'$set':{'disabled':body.disabled,'state_changed_at':iso(),'state_changed_by':user['id'],'state_change_reason':body.reason},
         '$unset':{'mfa_pending':''},'$inc':{'credential_version':1}},return_document=ReturnDocument.AFTER)
    if not changed:raise HTTPException(409,'Account changed; reload before trying again')
    # The epoch and disabled checks take effect even if a stale request inserts later.
    old_versions={'$or':[{'credential_version':{'$exists':False}},{'credential_version':{'$lt':changed['credential_version']}}]}
    await db.sessions.update_many({'user_id':user_id,'revoked':False,**old_versions},{'$set':{'revoked':True}})
    await db.api_tokens.update_many({'created_by':user_id,'revoked':False,**old_versions},{'$set':{'revoked':True,'revoked_at':iso()}})
    await db.mfa_attempts.delete_one({'_id':user['id']})
    await account_event(user_id,'account.disabled' if body.disabled else 'account.reactivated')
    await account_event(user['id'],'platform.account_disabled' if body.disabled else 'platform.account_reactivated')
    return {**public_account(changed),'notice':'Account state updated. Previous sessions and API tokens remain invalid. Reactivation requires a fresh login. In-flight requests and organization jobs may finish.'}
