"""Organization-owned service principals with capped, one-time credentials."""
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator, model_validator
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from core import Ctx, db, get_ctx, iso, new_id, sha256_hex, audit
from repository import Repository
from distributed_locks import LeaseFactory
from auth import membership_lock

router = APIRouter(prefix='/api')
SERVICE_LOCK = LeaseFactory('service-identities')
SERVICE_ID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', re.I)
ServicePermission = Literal['read','write','scan','report','report_read','triage','remediate','ai','evidence','audit']
SERVICE_PERMISSIONS = frozenset({'read','write','scan','report','report_read','triage','remediate','ai','evidence','audit'})


class IdentityInput(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    owner_user_id: str = Field(min_length=1, max_length=100)
    permissions: list[ServicePermission] = Field(min_length=1, max_length=10)
    project_ids: list[Annotated[str,Field(min_length=1,max_length=100)]] = Field(default_factory=list, max_length=500)

    @field_validator('name')
    @classmethod
    def normalize_name(cls, value):
        value = ' '.join(value.split())
        if len(value) < 2: raise ValueError('Provide a meaningful identity name')
        return value

    @field_validator('permissions')
    @classmethod
    def normalize_permissions(cls, value): return list(dict.fromkeys(value))

    @field_validator('project_ids')
    @classmethod
    def normalize_projects(cls, value): return sorted(set(value))

    @model_validator(mode='after')
    def requires_read(self):
        if 'read' not in self.permissions: raise ValueError('Service identities must include read permission')
        return self


class IdentityUpdate(IdentityInput):
    active: bool = True
    expected_version: int = Field(ge=1, le=2_147_483_647)


class CredentialInput(BaseModel):
    scopes: list[ServicePermission] = Field(min_length=1, max_length=10)
    project_ids: list[Annotated[str,Field(min_length=1,max_length=100)]] = Field(default_factory=list, max_length=500)
    expires_days: int = Field(default=30, ge=1, le=90)

    @field_validator('scopes')
    @classmethod
    def normalize_scopes(cls, value): return list(dict.fromkeys(value))

    @field_validator('project_ids')
    @classmethod
    def normalize_projects(cls, value): return sorted(set(value))


class RotateInput(BaseModel):
    expires_days: int = Field(default=30, ge=1, le=90)


def identity_metadata(row):
    return {'id':str(row['_id']),**{key: row.get(key) for key in ('name','owner_user_id','permissions','project_ids','active','version','created_at','updated_at')}}


def credential_metadata(row):
    return {'id':str(row['_id']),**{key: row.get(key) for key in ('identity_id','name','scopes','project_ids','token_prefix','created_at','expires_at','revoked','revoked_at','last_used_at')}}


def secret_value(): return 'vaptxsvc_' + secrets.token_urlsafe(36)


async def admin_actor(ctx):
    ctx.require('members')
    if ctx.scopes is not None: raise HTTPException(403, 'Use a browser session to manage service identities')
    member = await db.memberships.find_one({'org_id':ctx.org_id,'user_id':ctx.uid,'role':'org_admin'})
    user = await db.users.find_one({'_id':ctx.uid,'disabled':{'$ne':True}})
    if not member or not user or user.get('credential_version',0) != ctx.user.get('credential_version',0):
        raise HTTPException(403, 'Administrator authority changed; reload before continuing')
    if ctx.membership_id and str(member.get('_id')) != ctx.membership_id:
        raise HTTPException(403, 'Administrator membership changed; reload before continuing')


async def owner_in_org(org_id, user_id):
    membership = await db.memberships.find_one({'org_id':org_id,'user_id':user_id})
    if not membership: raise HTTPException(404, 'Choose a current member of this organization as the identity owner')
    user = await db.users.find_one({'_id':user_id,'disabled':{'$ne':True}})
    if not user: raise HTTPException(404, 'Identity owner account is unavailable')
    return user


async def validate_projects(ctx, project_ids):
    if project_ids:
        count = await db.projects.count_documents(Repository(ctx).query({'_id':{'$in':project_ids}}, collection='projects'))
        if count != len(project_ids): raise HTTPException(404, 'A selected project is unavailable in this organization')


async def get_identity(org_id, identity_id, active=None):
    if not SERVICE_ID.fullmatch(identity_id): raise HTTPException(404, 'Service identity not found')
    query = {'_id':identity_id,'org_id':org_id}
    if active is not None: query['active'] = active
    row = await db.service_identities.find_one(query)
    if not row: raise HTTPException(404, 'Service identity not found')
    return row


async def issue_credential(ctx, identity, body, name=''):
    if not identity.get('active'): raise HTTPException(409, 'Enable the service identity before issuing a credential')
    if not set(body.scopes).issubset(set(identity.get('permissions',[]))):
        raise HTTPException(403, 'Credential actions must be a subset of the identity permissions')
    if not set(body.project_ids).issubset(set(identity.get('project_ids',[]))):
        raise HTTPException(403, 'Credential projects must be a subset of the identity project grants')
    await owner_in_org(ctx.org_id, identity['owner_user_id'])
    active_count = await db.service_credentials.count_documents({'org_id':ctx.org_id,'identity_id':identity['_id'],'revoked':False,'expires_at':{'$gt':iso()}})
    if active_count >= 100: raise HTTPException(409, 'Revoke an existing credential before issuing another (maximum 100 active)')
    token = secret_value()
    row = {'_id':new_id(),'org_id':ctx.org_id,'identity_id':identity['_id'],'name':' '.join(name.split())[:80],
        'scopes':body.scopes,'project_ids':body.project_ids,'token_hash':sha256_hex(token.encode()),
        'token_prefix':token[:16],'created_by':ctx.uid,'created_at':iso(),
        'expires_at':(datetime.now(timezone.utc)+timedelta(days=body.expires_days)).isoformat(),
        'revoked':False,'revoked_at':None,'last_used_at':None}
    await db.service_credentials.insert_one(row)
    await audit(ctx,'service_credential.created','service_identities',identity['_id'],{'credential_id':row['_id'],'scopes':body.scopes,'project_ids':body.project_ids})
    return {**credential_metadata(row),'token':token,'notice':'Shown once. Only its hash is retained. Action and project caps are fixed for this credential and intersect the service identity’s current grants.'}


@router.get('/service-identities')
async def list_identities(ctx=Depends(get_ctx)):
    await admin_actor(ctx)
    rows = await db.service_identities.find({'org_id':ctx.org_id}).sort([('name_key',1),('_id',1)]).to_list(100)
    result=[]
    for row in rows:
        item=identity_metadata(row)
        owner=await db.users.find_one({'_id':row['owner_user_id']},{'email':1})
        item['owner_email']=owner.get('email') if owner else None
        item['credentials']=[credential_metadata(c) for c in await db.service_credentials.find({'org_id':ctx.org_id,'identity_id':row['_id']}).sort([('created_at',-1),('_id',-1)]).to_list(100)]
        result.append(item)
    return {'items':result,'permissions':sorted(SERVICE_PERMISSIONS)}


@router.post('/service-identities')
async def create_identity(body:IdentityInput,ctx=Depends(get_ctx)):
    async with membership_lock(ctx.org_id):
        await admin_actor(ctx)
        await owner_in_org(ctx.org_id,body.owner_user_id)
        await validate_projects(ctx,body.project_ids)
        name_key=body.name.casefold()
        if await db.service_identities.find_one({'org_id':ctx.org_id,'name_key':name_key}):
            raise HTTPException(409,'A service identity with this name already exists')
        row={'_id':new_id(),'org_id':ctx.org_id,'name':body.name,'name_key':name_key,'owner_user_id':body.owner_user_id,
            'permissions':body.permissions,'project_ids':body.project_ids,'active':True,'version':1,
            'created_by':ctx.uid,'created_at':iso(),'updated_at':iso()}
        async with SERVICE_LOCK.for_scope(ctx.org_id):
            if await db.service_identities.count_documents({'org_id':ctx.org_id})>=100:
                raise HTTPException(409,'An organization can have at most 100 service identities')
            try: await db.service_identities.insert_one(row)
            except DuplicateKeyError: raise HTTPException(409,'A service identity with this name already exists') from None
    await audit(ctx,'service_identity.created','service_identities',row['_id'],{'owner_user_id':body.owner_user_id,'permissions':body.permissions,'project_ids':body.project_ids})
    return identity_metadata(row)


@router.patch('/service-identities/{identity_id}')
async def update_identity(identity_id:str,body:IdentityUpdate,ctx=Depends(get_ctx)):
    async with membership_lock(ctx.org_id):
        await admin_actor(ctx)
        async with SERVICE_LOCK.for_scope(ctx.org_id):
            identity=await get_identity(ctx.org_id,identity_id)
            await owner_in_org(ctx.org_id,body.owner_user_id)
            await validate_projects(ctx,body.project_ids)
            name_key=body.name.casefold()
            if name_key!=identity.get('name_key') and await db.service_identities.find_one({'org_id':ctx.org_id,'name_key':name_key,'_id':{'$ne':identity_id}}):
                raise HTTPException(409,'A service identity with this name already exists')
            change={'name':body.name,'name_key':name_key,'owner_user_id':body.owner_user_id,'permissions':body.permissions,
                'project_ids':body.project_ids,'active':body.active,'version':body.expected_version+1,'updated_at':iso()}
            try:
                updated=await db.service_identities.find_one_and_update({'_id':identity_id,'org_id':ctx.org_id,'version':body.expected_version},
                    {'$set':change},return_document=ReturnDocument.AFTER)
            except DuplicateKeyError: raise HTTPException(409,'A service identity with this name already exists') from None
            if not updated: raise HTTPException(409,'Service identity changed; reload before saving')
            await audit(ctx,'service_identity.updated','service_identities',identity_id,{'version':updated['version'],'owner_user_id':body.owner_user_id,'permissions':body.permissions,'project_ids':body.project_ids,'active':body.active})
    return identity_metadata(updated)


@router.post('/service-identities/{identity_id}/credentials')
async def create_credential(identity_id:str,body:CredentialInput,ctx=Depends(get_ctx)):
    async with membership_lock(ctx.org_id):
        await admin_actor(ctx)
        async with SERVICE_LOCK.for_scope(ctx.org_id):
            identity=await get_identity(ctx.org_id,identity_id,active=True)
            return await issue_credential(ctx,identity,body)


@router.post('/service-identities/{identity_id}/credentials/{credential_id}/revoke')
async def revoke_credential(identity_id:str,credential_id:str,ctx=Depends(get_ctx)):
    async with membership_lock(ctx.org_id):
        await admin_actor(ctx)
        await get_identity(ctx.org_id,identity_id)
        if not SERVICE_ID.fullmatch(credential_id): raise HTTPException(404,'Credential not found')
        updated=await db.service_credentials.find_one_and_update({'_id':credential_id,'org_id':ctx.org_id,'identity_id':identity_id,'revoked':False},
            {'$set':{'revoked':True,'revoked_at':iso()}},return_document=ReturnDocument.AFTER)
        row=updated or await db.service_credentials.find_one({'_id':credential_id,'org_id':ctx.org_id,'identity_id':identity_id})
        if not row: raise HTTPException(404,'Credential not found')
        if updated: await audit(ctx,'service_credential.revoked','service_identities',identity_id,{'credential_id':credential_id})
    return credential_metadata(row)


@router.post('/service-identities/{identity_id}/credentials/{credential_id}/rotate')
async def rotate_credential(identity_id:str,credential_id:str,body:RotateInput,ctx=Depends(get_ctx)):
    async with membership_lock(ctx.org_id):
        await admin_actor(ctx)
        async with SERVICE_LOCK.for_scope(ctx.org_id):
            identity=await get_identity(ctx.org_id,identity_id,active=True)
            if not SERVICE_ID.fullmatch(credential_id): raise HTTPException(404,'Credential not found')
            old=await db.service_credentials.find_one({'_id':credential_id,'org_id':ctx.org_id,'identity_id':identity_id,'revoked':False,'expires_at':{'$gt':iso()}})
            if not old: raise HTTPException(404,'Active credential not found')
            updated=await db.service_credentials.find_one_and_update({'_id':credential_id,'org_id':ctx.org_id,'identity_id':identity_id,'revoked':False},
                {'$set':{'revoked':True,'revoked_at':iso()}},return_document=ReturnDocument.AFTER)
            if not updated: raise HTTPException(409,'Credential changed; reload before rotating')
            replacement=CredentialInput(scopes=old['scopes'],project_ids=old['project_ids'],expires_days=body.expires_days)
            return await issue_credential(ctx,identity,replacement,old.get('name',''))
