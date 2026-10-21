"""Organization-scoped, bounded custom roles. Privileged admin powers stay built-in."""
import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator, model_validator
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from core import Ctx, db, get_ctx, iso, new_id, audit

router = APIRouter(prefix='/api')

# Custom roles cannot administer members, authorize scan scope, manage integrations,
# or obtain the built-in administrator wildcard.
CustomPermission = Literal['read','write','scan','report','report_read','triage','remediate','ai','evidence','audit']
CUSTOM_PERMISSIONS = frozenset({'read','write','scan','report','report_read','triage','remediate','ai','evidence','audit'})
ROLE_ID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', re.I)


class RoleInput(BaseModel):
    name: str = Field(min_length=2, max_length=60)
    permissions: list[CustomPermission] = Field(min_length=1, max_length=10)

    @field_validator('name')
    @classmethod
    def clean_name(cls, value):
        value = ' '.join(value.split())
        if len(value) < 2:
            raise ValueError('Provide a meaningful role name')
        return value

    @field_validator('permissions')
    @classmethod
    def normalize_permissions(cls, value):
        return list(dict.fromkeys(value))

    @model_validator(mode='after')
    def require_read(self):
        if 'read' not in self.permissions:
            raise ValueError('Custom roles must include read permission')
        return self


class RoleUpdate(RoleInput):
    expected_version: int = Field(ge=1, le=2_147_483_647)


def metadata(row):
    return {'id':str(row['_id']),**{key: row.get(key) for key in ('name','permissions','version','created_at','updated_at')}}


async def role_permissions(org_id, role_id):
    if not isinstance(role_id, str) or not ROLE_ID.fullmatch(role_id):
        return None
    row = await db.custom_roles.find_one({'_id': role_id, 'org_id': org_id, 'active': True})
    if not row:
        return None
    permissions = row.get('permissions')
    if (not isinstance(permissions, list) or not permissions or len(permissions) > len(CUSTOM_PERMISSIONS)
            or any(permission not in CUSTOM_PERMISSIONS for permission in permissions)
            or 'read' not in permissions):
        return None
    return frozenset(permissions)


async def resolve_role_choice(org_id, choice):
    """Return stored membership role fields for a built-in or custom selector value."""
    from core import ROLES
    if choice in ROLES:
        return {'role': choice}
    if not isinstance(choice, str) or not choice.startswith('custom:'):
        raise HTTPException(422, 'Unknown organization role')
    role_id = choice[7:]
    permissions = await role_permissions(org_id, role_id)
    if permissions is None:
        raise HTTPException(404, 'Custom role is unavailable in this organization')
    return {'role': 'custom', 'custom_role_id': role_id}


async def current_admin(ctx):
    ctx.require('members')
    if ctx.scopes is not None:
        raise HTTPException(403, 'Use a browser session to manage custom roles')
    actor = await db.memberships.find_one({'org_id':ctx.org_id,'user_id':ctx.uid,'role':'org_admin'})
    user = await db.users.find_one({'_id':ctx.uid,'disabled':{'$ne':True}})
    if (not actor or not user or user.get('credential_version',0) != ctx.user.get('credential_version',0)
            or (ctx.membership_id and str(actor.get('_id')) != ctx.membership_id)):
        raise HTTPException(403, 'Administrator authority changed; reload before continuing')


@router.get('/custom-roles')
async def list_custom_roles(ctx=Depends(get_ctx)):
    ctx.require('read')
    rows = await db.custom_roles.find({'org_id':ctx.org_id,'active':True}).sort([('name_key',1),('_id',1)]).to_list(100)
    return {'items':[metadata(row) for row in rows], 'permissions':sorted(CUSTOM_PERMISSIONS)}


@router.post('/custom-roles')
async def create_custom_role(body:RoleInput,ctx=Depends(get_ctx)):
    await current_admin(ctx)
    name_key = body.name.casefold()
    if await db.custom_roles.find_one({'org_id':ctx.org_id,'name_key':name_key}):
        raise HTTPException(409,'A custom role with this name already exists')
    row = {'_id':new_id(),'org_id':ctx.org_id,'name':body.name,'name_key':name_key,
        'permissions':body.permissions,'version':1,'active':True,'created_at':iso(),'updated_at':iso()}
    try:
        await db.custom_roles.insert_one(row)
    except DuplicateKeyError:
        raise HTTPException(409,'A custom role with this name already exists') from None
    await audit(ctx,'custom_role.created','custom_roles',row['_id'],{'permissions':body.permissions})
    return metadata(row)


@router.patch('/custom-roles/{role_id}')
async def update_custom_role(role_id:str,body:RoleUpdate,ctx=Depends(get_ctx)):
    await current_admin(ctx)
    if not ROLE_ID.fullmatch(role_id):
        raise HTTPException(404,'Custom role not found')
    previous = await db.custom_roles.find_one({'_id':role_id,'org_id':ctx.org_id,'active':True})
    if not previous:
        raise HTTPException(404,'Custom role not found')
    changed_name = body.name.casefold() != previous.get('name_key')
    if changed_name and await db.custom_roles.find_one({'org_id':ctx.org_id,'name_key':body.name.casefold(),'_id':{'$ne':role_id}}):
        raise HTTPException(409,'A custom role with this name already exists')
    update = {'name':body.name,'name_key':body.name.casefold(),'permissions':body.permissions,
        'version':body.expected_version+1,'updated_at':iso()}
    try:
        result = await db.custom_roles.find_one_and_update(
            {'_id':role_id,'org_id':ctx.org_id,'active':True,'version':body.expected_version},
            {'$set':update},return_document=ReturnDocument.AFTER)
    except DuplicateKeyError:
        raise HTTPException(409,'A custom role with this name already exists') from None
    if not result:
        raise HTTPException(409,'Custom role changed; reload before saving')
    await audit(ctx,'custom_role.updated','custom_roles',role_id,{'version':result['version'],'permissions':body.permissions})
    return metadata(result)


@router.post('/custom-roles/{role_id}/delete')
async def delete_custom_role(role_id:str,expected_version:int=Query(ge=1,le=2_147_483_647),ctx=Depends(get_ctx)):
    from auth import MEMBER_LOCK
    async with MEMBER_LOCK:
        await current_admin(ctx)
        if not ROLE_ID.fullmatch(role_id):
            raise HTTPException(404,'Custom role not found')
        role = await db.custom_roles.find_one({'_id':role_id,'org_id':ctx.org_id,'active':True,'version':expected_version})
        if not role:
            if await db.custom_roles.find_one({'_id':role_id,'org_id':ctx.org_id,'active':True}):
                raise HTTPException(409,'Custom role changed; reload before deleting')
            raise HTTPException(404,'Custom role not found')
        if await db.memberships.count_documents({'org_id':ctx.org_id,'role':'custom','custom_role_id':role_id}):
            raise HTTPException(409,'Reassign members before deleting this custom role')
        result = await db.custom_roles.delete_one({'_id':role_id,'org_id':ctx.org_id,'active':True,'version':expected_version})
        if result.deleted_count != 1:
            raise HTTPException(409,'Custom role changed; reload before deleting')
        await audit(ctx,'custom_role.deleted','custom_roles',role_id,{'version':expected_version})
    return {'ok':True}
