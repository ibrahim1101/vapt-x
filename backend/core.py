import os
import uuid
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from pathlib import Path

import bcrypt
import jwt
from dotenv import load_dotenv
from identity_policy import enforce_workspace_policy
from fastapi import HTTPException, Request
from motor.motor_asyncio import AsyncIOMotorClient
from config import Settings
from pydantic import BaseModel, Field, ConfigDict, BeforeValidator
from typing import Annotated
import asyncio

PyObjectId = Annotated[str, BeforeValidator(str)]


class BaseDocument(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    id: PyObjectId = Field(default_factory=lambda: str(uuid.uuid4()), alias="_id")

    def to_mongo(self):
        return self.model_dump(by_alias=True)

    @classmethod
    def from_mongo(cls, doc):
        return cls.model_validate(doc)


class DomainDocument(BaseDocument):
    org_id: str
    created_by: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

settings = Settings.from_env(os.environ)
client = AsyncIOMotorClient(settings.mongo_url, serverSelectionTimeoutMS=settings.mongo_timeout_ms, connectTimeoutMS=settings.mongo_timeout_ms)
db = client[settings.db_name]
EVIDENCE_DIR = ROOT_DIR / "storage" / "evidence"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
JWT_ALG = "HS256"

ROLES = ["org_admin", "security_lead", "analyst", "auditor", "viewer"]
ROLE_RANK = {r: i for i, r in enumerate(reversed(ROLES))}  # viewer=0 ... org_admin=4

PERMS = {
    "org_admin": {"*"},
    "security_lead": {"read", "write", "scan", "authorize", "report", "triage", "remediate", "ai", "evidence", "integrations"},
    "analyst": {"read", "write", "scan", "report", "triage", "remediate", "ai", "evidence"},
    "auditor": {"read", "audit", "report_read"},
    "viewer": {"read", "report_read"},
}


def now():
    return datetime.now(timezone.utc)


def iso(dt=None):
    return (dt or now()).isoformat()


def new_id():
    return str(uuid.uuid4())


def clean(doc):
    if doc is None:
        return None
    result = BaseDocument.from_mongo(doc).model_dump()
    for field in ("password_hash", "mfa_secret", "mfa_pending", "mfa_recovery_hashes"):
        result.pop(field, None)
    return result


def clean_list(docs):
    return [clean(d) for d in docs]


def hash_password(p: str) -> str:
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()


def verify_password(p: str, h: str) -> bool:
    try:
        return bcrypt.checkpw(p.encode(), h.encode())
    except Exception:
        return False


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def create_access_token(uid: str, sid: str) -> str:
    return jwt.encode({"sub": uid, "sid": sid, "type": "access", "exp": now() + timedelta(minutes=30)}, os.environ["JWT_SECRET"], algorithm=JWT_ALG)


def create_refresh_token(uid: str, sid: str) -> str:
    return jwt.encode({"sub": uid, "sid": sid, "type": "refresh", "exp": now() + timedelta(days=7)}, os.environ["JWT_SECRET"], algorithm=JWT_ALG)


def decode_token(token: str) -> dict:
    return jwt.decode(token, os.environ["JWT_SECRET"], algorithms=[JWT_ALG])


async def get_current_user(request: Request) -> dict:
    cached=getattr(request.state,"api_user",None)
    if cached is not None:return cached
    authorization=request.headers.get("authorization", "")
    if authorization:
        scheme, _, raw=authorization.partition(" ")
        if scheme.lower()!="bearer" or not raw.startswith(("vaptx_","vaptxsvc_")) or not 40<=len(raw)<=100:
            raise HTTPException(401,"Invalid API token")
        if raw.startswith('vaptxsvc_'):
            credential=await db.service_credentials.find_one(
                {'token_hash':sha256_hex(raw.encode()),'revoked':False,'expires_at':{'$gt':iso()}})
            if not credential: raise HTTPException(401,'Invalid, revoked or expired service credential')
            identity=await db.service_identities.find_one({'_id':credential['identity_id'],'org_id':credential['org_id'],'active':True})
            if not identity: raise HTTPException(401,'Service identity is disabled')
            owner=await db.memberships.find_one({'org_id':credential['org_id'],'user_id':identity['owner_user_id']})
            owner_user=await db.users.find_one({'_id':identity['owner_user_id'],'disabled':{'$ne':True}})
            if not owner or not owner_user:
                raise HTTPException(401,'Service identity owner is unavailable; an organization administrator must transfer ownership')
            touched=await db.service_credentials.update_one(
                {'_id':credential['_id'],'revoked':False,'expires_at':{'$gt':iso()}},
                {'$set':{'last_used_at':iso()}})
            if touched.matched_count!=1: raise HTTPException(401,'Service credential was revoked before authorization completed')
            user={'id':identity['_id'],'name':identity['name'],'email':f"{identity['name']} (service identity)",
                '_service_identity_id':identity['_id'],'_service_credential_id':credential['_id'],
                '_service_owner_id':identity['owner_user_id'],'_token_org':credential['org_id'],
                '_token_scopes':credential.get('scopes',[]),'_token_project_ids':credential.get('project_ids',[])}
            enforce_workspace_policy(user,request.url.path)
            request.state.api_user=user
            return user
        token=await db.api_tokens.find_one({"token_hash":sha256_hex(raw.encode()),"revoked":False,"expires_at":{"$gt":iso()}})
        if not token:raise HTTPException(401,"Invalid or expired API token")
        user=await db.users.find_one({"_id":token["created_by"]})
        if not user or user.get("disabled") or user.get("credential_version",0)!=token.get("credential_version",0):raise HTTPException(401,"Token owner credentials changed")
        user=clean(user)
        user.update(_token_scopes=token["scopes"],_token_org=token["org_id"],_api_token_id=str(token["_id"]),_token_membership_id=token.get("membership_id"),_token_project_ids=token.get("project_ids"))
        enforce_workspace_policy(user,request.url.path)
        request.state.api_user=user
        return user
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(401, "Not authenticated")
    try:
        payload = decode_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")
    if payload.get("type") != "access" or not payload.get("sub"):
        raise HTTPException(401, "Invalid token type")
    sess = await db.sessions.find_one({"_id": payload.get("sid"), "user_id": payload["sub"], "revoked": False, "expires_at": {"$gt": iso()}})
    if not sess:
        raise HTTPException(401, "Session revoked or expired")
    user = await db.users.find_one({"_id": payload["sub"]})
    if not user or user.get("disabled") or user.get("credential_version", 0) != sess.get("credential_version", 0):
        raise HTTPException(401, "Session credentials changed")
    user["_sid"] = payload.get("sid")
    user=clean(user)
    enforce_workspace_policy(user,request.url.path)
    return user


class Ctx:
    def __init__(self, user, org_id, role, custom_permissions=None, service_permissions=None):
        self.user = user
        self.uid = user["id"]
        self.org_id = org_id
        self.role = role
        self.custom_permissions = frozenset(custom_permissions or ())
        self.service_permissions = frozenset(service_permissions or ())
        self.scopes = user.get("_token_scopes")
        self.membership_id = None
        self.project_ids = None
        self.service_identity_id = user.get('_service_identity_id')
        self.service_credential_id = user.get('_service_credential_id')
        self.service_owner_id = user.get('_service_owner_id')

    def can(self, perm: str) -> bool:
        if self.project_ids is not None and perm in {"integrations", "members"}:return False
        if self.scopes is not None and perm not in self.scopes and "*" not in self.scopes:
            return False
        p = PERMS.get(self.role, set())
        if self.role=='service': return perm in self.service_permissions
        return "*" in p or perm in p or perm in self.custom_permissions

    def require(self, perm: str):
        if not self.can(perm):
            asyncio.create_task(audit(self, "permission.denied", details={"permission": perm}, outcome="deny"))
            raise HTTPException(403, f"Permission '{perm}' required (role: {self.role})")


async def get_ctx(request: Request) -> Ctx:
    user = await get_current_user(request)
    if user.get("_token_org") and request.headers.get("X-Org-Id") not in {None,user["_token_org"]}:
        raise HTTPException(404,"Organization not found")
    org_id = user.get("_token_org") or request.headers.get("X-Org-Id") or user.get("active_org_id")
    if not org_id:
        raise HTTPException(409, "No active organization")
    if user.get('_service_identity_id'):
        identity=await db.service_identities.find_one({'_id':user['_service_identity_id'],'org_id':org_id,'active':True})
        if not identity or identity.get('owner_user_id')!=user.get('_service_owner_id'):
            raise HTTPException(401,'Service identity changed; administrator handoff or reactivation is required')
        owner=await db.memberships.find_one({'org_id':org_id,'user_id':identity['owner_user_id']})
        owner_user=await db.users.find_one({'_id':identity['owner_user_id'],'disabled':{'$ne':True}})
        if not owner or not owner_user:
            raise HTTPException(401,'Service identity owner is unavailable; an organization administrator must transfer ownership')
        identity_projects=identity.get('project_ids',[])
        credential_projects=user.get('_token_project_ids',[])
        if not isinstance(identity_projects,list) or not isinstance(credential_projects,list): project_ids=[]
        else: project_ids=sorted(set(identity_projects).intersection(credential_projects))
        ctx=Ctx(user,org_id,'service',service_permissions=identity.get('permissions',[]))
        ctx.project_ids=project_ids
        ctx.service_identity_id=identity['_id']
        ctx.service_credential_id=user['_service_credential_id']
        ctx.service_owner_id=identity['owner_user_id']
        return ctx
    m = await db.memberships.find_one({"org_id": org_id, "user_id": user["id"]})
    if not m:
        raise HTTPException(404, "Organization not found")
    if user.get("_token_membership_id") and user["_token_membership_id"]!=str(m.get("_id")):
        raise HTTPException(401,"API token membership changed")
    if user.get("_api_token_id") and not user.get("_token_membership_id"):
        if await db.membership_revocations.find_one({"_id":org_id+":"+user["id"]}):
            raise HTTPException(401,"Legacy API token membership was removed")
    custom_permissions=None
    if m.get('role')=='custom':
        from custom_roles import role_permissions
        custom_permissions=await role_permissions(org_id,m.get('custom_role_id'))
        if custom_permissions is None:
            raise HTTPException(403,"Organization role is unavailable; contact an administrator")
    ctx=Ctx(user,org_id,m["role"],custom_permissions)
    from project_access import effective_projects
    ctx.project_ids=effective_projects(m,user)
    ctx.membership_id=str(m["_id"]) if m.get("_id") else None
    return ctx


async def get_one(coll: str, ctx: Ctx, oid: str):
    from repository import Repository
    return await Repository(ctx).get(coll,oid)


async def audit(ctx_or_none, action: str, resource_type: str = "", resource_id: str = "", details: dict | None = None, org_id: str | None = None, actor_email: str | None = None, outcome: str = "allow"):
    from project_access import PROJECT_COLLECTIONS
    project_id=None
    if ctx_or_none and resource_type in PROJECT_COLLECTIONS and resource_id:
        if resource_type=='projects':project_id=resource_id
        else:
            resource=await db[resource_type].find_one({'_id':resource_id,'org_id':ctx_or_none.org_id},{'project_id':1})
            if resource:project_id=resource.get('project_id')
    doc = DomainDocument(
        **({'project_id':project_id} if project_id else {}),
        **({'service_identity_id':ctx_or_none.user.get('_service_identity_id'),
            'service_credential_id':ctx_or_none.user.get('_service_credential_id')} if ctx_or_none and ctx_or_none.user.get('_service_identity_id') else {}),
        org_id=org_id or ctx_or_none.org_id,
        created_by=ctx_or_none.uid if ctx_or_none else "system",
        actor_id=ctx_or_none.uid if ctx_or_none else None,
        api_token_id=ctx_or_none.user.get("_api_token_id") if ctx_or_none else None,
        actor_email=actor_email or (ctx_or_none.user.get("email") if ctx_or_none else None),
        action=action, resource_type=resource_type, resource_id=resource_id,
        details=details or {}, outcome=outcome,
    )
    await db.audit_events.insert_one(doc.to_mongo())
    if action in {"finding.triaged","scan.completed","reports.created","assessment.cancelled"}:
        try:
            from webhooks import dispatch_event
            await dispatch_event(doc.org_id,action,doc.model_dump())
        except Exception:
            import logging
            logging.getLogger(__name__).warning("Webhook enqueue failed; primary action audit was preserved")


async def notify(org_id: str, kind: str, title: str, body: str = "", link: str = "", user_ids: list | None = None, severity: str = "info"):
    if user_ids is None:
        ms = await db.memberships.find({"org_id": org_id}, {"user_id": 1}).to_list(500)
        user_ids = [m["user_id"] for m in ms]
    docs = [{"id": new_id(), "org_id": org_id, "user_id": u, "kind": kind, "title": title, "body": body, "link": link, "severity": severity, "read": False, "created_at": iso()} for u in user_ids]
    if docs:
        await db.notifications.insert_many(docs)
    from webhooks import dispatch_event
    await dispatch_event(org_id, kind, {"title": title, "body": body, "link": link})


def gen_api_token() -> str:
    return "vx_" + secrets.token_urlsafe(32)
