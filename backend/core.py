import os
import uuid
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from pathlib import Path

import bcrypt
import jwt
from dotenv import load_dotenv
from fastapi import HTTPException, Request
from motor.motor_asyncio import AsyncIOMotorClient
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

client = AsyncIOMotorClient(os.environ["MONGO_URL"])
db = client[os.environ["DB_NAME"]]
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
    result.pop("password_hash", None)
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
    sess = await db.sessions.find_one({"_id": payload.get("sid"), "user_id": payload["sub"], "revoked": False})
    if not sess:
        raise HTTPException(401, "Session revoked")
    user = await db.users.find_one({"_id": payload["sub"]})
    if not user:
        raise HTTPException(401, "User not found")
    user["_sid"] = payload.get("sid")
    return clean(user)


class Ctx:
    def __init__(self, user, org_id, role):
        self.user = user
        self.uid = user["id"]
        self.org_id = org_id
        self.role = role
        self.scopes = user.get("_token_scopes")

    def can(self, perm: str) -> bool:
        if self.scopes is not None and perm not in self.scopes and "*" not in self.scopes:
            return False
        p = PERMS.get(self.role, set())
        return "*" in p or perm in p

    def require(self, perm: str):
        if not self.can(perm):
            asyncio.create_task(audit(self, "permission.denied", details={"permission": perm}, outcome="deny"))
            raise HTTPException(403, f"Permission '{perm}' required (role: {self.role})")


async def get_ctx(request: Request) -> Ctx:
    user = await get_current_user(request)
    org_id = user.get("_token_org") or request.headers.get("X-Org-Id") or user.get("active_org_id")
    if not org_id:
        raise HTTPException(409, "No active organization")
    m = await db.memberships.find_one({"org_id": org_id, "user_id": user["id"]})
    if not m:
        raise HTTPException(404, "Organization not found")
    return Ctx(user, org_id, m["role"])


async def get_one(coll: str, ctx: Ctx, oid: str):
    doc = await db[coll].find_one({"id": oid, "org_id": ctx.org_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, f"{coll[:-1] if coll.endswith('s') else coll} not found")
    return doc


async def audit(ctx_or_none, action: str, resource_type: str = "", resource_id: str = "", details: dict | None = None, org_id: str | None = None, actor_email: str | None = None, outcome: str = "allow"):
    doc = DomainDocument(
        org_id=org_id or ctx_or_none.org_id,
        created_by=ctx_or_none.uid if ctx_or_none else "system",
        actor_id=ctx_or_none.uid if ctx_or_none else None,
        actor_email=actor_email or (ctx_or_none.user["email"] if ctx_or_none else None),
        action=action, resource_type=resource_type, resource_id=resource_id,
        details=details or {}, outcome=outcome,
    )
    await db.audit_events.insert_one(doc.to_mongo())


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
