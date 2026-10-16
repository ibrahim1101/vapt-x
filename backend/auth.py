import os
import asyncio
import secrets
import logging
import hashlib
import math
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query
from pydantic import BaseModel, EmailStr, Field, field_validator
from pymongo.errors import DuplicateKeyError
from pymongo import ReturnDocument
from core import (db, BaseDocument, clean, iso, now, new_id, hash_password, verify_password,
                  create_access_token, create_refresh_token, decode_token, get_current_user, get_ctx, Ctx, audit, ROLES)

router = APIRouter(prefix="/api")
# The application currently requires one API worker (scanner ownership is also local).
MEMBER_LOCK = asyncio.Lock()


class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=72)
    name: str = Field(default="", max_length=100)
    mfa_code: str = Field(default="", max_length=64)

    @field_validator("password")
    @classmethod
    def bcrypt_byte_limit(cls, value):
        if len(value.encode("utf-8")) > 72:
            raise ValueError("Password must not exceed 72 UTF-8 bytes")
        return value


class PasswordChange(BaseModel):
    mfa_code: str = Field(default="", max_length=64)
    current_password: str = Field(min_length=10, max_length=72)
    new_password: str = Field(min_length=10, max_length=72)

    @field_validator("current_password", "new_password")
    @classmethod
    def byte_limit(cls, value):
        return Credentials.bcrypt_byte_limit(value)


class OrgInput(BaseModel):
    name: str = Field(min_length=2, max_length=100)


class MemberInput(BaseModel):
    email: EmailStr
    role: str


def public_user(user):
    return {k: user.get(k) for k in ("id", "email", "name", "active_org_id", "platform_role")}


async def insert_identity(collection, fields):
    doc = BaseDocument(**fields)
    await db[collection].insert_one(doc.to_mongo())
    return doc.model_dump()


async def account_event(user_id, action):
    # Metadata only. A history outage must not strand an account after credential rotation.
    try:
        await insert_identity("account_events", {"user_id":user_id,"action":action,"created_at":iso()})
    except Exception:
        logging.getLogger(__name__).warning("Account security history write failed")


@router.get("/auth/security-events")
async def security_events(offset:int=Query(default=0,ge=0,le=1_000_000),
    limit:int=Query(default=25,ge=1,le=100),user=Depends(get_current_user)):
    if user.get("_token_scopes") is not None: raise HTTPException(403,"Use a browser session to view account security history")
    query={"user_id":user["id"]}
    total=await db.account_events.count_documents(query)
    rows=await db.account_events.find(query,{"_id":1,"action":1,"created_at":1}).sort(
        [("created_at",-1),("_id",-1)]).skip(offset).limit(limit).to_list(limit)
    return {"items":[{"id":str(row["_id"]),"action":row["action"],"created_at":row["created_at"]} for row in rows],
        "total":total,"offset":offset,"limit":limit,"has_more":offset+len(rows)<total,
        "notice":"Your account events across organizations. Historical events before this feature are unavailable. History recording is best effort and is not a tamper-proof audit log."}


async def seed_admin():
    await db.users.create_index("email", unique=True)
    await db.memberships.create_index([("org_id", 1), ("user_id", 1)], unique=True)
    await db.auth_rate_limits.create_index("expires_at", expireAfterSeconds=0)
    await db.mfa_attempts.create_index("expires_at", expireAfterSeconds=0)
    await db.account_events.create_index([("user_id",1),("created_at",-1),("_id",-1)])
    email = os.environ["ADMIN_EMAIL"].lower().strip()
    if not await db.users.find_one({"email": email}):
        await insert_identity("users", {"email": email, "name": "Workspace owner", "password_hash": hash_password(os.environ["ADMIN_PASSWORD"]), "platform_role": "platform_admin", "created_at": iso()})


async def establish_session(user, response):
    sid = new_id()
    await insert_identity("sessions", {"id": sid, "user_id": user["id"], "credential_version": user.get("credential_version", 0), "revoked": False, "created_at": iso(), "expires_at": iso(now() + timedelta(days=7))})
    set_cookies(response, user["id"], sid)
    await account_event(user["id"], "session.created")
    return public_user(user)


def local_cookie_mode():
    """Allow insecure cookies only for explicit loopback-only local development."""
    from urllib.parse import urlsplit
    url = urlsplit(os.environ.get("FRONTEND_URL", ""))
    return os.environ.get("VAPTX_LOCAL_HTTP") == "1" and url.scheme == "http" and url.hostname in {"localhost", "127.0.0.1"}


def set_cookies(response, uid, sid):
    for name, value, age, http_only in [
        ("access_token", create_access_token(uid, sid), 1800, True),
        ("refresh_token", create_refresh_token(uid, sid), 604800, True),
        ("csrf", secrets.token_urlsafe(32), 604800, False),
    ]:
        response.set_cookie(name, value, httponly=http_only, secure=not local_cookie_mode(), samesite="lax", max_age=age, path="/")


@router.post("/auth/register")
async def register(body: Credentials, response: Response):
    try:
        user = await insert_identity("users", {"email": str(body.email).lower(), "name": body.name or "Analyst", "password_hash": hash_password(body.password), "created_at": iso(), "platform_role": None})
    except DuplicateKeyError:
        raise HTTPException(409, "This email is already registered")
    return await establish_session(user, response)


@router.post("/auth/login")
async def login(body: Credentials, response: Response):
    email = str(body.email).lower()
    await charge_auth_attempt("login", email)
    doc = await db.users.find_one({"email": email})
    if not doc or doc.get("disabled") or not verify_password(body.password, doc["password_hash"]):
        raise HTTPException(401, "Invalid email or password")
    if doc.get("mfa_enabled"):
        from mfa import consume
        verified = await consume(doc, body.mfa_code)
        if not verified:
            raise HTTPException(401, "A valid, unused authenticator or recovery code is required")
        doc = verified
        await db.mfa_attempts.delete_one({"_id":str(doc["_id"])})
    return await establish_session(clean(doc), response)


async def charge_auth_attempt(action, subject):
    """Reserve one password check atomically; successes do not reset the budget."""
    instant = now()
    window = int(instant.timestamp()) // 900
    expires = datetime.fromtimestamp((window + 1) * 900, tz=timezone.utc)
    identity = hashlib.sha256(subject.encode()).hexdigest()
    query = {"_id": f"{action}:{identity}:{window}"}
    update = {"$inc": {"count": 1}, "$setOnInsert": {"expires_at": expires}}
    try:
        attempt = await db.auth_rate_limits.find_one_and_update(
            query, update, upsert=True, return_document=ReturnDocument.AFTER)
    except DuplicateKeyError:
        # A concurrent first request may win insertion of this unique bucket.
        attempt = await db.auth_rate_limits.find_one_and_update(
            query, {"$inc": {"count": 1}}, return_document=ReturnDocument.AFTER)
    if not attempt or attempt["count"] > 10:
        retry_after = max(1, math.ceil((expires - instant).total_seconds()))
        raise HTTPException(429, "Too many attempts. Try again after the current 15-minute window.",
                            headers={"Retry-After": str(retry_after)})


@router.get("/auth/me")
async def me(user=Depends(get_current_user)):
    memberships = await db.memberships.find({"user_id": user["id"]}).to_list(100)
    orgs = []
    for m in memberships:
        org = await db.organizations.find_one({"_id": m["org_id"]})
        if org:
            orgs.append({"id": str(org["_id"]), "name": org["name"], "role": m["role"]})
    active=user.get("active_org_id")
    if active not in {org["id"] for org in orgs}:active=orgs[0]["id"] if orgs else None
    return {**public_user(user), "active_org_id":active, "organizations": orgs}


@router.post("/auth/refresh")
async def refresh(request: Request, response: Response):
    try:
        payload = decode_token(request.cookies.get("refresh_token", ""))
        if payload.get("type") != "refresh":
            raise ValueError()
        # Consume the old session in one database operation. A separate read and
        # revoke lets concurrent requests mint multiple replacement sessions.
        session = await db.sessions.find_one_and_update(
            {"_id": payload["sid"], "user_id": payload["sub"], "revoked": False,
             "expires_at": {"$gt": iso()}},
            {"$set": {"revoked": True}},
        )
        if not session:
            raise ValueError()
    except Exception:
        raise HTTPException(401, "Session expired. Sign in again.")
    doc = await db.users.find_one({"_id": payload["sub"]})
    if not doc or doc.get("disabled") or doc.get("credential_version", 0) != session.get("credential_version", 0):
        raise HTTPException(401, "Session expired. Sign in again.")
    return await establish_session(clean(doc), response)


@router.post("/auth/logout")
async def logout(response: Response, user=Depends(get_current_user)):
    await db.sessions.update_one({"_id": user["_sid"]}, {"$set": {"revoked": True}})
    for key in ("access_token", "refresh_token", "csrf"):
        response.delete_cookie(key, path="/", secure=not local_cookie_mode(), samesite="lax")
    await account_event(user["id"], "session.logged_out")
    return {"ok": True}


@router.post("/auth/password")
async def change_password(body: PasswordChange, response: Response, user=Depends(get_current_user)):
    if user.get("_token_scopes") is not None:
        raise HTTPException(403, "Use a browser session to change your password")
    credential = await db.users.find_one({"_id": user["id"]})
    if not credential or credential.get("credential_version", 0) != user.get("credential_version", 0):
        raise HTTPException(401, "Credentials changed. Sign in again.")
    # Independent throttle: a stolen session must not allow unlimited password guesses.
    await charge_auth_attempt("password-change", user["id"])
    if not verify_password(body.current_password, credential["password_hash"]):
        raise HTTPException(403, "Current password is incorrect")
    if verify_password(body.new_password, credential["password_hash"]):
        raise HTTPException(422, "Choose a different password")
    from mfa import consume, version_query
    if credential.get("mfa_enabled"):
        credential = await consume(credential, body.mfa_code)
        if not credential: raise HTTPException(403, "A valid, unused authenticator or recovery code is required")
    # Compare-and-swap prevents concurrent changes from overwriting one another.
    # Credential versions also invalidate sessions/tokens minted by in-flight old requests.
    changed = await db.users.find_one_and_update(
        {"_id": user["id"], "password_hash": credential["password_hash"], **version_query(credential)},
        {"$set": {"password_hash": hash_password(body.new_password), "password_changed_at": iso()},
         "$inc": {"credential_version": 1}}, return_document=ReturnDocument.AFTER)
    if not changed:
        raise HTTPException(409, "Credentials changed. Sign in again.")
    await renew_credentials(changed, response)
    await account_event(user["id"], "password.changed")
    return {"ok": True, "notice": "Password changed. Previous sessions and API tokens are invalidated."}


async def renew_credentials(document, response):
    """Epoch invalidation is authoritative even if old requests insert after cleanup."""
    version = document["credential_version"]
    uid = str(document["_id"])
    old_versions = {"$or": [{"credential_version": {"$exists": False}}, {"credential_version": {"$lt": version}}]}
    await db.sessions.update_many({"user_id": uid, "revoked": False, **old_versions}, {"$set": {"revoked": True}})
    await db.api_tokens.update_many({"created_by": uid, "revoked": False, **old_versions}, {"$set": {"revoked": True, "revoked_at": iso()}})
    await establish_session(clean(document), response)


@router.get("/auth/sessions")
async def list_sessions(user=Depends(get_current_user)):
    records = await db.sessions.find(
        {"user_id": user["id"], "revoked": False, "expires_at": {"$gt": iso()}},
        {"_id": 1, "created_at": 1, "expires_at": 1},
    ).sort([("created_at", -1), ("_id", -1)]).to_list(101)
    return {"sessions": [
        {"id": str(row["_id"]), "created_at": row.get("created_at"),
         "expires_at": row["expires_at"], "current": str(row["_id"]) == user["_sid"]}
        for row in records[:100]
    ], "has_more": len(records) > 100}


@router.post("/auth/sessions/revoke-others")
async def revoke_other_sessions(user=Depends(get_current_user)):
    result = await db.sessions.update_many(
        {"user_id": user["id"], "_id": {"$ne": user["_sid"]},
         "revoked": False, "expires_at": {"$gt": iso()}},
        {"$set": {"revoked": True}},
    )
    await account_event(user["id"], "sessions.others_revoked")
    return {"revoked_count": result.modified_count}


@router.post("/auth/sessions/{session_id}/revoke")
async def revoke_session(session_id: str, response: Response, user=Depends(get_current_user)):
    session = await db.sessions.find_one_and_update(
        {"_id": session_id, "user_id": user["id"], "revoked": False,
         "expires_at": {"$gt": iso()}},
        {"$set": {"revoked": True}},
    )
    if not session:
        raise HTTPException(404, "Active session not found")
    current = session_id == user["_sid"]
    if current:
        for key in ("access_token", "refresh_token", "csrf"):
            response.delete_cookie(key, path="/", secure=not local_cookie_mode(), samesite="lax")
    await account_event(user["id"], "session.revoked")
    return {"ok": True, "current": current}


@router.post("/organizations")
async def create_org(body: OrgInput, user=Depends(get_current_user)):
    org = await insert_identity("organizations", {"name": body.name, "created_by": user["id"], "created_at": iso()})
    await insert_identity("memberships", {"org_id": org["id"], "user_id": user["id"], "role": "org_admin"})
    await db.users.update_one({"_id": user["id"]}, {"$set": {"active_org_id": org["id"]}})
    await audit(Ctx(user, org["id"], "org_admin"), "organization.created", "organizations", org["id"])
    return org


@router.get("/members")
async def members(ctx=Depends(get_ctx)):
    ctx.require("read")
    records = await db.memberships.find({"org_id": ctx.org_id}).to_list(100)
    result = []
    for m in records:
        u = await db.users.find_one({"_id": m["user_id"]})
        if u:
            result.append({"id": m["user_id"], "name": u.get("name"), "email": u["email"], "role": m["role"]})
    return result


async def live_membership_admin(ctx):
    ctx.require("members")
    actor=await db.memberships.find_one({"org_id":ctx.org_id,"user_id":ctx.uid,"role":"org_admin"})
    if not actor: raise HTTPException(403,"Organization administrator permission changed; reload your workspace")


@router.post("/members")
async def grant_member(body: MemberInput, ctx=Depends(get_ctx)):
    ctx.require("members")
    if body.role not in ROLES: raise HTTPException(422,"Unknown organization role")
    async with MEMBER_LOCK:
        await live_membership_admin(ctx)
        user=await db.users.find_one({"email":str(body.email).lower()})
        if not user: raise HTTPException(404,"User must register before being added")
        if str(user["_id"])==ctx.uid and body.role!="org_admin": raise HTTPException(400,"You cannot demote yourself")
        target=await db.memberships.find_one({"org_id":ctx.org_id,"user_id":str(user["_id"])})
        if target and target["role"]=="org_admin" and body.role!="org_admin" and await db.memberships.count_documents({"org_id":ctx.org_id,"role":"org_admin"})<=1:
            raise HTTPException(409,"An organization must retain an administrator")
        await db.memberships.update_one({"org_id":ctx.org_id,"user_id":str(user["_id"])},
            {"$set":{"role":body.role},"$setOnInsert":{"_id":new_id()}},upsert=True)
        await audit(ctx,"membership.granted","users",str(user["_id"]),{"role":body.role})
    return {"ok":True}


class MemberRemoval(BaseModel):
    reason:str=Field(min_length=5,max_length=500)
    @field_validator("reason")
    @classmethod
    def meaningful(cls,value):
        if len(value.strip())<5:raise ValueError("Provide a reason of at least five characters")
        return value.strip()


@router.post("/members/{user_id}/remove")
async def remove_member(user_id:str,body:MemberRemoval,ctx=Depends(get_ctx)):
    ctx.require("members")
    if user_id==ctx.uid:raise HTTPException(409,"You cannot remove your own organization membership")
    async with MEMBER_LOCK:
        await live_membership_admin(ctx)
        membership=await db.memberships.find_one({"org_id":ctx.org_id,"user_id":user_id})
        if not membership:raise HTTPException(404,"Organization membership not found")
        if membership["role"]=="org_admin" and await db.memberships.count_documents({"org_id":ctx.org_id,"role":"org_admin"})<=1:
            raise HTTPException(409,"An organization must retain an administrator")
        # A retained marker also blocks unbound tokens issued before membership binding existed.
        # Write it before deletion so a partial cleanup failure cannot revive a legacy token.
        await db.membership_revocations.update_one({"_id":ctx.org_id+":"+user_id},
            {"$set":{"removed_at":iso()}},upsert=True)
        removed=await db.memberships.delete_one({"_id":membership["_id"],"org_id":ctx.org_id,"user_id":user_id})
        if not removed.deleted_count:raise HTTPException(409,"Membership changed; reload before trying again")
        await db.api_tokens.update_many({"org_id":ctx.org_id,"created_by":user_id,"revoked":False},
            {"$set":{"revoked":True,"revoked_at":iso()}})
        await db.users.update_one({"_id":user_id,"active_org_id":ctx.org_id},{"$set":{"active_org_id":None}})
        await audit(ctx,"membership.removed","users",user_id,{"reason":body.reason})
    return {"ok":True,"notice":"Organization access removed and its API tokens revoked. The account and memberships in other organizations are retained. Requests already in progress may finish."}
