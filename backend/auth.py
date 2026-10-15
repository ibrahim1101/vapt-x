import os
import secrets
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr, Field, field_validator
from pymongo.errors import DuplicateKeyError
from pymongo import ReturnDocument
from core import (db, BaseDocument, clean, iso, now, new_id, hash_password, verify_password,
                  create_access_token, create_refresh_token, decode_token, get_current_user, get_ctx, Ctx, audit, ROLES)

router = APIRouter(prefix="/api")


class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=72)
    name: str = Field(default="", max_length=100)

    @field_validator("password")
    @classmethod
    def bcrypt_byte_limit(cls, value):
        if len(value.encode("utf-8")) > 72:
            raise ValueError("Password must not exceed 72 UTF-8 bytes")
        return value


class PasswordChange(BaseModel):
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


async def seed_admin():
    await db.users.create_index("email", unique=True)
    await db.memberships.create_index([("org_id", 1), ("user_id", 1)], unique=True)
    await db.auth_attempts.create_index("expires_at", expireAfterSeconds=0)
    email = os.environ["ADMIN_EMAIL"].lower().strip()
    if not await db.users.find_one({"email": email}):
        await insert_identity("users", {"email": email, "name": "Workspace owner", "password_hash": hash_password(os.environ["ADMIN_PASSWORD"]), "platform_role": "platform_admin", "created_at": iso()})


async def establish_session(user, response):
    sid = new_id()
    await insert_identity("sessions", {"id": sid, "user_id": user["id"], "credential_version": user.get("credential_version", 0), "revoked": False, "created_at": iso(), "expires_at": iso(now() + timedelta(days=7))})
    set_cookies(response, user["id"], sid)
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
    count = await db.auth_attempts.count_documents({"email": email, "expires_at": {"$gt": now()}})
    if count >= 10:
        raise HTTPException(429, "Too many attempts. Try again in 15 minutes.")
    doc = await db.users.find_one({"email": email})
    if not doc or not verify_password(body.password, doc["password_hash"]):
        await insert_identity("auth_attempts", {"email": email, "expires_at": now() + timedelta(minutes=15)})
        raise HTTPException(401, "Invalid email or password")
    await db.auth_attempts.delete_many({"email": email})
    return await establish_session(clean(doc), response)


@router.get("/auth/me")
async def me(user=Depends(get_current_user)):
    memberships = await db.memberships.find({"user_id": user["id"]}).to_list(100)
    orgs = []
    for m in memberships:
        org = await db.organizations.find_one({"_id": m["org_id"]})
        if org:
            orgs.append({"id": str(org["_id"]), "name": org["name"], "role": m["role"]})
    return {**public_user(user), "organizations": orgs}


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
    if not doc or doc.get("credential_version", 0) != session.get("credential_version", 0):
        raise HTTPException(401, "Session expired. Sign in again.")
    return await establish_session(clean(doc), response)


@router.post("/auth/logout")
async def logout(response: Response, user=Depends(get_current_user)):
    await db.sessions.update_one({"_id": user["_sid"]}, {"$set": {"revoked": True}})
    for key in ("access_token", "refresh_token", "csrf"):
        response.delete_cookie(key, path="/", secure=not local_cookie_mode(), samesite="lax")
    return {"ok": True}


@router.post("/auth/password")
async def change_password(body: PasswordChange, response: Response, user=Depends(get_current_user)):
    if user.get("_token_scopes") is not None:
        raise HTTPException(403, "Use a browser session to change your password")
    credential = await db.users.find_one({"_id": user["id"]})
    if not credential or credential.get("credential_version", 0) != user.get("credential_version", 0):
        raise HTTPException(401, "Credentials changed. Sign in again.")
    # Independent throttle: a stolen session must not allow unlimited password guesses.
    key = "password-change:" + user["id"]
    if await db.auth_attempts.count_documents({"email": key, "expires_at": {"$gt": now()}}) >= 10:
        raise HTTPException(429, "Too many attempts. Try again in 15 minutes.")
    await insert_identity("auth_attempts", {"email": key, "expires_at": now() + timedelta(minutes=15)})
    if not verify_password(body.current_password, credential["password_hash"]):
        raise HTTPException(403, "Current password is incorrect")
    if verify_password(body.new_password, credential["password_hash"]):
        raise HTTPException(422, "Choose a different password")
    # Compare-and-swap prevents concurrent changes from overwriting one another.
    # Credential versions also invalidate sessions/tokens minted by in-flight old requests.
    changed = await db.users.find_one_and_update(
        {"_id": user["id"], "password_hash": credential["password_hash"]},
        {"$set": {"password_hash": hash_password(body.new_password), "password_changed_at": iso()},
         "$inc": {"credential_version": 1}}, return_document=ReturnDocument.AFTER)
    if not changed:
        raise HTTPException(409, "Credentials changed. Sign in again.")
    version = changed["credential_version"]
    old_versions = {"$or": [{"credential_version": {"$exists": False}}, {"credential_version": {"$lt": version}}]}
    await db.sessions.update_many({"user_id": user["id"], "revoked": False, **old_versions}, {"$set": {"revoked": True}})
    await db.api_tokens.update_many({"created_by": user["id"], "revoked": False, **old_versions}, {"$set": {"revoked": True, "revoked_at": iso()}})
    await db.auth_attempts.delete_many({"email": key})
    await establish_session(clean(changed), response)
    return {"ok": True, "notice": "Password changed. Previous sessions and API tokens are invalidated."}


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


@router.post("/members")
async def grant_member(body: MemberInput, ctx=Depends(get_ctx)):
    ctx.require("members")
    if body.role not in ROLES:
        raise HTTPException(422, "Unknown organization role")
    user = await db.users.find_one({"email": str(body.email).lower()})
    if not user:
        raise HTTPException(404, "User must register before being added")
    if str(user["_id"]) == ctx.uid and body.role != "org_admin":
        raise HTTPException(400, "You cannot demote yourself")
    await db.memberships.update_one({"org_id": ctx.org_id, "user_id": str(user["_id"])}, {"$set": {"role": body.role}, "$setOnInsert": {"_id": new_id()}}, upsert=True)
    await audit(ctx, "membership.granted", "users", str(user["_id"]), {"role": body.role})
    return {"ok": True}
