import os
import secrets
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr, Field
from pymongo.errors import DuplicateKeyError
from core import (db, BaseDocument, clean, iso, now, new_id, hash_password, verify_password,
                  create_access_token, create_refresh_token, decode_token, get_current_user, get_ctx, Ctx, audit, ROLES)

router = APIRouter(prefix="/api")


class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=72)
    name: str = Field(default="", max_length=100)


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
    await insert_identity("sessions", {"id": sid, "user_id": user["id"], "revoked": False, "created_at": iso(), "expires_at": iso(now() + timedelta(days=7))})
    set_cookies(response, user["id"], sid)
    return public_user(user)


def set_cookies(response, uid, sid):
    for name, value, age, http_only in [
        ("access_token", create_access_token(uid, sid), 1800, True),
        ("refresh_token", create_refresh_token(uid, sid), 604800, True),
        ("csrf", secrets.token_urlsafe(32), 604800, False),
    ]:
        response.set_cookie(name, value, httponly=http_only, secure=True, samesite="lax", max_age=age, path="/")


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
        session = await db.sessions.find_one({"_id": payload["sid"], "user_id": payload["sub"], "revoked": False})
        if not session:
            raise ValueError()
    except Exception:
        raise HTTPException(401, "Session expired. Sign in again.")
    await db.sessions.update_one({"_id": payload["sid"]}, {"$set": {"revoked": True}})
    doc = await db.users.find_one({"_id": payload["sub"]})
    if not doc:
        raise HTTPException(401, "Account not found")
    return await establish_session(clean(doc), response)


@router.post("/auth/logout")
async def logout(response: Response, user=Depends(get_current_user)):
    await db.sessions.update_one({"_id": user["_sid"]}, {"$set": {"revoked": True}})
    for key in ("access_token", "refresh_token", "csrf"):
        response.delete_cookie(key, path="/", secure=True, samesite="lax")
    return {"ok": True}


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
