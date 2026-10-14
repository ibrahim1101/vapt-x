import asyncio
import hashlib
import hmac
import ipaddress
import json
import socket
from urllib.parse import urlparse

import httpx

from core import db, iso, new_id

BLOCKED_HOSTS = {"metadata.google.internal", "metadata", "localhost"}


def validate_outbound_url(url: str):
    """Reject URLs pointing at internal/private/metadata networks (SSRF defense)."""
    p = urlparse(url)
    if p.scheme not in ("https", "http"):
        raise ValueError("Only http(s) URLs are allowed")
    host = (p.hostname or "").lower()
    if not host or host in BLOCKED_HOSTS:
        raise ValueError("Host not allowed")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise ValueError("Host does not resolve")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise ValueError(f"Destination {ip} is internal and blocked")


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


async def deliver(hook: dict, event: str, payload: dict):
    body = json.dumps({"event": event, "data": payload, "sent_at": iso()}).encode()
    rec = {"id": new_id(), "org_id": hook["org_id"], "webhook_id": hook["id"], "event": event, "attempts": 0, "status": "pending", "created_at": iso()}
    for attempt in range(1, 4):
        rec["attempts"] = attempt
        try:
            validate_outbound_url(hook["url"])
            async with httpx.AsyncClient(timeout=8, follow_redirects=False) as c:
                r = await c.post(hook["url"], content=body, headers={"Content-Type": "application/json", "X-VAPTX-Event": event, "X-VAPTX-Signature": sign(hook["secret"], body)})
            rec["response_code"] = r.status_code
            if r.status_code < 300:
                rec["status"] = "delivered"
                break
            rec["status"] = "failed"
            rec["error"] = f"HTTP {r.status_code}"
        except Exception as e:
            rec["status"] = "failed"
            rec["error"] = str(e)[:300]
        await asyncio.sleep(2 ** attempt)
    rec["finished_at"] = iso()
    await db.webhook_deliveries.insert_one(rec)
    return rec


async def dispatch_event(org_id: str, event: str, payload: dict):
    hooks = await db.webhooks.find({"org_id": org_id, "enabled": True}, {"_id": 0}).to_list(50)
    for h in hooks:
        if not h.get("events") or event in h["events"]:
            asyncio.create_task(deliver(h, event, payload))
