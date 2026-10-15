import asyncio
import ipaddress
import os
import shutil
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx
from fastapi import HTTPException
from core import db, Ctx, clean, iso, audit, sha256_hex
from repository import Repository
from importers import finding, parse_report

JOB_LOCK = asyncio.Lock()
ACTIVE_CHECKS = {}  # Single-worker managed child tasks, keyed by organization/job.

SCANNERS = {"safe", "nmap", "nuclei", "semgrep", "trivy", "zap", "gitleaks", "checkov"}


def target_host(target):
    if target == "training://local":
        return target
    parsed = urlsplit(target if "://" in target else "https://" + target)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Use an HTTP(S) URL or hostname without credentials or fragments")
    host = parsed.hostname.lower().rstrip(".")
    if len(host) > 253 or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789.-:" for c in host):
        raise ValueError("Invalid hostname")
    if parsed.port not in (None, 80, 443, 8080, 8443):
        raise ValueError("Only web ports 80, 443, 8080 and 8443 are allowed")
    return host


async def resolve_public(host):
    infos = await asyncio.to_thread(socket.getaddrinfo, host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    ips = sorted({x[4][0] for x in infos})
    if not ips or any(not ipaddress.ip_address(ip).is_global for ip in ips):
        raise ValueError("Private, local, reserved and metadata destinations are blocked. Use the managed training target for local testing.")
    return next((ip for ip in ips if ":" not in ip), ips[0])


async def validate_scope(repo, assessment, asset, scanner):
    if assessment.get("status") == "cancelled":
        raise HTTPException(409, "Assessment is cancelled. Create a retry to start new work.")
    if asset["project_id"] != assessment["project_id"] or asset["id"] not in assessment["asset_ids"]:
        raise HTTPException(400, "Asset does not belong to this assessment")
    scope = await repo.get("scopes", asset["scope_id"])
    if scope["project_id"] != assessment["project_id"]:
        raise HTTPException(403, "Scope does not belong to this assessment's project")
    current = datetime.now(timezone.utc)
    if not scope.get("authorized") or not (datetime.fromisoformat(scope["starts_at"]) <= current <= datetime.fromisoformat(scope["ends_at"])):
        raise HTTPException(403, "Scope is not authorized or is outside its approved time window")
    if scanner not in scope["allowed_scanners"]:
        raise HTTPException(403, "Scanner is not permitted by the rules of engagement")
    if target_host(asset["target"]) != scope["host"]:
        raise HTTPException(403, "Target is outside the authorized scope")
    return scope


async def fetch_pinned(url, ip, max_bytes=1024 * 1024):
    p = urlsplit(url)
    port = p.port or (443 if p.scheme == "https" else 80)
    address = f"[{ip}]" if ":" in ip else ip
    dest = f"{p.scheme}://{address}:{port}{p.path or '/'}" + ("?" + p.query if p.query else "")
    async with httpx.AsyncClient(timeout=12, follow_redirects=False, trust_env=False) as client:
        async with client.stream("GET", dest, headers={"Host": p.netloc, "User-Agent": "VAPT-X/1.0 authorized-safe-check"}, extensions={"sni_hostname": p.hostname}) as response:
            chunks = bytearray()
            async for chunk in response.aiter_bytes():
                chunks.extend(chunk)
                if len(chunks) > max_bytes:
                    raise ValueError("Response exceeds the 1 MB safe-check limit")
            return response.status_code, response.headers, bytes(chunks)


def certificate(ip, host, port):
    context = ssl.create_default_context()
    with socket.create_connection((ip, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=host) as connection:
            cert = connection.getpeercert()
            return {"expires_at": datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc).isoformat(), "protocol": connection.version()}


async def safe_checks(asset, ip):
    training = asset["target"] == "training://local"
    url = os.environ["INTERNAL_API_URL"] + "/api/lab/target" if training else asset["target"]
    if "://" not in url:
        url = "https://" + url
    parsed = urlsplit(url)
    rows, checks = [], []
    checks.append({"name": "DNS resolution", "status": "skipped" if training else "passed", "detail": "Managed training target (DNS not applicable)" if training else f"Pinned public address: {ip}"})
    status, headers, body = await fetch_pinned(url, ip)
    checks.append({"name": "HTTP response", "status": "passed", "detail": f"HTTP {status}; {len(body)} bytes; redirects are not followed"})
    if status >= 400 or 300 <= status < 400:
        checks.append({"name": "Header coverage", "status": "limited", "detail": "Only this response was inspected; destination redirects and protected pages were not scanned."})
    required = {"content-security-policy": "medium", "x-content-type-options": "low", "referrer-policy": "low"}
    if parsed.scheme == "https":
        required["strict-transport-security"] = "medium"
    for header, severity in required.items():
        present = header in headers
        checks.append({"name": header, "status": "passed" if present else "failed", "detail": headers.get(header, "Header absent from observed response")})
        if not present:
            rows.append(finding(f"Missing {header} header", severity, f"header:{header}", asset["target"], f"GET {asset['target']} returned HTTP {status} without {header}. Observed response headers: {dict((k,v) for k,v in headers.items() if k != 'set-cookie')}", f"Configure {header} with a policy appropriate to your application, then retest."))
    cookies = headers.get_list("set-cookie")
    for index, cookie in enumerate(cookies):
        flags = cookie.lower().split(";")[1:]
        missing = [flag for flag in ("secure", "httponly") if not any(x.strip() == flag for x in flags)]
        if missing:
            rows.append(finding("Cookie missing protective flags", "low", f"cookie:{index}", asset["target"], f"Cookie {cookie.split('=', 1)[0]} missing {', '.join(missing)}. Cookie values redacted.", "Use Secure and HttpOnly on session cookies and set an appropriate SameSite policy."))
    checks.append({"name": "Cookie flags", "status": "failed" if any(r["rule_id"].startswith("cookie:") for r in rows) else "passed" if cookies else "skipped", "detail": f"Inspected {len(cookies)} Set-Cookie headers; values not retained"})
    security_url = os.environ["INTERNAL_API_URL"] + "/api/lab/security.txt" if training else f"{parsed.scheme}://{parsed.netloc}/.well-known/security.txt"
    sec_status, _, sec_body = await fetch_pinned(security_url, ip)
    valid_security = sec_status == 200 and b"Contact:" in sec_body
    checks.append({"name": "security.txt", "status": "passed" if valid_security else "failed", "detail": f"HTTP {sec_status}; Contact field {'found' if valid_security else 'not found'}"})
    if not valid_security:
        rows.append(finding("Security contact policy not found", "info", "security-txt", asset["target"], f"security.txt returned HTTP {sec_status} without a valid Contact field.", "Publish a security.txt contact policy following RFC 9116."))
    if parsed.scheme == "https":
        cert = await asyncio.to_thread(certificate, ip, parsed.hostname, parsed.port or 443)
        checks.append({"name": "TLS certificate", "status": "passed", "detail": str(cert)})
        days = (datetime.fromisoformat(cert["expires_at"]) - datetime.now(timezone.utc)).days
        if days < 30:
            rows.append(finding("TLS certificate expires soon", "medium", "tls:expiry", asset["target"], f"Certificate expires in {days} days: {cert['expires_at']}", "Renew and install the certificate before expiry."))
    else:
        checks.append({"name": "TLS certificate", "status": "skipped", "detail": "HTTP target; no TLS endpoint assessed"})
    return rows, checks


async def nmap_scan(asset, ip):
    binary = os.environ["NMAP_BINARY"]
    if not shutil.which(binary):
        raise ValueError("Nmap is not installed in this environment. Import a real Nmap XML report instead.")
    ports = str(urlsplit(os.environ["INTERNAL_API_URL"]).port) if asset["target"] == "training://local" else "80,443,8080,8443"
    args = [binary, "-sT", "-Pn", "-n", "-T2", "--max-retries", "1", "--host-timeout", "45s", "-p", ports, "-oX", "-", ip]
    process = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        output, error = await asyncio.wait_for(process.communicate(), timeout=60)
    except (asyncio.TimeoutError, asyncio.CancelledError) as exc:
        if process.returncode is None:
            process.kill()
        await process.wait()
        if isinstance(exc, asyncio.CancelledError):
            raise
        raise ValueError("Nmap exceeded the 60 second execution limit")
    if process.returncode:
        raise ValueError(error.decode(errors="replace")[:500])
    text = output.decode(errors="replace")
    return parse_report("nmap", text), [{"name": "Nmap TCP connect", "status": "passed", "detail": f"Scanned pinned address {ip}, ports {ports}. No scripts, UDP, exploits or service brute force."}], text


async def store_findings(repo, assessment, asset, job, rows):
    count = 0
    for row in rows[:2000]:
        fingerprint = sha256_hex(f"{asset['id']}:{job['scanner']}:{row['rule_id']}:{row['target']}".encode())
        existing = await repo.list("findings", {"assessment_id": assessment["id"], "fingerprint": fingerprint})
        if existing:
            continue
        await repo.add("findings", {**row, "fingerprint": fingerprint, "assessment_id": assessment["id"], "project_id": assessment["project_id"], "asset_id": asset["id"], "job_id": job["id"], "scanner": job["scanner"], "source": job["source"], "status": "open", "verification": "imported-unverified" if job["source"] == "import" else "observed", "notes": ""}, log=False)
        count += 1
    return count


async def run_job(ctx, job_id):
    repo = Repository(ctx)
    key = (ctx.org_id, job_id)
    try:
        async with JOB_LOCK:
            job = await repo.get("jobs", job_id)
            if job["status"] != "queued":
                return
            membership = await db.memberships.find_one({"org_id": ctx.org_id, "user_id": ctx.uid})
            if not membership:
                raise ValueError("Organization access was revoked")
            ctx.role = membership["role"]
            ctx.require("scan")
            assessment = await repo.get("assessments", job["assessment_id"])
            asset = await repo.get("assets", job["asset_id"])
            await validate_scope(repo, assessment, asset, job["scanner"])
            await repo.update("jobs", job_id, {"status": "running", "started_at": iso(), "logs": ["Authorization and approved time window validated.", "Resolving and pinning target address."]}, log=False)
            async def execute():
                ip = "127.0.0.1" if asset["target"] == "training://local" else await resolve_public(target_host(asset["target"]))
                if job["scanner"] == "safe":
                    rows, checks = await safe_checks(asset, ip)
                    return rows, checks, None, ip
                rows, checks, raw = await nmap_scan(asset, ip)
                return rows, checks, raw, ip
            task = asyncio.create_task(execute())
            ACTIVE_CHECKS[key] = task
        rows, checks, raw, ip = await task
        async with JOB_LOCK:
            # Cancellation and finding persistence are serialized. A cancelled
            # assessment can never be restored to review by a late result.
            assessment = await repo.get("assessments", job["assessment_id"])
            if assessment.get("status") == "cancelled":
                await repo.update("jobs", job_id, {"status": "cancelled", "finished_at": iso()}, log=False)
                return
            count = await store_findings(repo, assessment, asset, job, rows)
            await repo.update("jobs", job_id, {"status": "completed", "finished_at": iso(), "checks": checks, "finding_count": count, "raw_output": raw, "logs": ["Authorization verified.", f"Connected to pinned address {ip}.", f"Completed {len(checks)} checks. Stored {count} new observations."]}, log=False)
            await repo.update("assessments", assessment["id"], {"status": "review"}, log=False)
        await audit(ctx, "scan.completed", "jobs", job_id, {"findings": count})
    except asyncio.CancelledError:
        current = await repo.get("jobs", job_id)
        status = "cancelled" if current.get("status") == "cancelling" else "interrupted"
        await repo.update("jobs", job_id, {"status": status, "finished_at": iso()}, log=False)
        await audit(ctx, "scan." + status, "jobs", job_id)
        if status == "interrupted":
            raise
    except Exception as exc:
        detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
        async with JOB_LOCK:
            current = await repo.get("jobs", job_id)
            status = "cancelled" if current.get("status") in {"cancelling", "cancelled"} else "failed"
            await repo.update("jobs", job_id, {"status": status, "error": str(detail)[:1000], "finished_at": iso()}, log=False)
        await audit(ctx, "scan." + status, "jobs", job_id, {"error": str(detail)[:300]})
    finally:
        ACTIVE_CHECKS.pop(key, None)
