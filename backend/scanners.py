import asyncio
import ipaddress
import os
import shutil
import socket
import ssl
import uuid
from datetime import datetime, timezone, timedelta
from urllib.parse import urlsplit

import httpx
from fastapi import HTTPException
from pymongo import ReturnDocument
from core import db, Ctx, clean, iso, audit, sha256_hex
from repository import Repository
from importers import finding, parse_report
from distributed_locks import distributed_lock

JOB_LOCK = asyncio.Lock()
ACTIVE_CHECKS = {}  # Single-worker managed child tasks, keyed by organization/job.
SCAN_LEASE_SECONDS = 30
SCAN_WORKER_POLL_SECONDS = 1

SCANNERS = {"safe", "nmap", "nuclei", "semgrep", "trivy", "zap", "gitleaks", "checkov", "prowler", "mobsf", "openapi", "cyclonedx", "spdx"}


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
        await repo.add("findings", {**row, "scanner_severity": row["severity"], "fingerprint": fingerprint, "assessment_id": assessment["id"], "project_id": assessment["project_id"], "asset_id": asset["id"], "job_id": job["id"], "scanner": job["scanner"], "source": job["source"], "status": "open", "verification": "imported-unverified" if job["source"] == "import" else "observed", "notes": ""}, log=False)
        count += 1
    return count


async def execution_credentials(ctx):
    """Recheck the initiating credential before any target resolution or execution."""
    if ctx.user.get('_service_identity_id'):
        credential=await db.service_credentials.find_one({'_id':ctx.service_credential_id,
            'org_id':ctx.org_id,'identity_id':ctx.service_identity_id,'revoked':False,'expires_at':{'$gt':iso()}})
        identity=await db.service_identities.find_one({'_id':ctx.service_identity_id,'org_id':ctx.org_id,'active':True})
        if not credential or not identity or identity.get('owner_user_id')!=ctx.service_owner_id:
            raise ValueError('Service identity or credential changed before execution')
        owner=await db.memberships.find_one({'org_id':ctx.org_id,'user_id':identity['owner_user_id']})
        owner_user=await db.users.find_one({'_id':identity['owner_user_id'],'disabled':{'$ne':True}})
        if not owner or not owner_user:raise ValueError('Service identity owner access was revoked before execution')
        identity_projects=identity.get('project_ids',[]);credential_projects=credential.get('project_ids',[])
        if not isinstance(identity_projects,list) or not isinstance(credential_projects,list):raise ValueError('Service identity project policy is invalid')
        ctx.project_ids=sorted(set(identity_projects).intersection(credential_projects))
        ctx.service_permissions=frozenset(identity.get('permissions',[]))
        ctx.scopes=credential.get('scopes',[])
        ctx.user={**ctx.user,'_token_project_ids':credential_projects,'_token_scopes':ctx.scopes}
        return
    user = await db.users.find_one({"_id": ctx.uid})
    epoch = ctx.user.get("credential_version", 0)
    if not user or user.get("disabled") or user.get("credential_version", 0) != epoch:
        raise ValueError("Initiator credentials changed before execution")
    if ctx.user.get("_api_token_id"):
        token = await db.api_tokens.find_one({"_id": ctx.user["_api_token_id"],
            "org_id": ctx.org_id, "created_by": ctx.uid, "revoked": False,
            "expires_at": {"$gt": iso()}, "credential_version": epoch})
        if not token:
            raise ValueError("API token revoked or expired before execution")
        if token.get("membership_id") != ctx.user.get("_token_membership_id"):
            raise ValueError("API token membership changed before execution")
        ctx.user = {**ctx.user, "_token_project_ids": token.get("project_ids")}
        ctx.scopes = token["scopes"]
    else:
        session = await db.sessions.find_one({"_id": ctx.user.get("_sid"),
            "user_id": ctx.uid, "revoked": False, "expires_at": {"$gt": iso()}})
        if not session or session.get("credential_version", 0) != epoch:
            raise ValueError("Session revoked or expired before execution")


def execution_actor(ctx):
    """Persist only references needed to revalidate the initiator after a restart."""
    user=ctx.user
    common={'org_id':ctx.org_id,'user_id':ctx.uid}
    if user.get('_service_identity_id'):
        return {**common,'kind':'service','identity_id':user['_service_identity_id'],
            'credential_id':user['_service_credential_id'],'owner_id':user['_service_owner_id']}
    if user.get('_api_token_id'):
        return {**common,'kind':'api_token','token_id':user['_api_token_id'],
            'membership_id':user.get('_token_membership_id')}
    return {**common,'kind':'session','session_id':user.get('_sid'),
        'credential_version':user.get('credential_version',0),'membership_id':ctx.membership_id}


async def execution_context(actor):
    """Rebuild a minimal context from durable identifiers; run_job rechecks authority."""
    if not isinstance(actor,dict) or not actor.get('org_id') or not actor.get('kind'):
        raise ValueError('Queued scan has no valid execution authority reference')
    org_id=actor['org_id']
    if actor['kind']=='service':
        identity=await db.service_identities.find_one({'_id':actor.get('identity_id'),'org_id':org_id})
        if not identity:raise ValueError('Service identity no longer exists')
        user={'id':identity['_id'],'name':identity['name'],'email':f"{identity['name']} (service identity)",
            '_service_identity_id':identity['_id'],'_service_credential_id':actor.get('credential_id'),
            '_service_owner_id':actor.get('owner_id'),'_token_org':org_id,
            '_token_scopes':[],'_token_project_ids':[]}
        return Ctx(user,org_id,'service')
    user_doc=await db.users.find_one({'_id':actor.get('user_id'),'disabled':{'$ne':True}})
    if not user_doc:raise ValueError('Scan initiator is unavailable')
    user=clean(user_doc)
    if actor['kind']=='session':
        user['_sid']=actor.get('session_id')
        user['credential_version']=actor.get('credential_version',0)
    elif actor['kind']=='api_token':
        token=await db.api_tokens.find_one({'_id':actor.get('token_id'),'org_id':org_id})
        if not token:raise ValueError('Scan API token is unavailable')
        user.update(_api_token_id=actor['token_id'],_token_org=org_id,
            _token_membership_id=actor.get('membership_id'),_token_scopes=token.get('scopes',[]),
            _token_project_ids=token.get('project_ids'))
    else:
        raise ValueError('Queued scan initiator type is not supported')
    membership=await db.memberships.find_one({'org_id':org_id,'user_id':actor.get('user_id')})
    if not membership:raise ValueError('Scan initiator organization access is unavailable')
    from project_access import effective_projects
    ctx=Ctx(user,org_id,membership.get('role','viewer'))
    ctx.membership_id=actor.get('membership_id')
    ctx.project_ids=effective_projects(membership,user)
    return ctx


async def recover_expired_scan_leases():
    """Mark abandoned running work interrupted; never replay a partially executed scan."""
    now_value=iso()
    cursor=db.jobs.find({'status':{'$in':['running','cancelling']},
        '_worker_lease_expires_at':{'$lte':now_value}},
        projection={'_id':1,'org_id':1,'assessment_id':1,'status':1})
    async for candidate in cursor:
        scope=f'{candidate.get("org_id","")}:{candidate.get("assessment_id",candidate["_id"])}'
        async with distributed_lock('scan-state',scope):
            if candidate['status']=='running':
                fields={'status':'interrupted','error':'Worker lease expired; create a new scan to continue.',
                    'finished_at':now_value}
            else:
                fields={'status':'cancelled','finished_at':now_value}
            await db.jobs.update_one({'_id':candidate['_id'],'org_id':candidate.get('org_id'),
                'status':candidate['status'],'_worker_lease_expires_at':{'$lte':now_value}},
                {'$set':fields,'$unset':{'_worker_lease_owner':'','_worker_lease_expires_at':''}})


async def claim_queued_scan(worker_id):
    now_value=iso()
    lease_until=iso(datetime.now(timezone.utc)+timedelta(seconds=SCAN_LEASE_SECONDS))
    return await db.jobs.find_one_and_update(
        {'status':'queued','$or':[{'_worker_lease_expires_at':{'$exists':False}},
            {'_worker_lease_expires_at':{'$lte':now_value}}]},
        {'$set':{'_worker_lease_owner':worker_id,'_worker_lease_expires_at':lease_until}},
        sort=[('created_at',1),('_id',1)],return_document=ReturnDocument.AFTER)


async def scan_worker_loop(worker_id=None):
    worker_id=worker_id or str(uuid.uuid4())
    while True:
        try:
            await recover_expired_scan_leases()
            job=await claim_queued_scan(worker_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            await asyncio.sleep(SCAN_WORKER_POLL_SECONDS)
            continue
        if not job:
            await asyncio.sleep(SCAN_WORKER_POLL_SECONDS)
            continue
        try:
            ctx=await execution_context(job.get('_execution_actor'))
            await run_job(ctx,str(job['_id']),worker_id=worker_id)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            now_value=iso()
            await db.jobs.update_one({'_id':job['_id'],'_worker_lease_owner':worker_id,
                'status':{'$in':['queued','running']}}, {'$set':{'status':'failed',
                    'error':str(exc)[:1000],'finished_at':now_value},
                    '$unset':{'_worker_lease_owner':'','_worker_lease_expires_at':''}})


async def maintain_scan_lease(job_id,worker_id,task_holder):
    while True:
        await asyncio.sleep(5)
        lease_until=iso(datetime.now(timezone.utc)+timedelta(seconds=SCAN_LEASE_SECONDS))
        job=await db.jobs.find_one_and_update(
            {'_id':job_id,'_worker_lease_owner':worker_id,
                'status':{'$in':['queued','running','cancelling']}},
            {'$set':{'_worker_lease_expires_at':lease_until}},
            projection={'status':1},return_document=ReturnDocument.AFTER)
        if not job or job.get('status')=='cancelling':
            task=task_holder.get('task')
            if task and not task.done():task.cancel()
            return


async def run_job(ctx, job_id, worker_id=None):
    repo = Repository(ctx)
    job = await repo.get("jobs", job_id)
    key = (ctx.org_id, job_id)
    lease_task=None
    try:
        async with distributed_lock('scan-state',f'{ctx.org_id}:{job.get("assessment_id",job_id)}'):
            job = await repo.get("jobs", job_id)
            if job["status"] != "queued":
                return
            if worker_id and not await db.jobs.find_one({'_id':job_id,'_worker_lease_owner':worker_id,'status':'queued'}):
                return
            await execution_credentials(ctx)
            if ctx.user.get('_service_identity_id'):
                allowed=ctx.project_ids
                if job.get('project_id') not in allowed:raise ValueError('Service identity project access was revoked before execution')
            else:
                membership = await db.memberships.find_one({"org_id": ctx.org_id, "user_id": ctx.uid})
                if not membership:
                    raise ValueError("Organization access was revoked")
                from project_access import effective_projects
                allowed=effective_projects(membership,ctx.user)
                if allowed is not None and job.get('project_id') not in allowed:raise ValueError('Project access was revoked before execution')
                if ctx.membership_id and str(membership.get('_id'))!=ctx.membership_id:raise ValueError('Organization membership changed before execution')
                ctx.project_ids=allowed
                ctx.role = membership["role"]
                ctx.custom_permissions=frozenset()
                if ctx.role=='custom':
                    from custom_roles import role_permissions
                    permissions=await role_permissions(ctx.org_id,membership.get('custom_role_id'))
                    if permissions is None:raise ValueError('Custom role was removed or is unavailable before execution')
                    ctx.custom_permissions=permissions
            ctx.require("scan")
            assessment = await repo.get("assessments", job["assessment_id"])
            asset = await repo.get("assets", job["asset_id"])
            await validate_scope(repo, assessment, asset, job["scanner"])
            fields={"status": "running", "started_at": iso(), "logs": ["Authorization and approved time window validated.", "Resolving and pinning target address."]}
            if worker_id:
                claim_filter={'_id':job_id,'org_id':ctx.org_id,'status':'queued','_worker_lease_owner':worker_id}
                started=await db.jobs.update_one(claim_filter,{'$set':fields})
                if started.matched_count!=1:return
            else:
                await repo.update("jobs", job_id, fields, log=False)
            async def execute():
                ip = "127.0.0.1" if asset["target"] == "training://local" else await resolve_public(target_host(asset["target"]))
                if job["scanner"] == "safe":
                    rows, checks = await safe_checks(asset, ip)
                    return rows, checks, None, ip
                rows, checks, raw = await nmap_scan(asset, ip)
                return rows, checks, raw, ip
            task = asyncio.create_task(execute())
            ACTIVE_CHECKS[key] = task
            task_holder={'task':task}
            lease_task=asyncio.create_task(maintain_scan_lease(job_id,worker_id,task_holder)) if worker_id else None
        rows, checks, raw, ip = await task
        async with distributed_lock('scan-state',f'{ctx.org_id}:{job.get("assessment_id",job_id)}'):
            # Cancellation and finding persistence are serialized. A cancelled
            # assessment can never be restored to review by a late result.
            assessment = await repo.get("assessments", job["assessment_id"])
            if assessment.get("status") == "cancelled":
                if worker_id:
                    await db.jobs.update_one({'_id':job_id,'org_id':ctx.org_id,
                        '_worker_lease_owner':worker_id,'status':{'$in':['queued','running','cancelling']}},
                        {'$set':{'status':'cancelled','finished_at':iso()}})
                else:
                    await repo.update("jobs", job_id, {"status": "cancelled", "finished_at": iso()}, log=False)
                return
            if worker_id:
                owned=await db.jobs.find_one({'_id':job_id,'org_id':ctx.org_id,
                    '_worker_lease_owner':worker_id,'status':'running'})
                if not owned:return
            count = await store_findings(repo, assessment, asset, job, rows)
            fields={"status": "completed", "finished_at": iso(), "checks": checks,
                "finding_count": count, "raw_output": raw, "logs": ["Authorization verified.",
                    f"Connected to pinned address {ip}.", f"Completed {len(checks)} checks. Stored {count} new observations."]}
            if worker_id:
                saved=await db.jobs.update_one({'_id':job_id,'org_id':ctx.org_id,
                    '_worker_lease_owner':worker_id,'status':'running'}, {'$set':fields})
                if saved.matched_count!=1:return
                await db.assessments.update_one({'_id':assessment['id'],'org_id':ctx.org_id,
                    'status':{'$ne':'cancelled'}},{'$set':{'status':'review'}})
            else:
                await repo.update("jobs", job_id, fields, log=False)
                await repo.update("assessments", assessment["id"], {"status": "review"}, log=False)
        await audit(ctx, "scan.completed", "jobs", job_id, {"findings": count})
    except asyncio.CancelledError:
        async with distributed_lock('scan-state',f'{ctx.org_id}:{job.get("assessment_id",job_id)}'):
            current = await repo.get("jobs", job_id)
            status = "cancelled" if current.get("status") in {"cancelling","cancelled"} else "interrupted"
            if worker_id:
                await db.jobs.update_one({'_id':job_id,'org_id':ctx.org_id,'_worker_lease_owner':worker_id,
                    'status':{'$in':['queued','running','cancelling']}},
                    {'$set':{'status':status,'finished_at':iso()}})
            else:
                await repo.update("jobs", job_id, {"status": status, "finished_at": iso()}, log=False)
        await audit(ctx, "scan." + status, "jobs", job_id)
        if status == "interrupted":
            raise
    except Exception as exc:
        detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
        async with distributed_lock('scan-state',f'{ctx.org_id}:{job.get("assessment_id",job_id)}'):
            current = await repo.get("jobs", job_id)
            status = "cancelled" if current.get("status") in {"cancelling", "cancelled"} else "failed"
            if worker_id:
                await db.jobs.update_one({'_id':job_id,'org_id':ctx.org_id,'_worker_lease_owner':worker_id,
                    'status':{'$in':['queued','running','cancelling']}},
                    {'$set':{'status':status,'error':str(detail)[:1000],'finished_at':iso()}})
            else:
                await repo.update("jobs", job_id, {"status": status, "error": str(detail)[:1000], "finished_at": iso()}, log=False)
        await audit(ctx, "scan." + status, "jobs", job_id, {"error": str(detail)[:300]})
    finally:
        if lease_task:
            lease_task.cancel()
            await asyncio.gather(lease_task,return_exceptions=True)
        if worker_id:
            await db.jobs.update_one({'_id':job_id,'_worker_lease_owner':worker_id},
                {'$unset':{'_worker_lease_owner':'','_worker_lease_expires_at':''}})
        ACTIVE_CHECKS.pop(key, None)
