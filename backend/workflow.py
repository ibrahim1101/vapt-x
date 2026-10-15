import asyncio
import re
import os
import shutil
from importlib.util import find_spec
from datetime import date, datetime, timezone
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from pydantic import BaseModel, Field, field_validator
from core import get_ctx, iso, audit, db, DomainDocument
from pymongo import ReturnDocument
from pymongo.errors import PyMongoError
from repository import Repository
from scanners import target_host, validate_scope, run_job, SCANNERS, store_findings, JOB_LOCK, ACTIVE_CHECKS
from importers import parse_report

router = APIRouter(prefix="/api")
SCAN_LOCK = JOB_LOCK
ASSET_IMPORT_LOCK = asyncio.Lock()


class ProjectInput(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    description: str = Field(default="", max_length=3000)
    template_id: str | None = Field(default=None, max_length=100)


class ProjectTemplateInput(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    description: str = Field(default="", max_length=3000)


class ProjectUpdate(ProjectInput):
    status: Literal["active", "archived"] = "active"
    owner: str = Field(default="", max_length=150)

    @field_validator("name")
    @classmethod
    def meaningful_name(cls, value):
        if len(value.strip()) < 2:
            raise ValueError("Provide a project name of at least two characters")
        return value.strip()


class ScopeInput(BaseModel):
    project_id: str
    target: str = Field(max_length=500)
    authorization_reference: str = Field(min_length=5, max_length=500)
    authorized: bool
    starts_at: datetime
    ends_at: datetime
    allowed_scanners: list[str] = Field(min_length=1)

    @field_validator("starts_at", "ends_at")
    @classmethod
    def aware(cls, value):
        if value.tzinfo is None:
            raise ValueError("Include a timezone in the authorization window")
        return value.astimezone(timezone.utc)


class ScopeRevocationInput(BaseModel):
    reason: str = Field(min_length=5, max_length=500)

    @field_validator("reason")
    @classmethod
    def meaningful_reason(cls, value):
        if len(value.strip()) < 5:
            raise ValueError("Provide a reason of at least five non-whitespace characters")
        return value.strip()


class AssetInput(BaseModel):
    project_id: str
    scope_id: str
    name: str = Field(min_length=2, max_length=120)
    target: str = Field(max_length=500)
    kind: Literal["web", "host", "repository", "container"] = "web"


class AssetUpdate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    owner: str = Field(default="", max_length=150)
    criticality: Literal["critical", "high", "medium", "low"] = "medium"
    tags: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("name")
    @classmethod
    def meaningful_name(cls, value):
        if len(value.strip()) < 2:
            raise ValueError("Provide an asset name of at least two characters")
        return value.strip()

    @field_validator("tags")
    @classmethod
    def normalized_tags(cls, values):
        result = []
        for value in values:
            value = value.strip()
            if not value or len(value) > 50:
                raise ValueError("Tags must contain between 1 and 50 characters")
            if value not in result:
                result.append(value)
        return result


class BulkAssetInput(BaseModel):
    assets: list[AssetInput] = Field(min_length=1, max_length=100)


class AssessmentInput(BaseModel):
    project_id: str
    name: str = Field(min_length=2, max_length=120)
    asset_ids: list[str] = Field(min_length=1, max_length=20)


class ScanInput(BaseModel):
    assessment_id: str
    asset_id: str
    scanner: Literal["safe", "nmap"]


class ImportInput(BaseModel):
    assessment_id: str
    asset_id: str
    scanner: Literal["nmap", "nuclei", "semgrep", "trivy", "zap", "gitleaks", "checkov"]
    content: str = Field(min_length=2, max_length=2_000_000)


class TriageInput(BaseModel):
    owner: str | None = Field(default=None, max_length=150)
    status: Literal["open", "confirmed", "false_positive", "accepted_risk", "resolved"]
    notes: str | None = Field(default="", max_length=5000)


def valid_due_date(value):
    if not value:
        return ""
    try:
        return date.fromisoformat(value).isoformat()
    except ValueError:
        raise ValueError("Due date must be a calendar date (YYYY-MM-DD)")


class BulkTriageInput(BaseModel):
    finding_ids: list[str] = Field(min_length=1, max_length=100)
    status: Literal["open", "confirmed", "false_positive", "accepted_risk", "resolved"]
    notes: str | None = Field(default=None, max_length=5000)
    owner: str | None = Field(default=None, max_length=150)


class TaskInput(BaseModel):
    finding_id: str
    title: str = Field(min_length=2, max_length=200)
    assignee: str = Field(default="", max_length=150)
    due_date: str = Field(default="", max_length=30)

    @field_validator("due_date")
    @classmethod
    def calendar_date(cls, value):
        return valid_due_date(value)


class TaskUpdate(BaseModel):
    status: Literal["todo", "in_progress", "done"] | None = None
    title: str | None = Field(default=None, min_length=2, max_length=200)
    assignee: str | None = Field(default=None, max_length=150)
    due_date: str | None = Field(default=None, max_length=30)
    progress: int | None = Field(default=None, ge=0, le=100)

    @field_validator("due_date")
    @classmethod
    def calendar_date(cls, value):
        return valid_due_date(value) if value is not None else value


@router.get("/capabilities")
async def capabilities(ctx=Depends(get_ctx)):
    ctx.require("read")
    return {"safe": True, "nmap": bool(shutil.which(os.environ["NMAP_BINARY"])), "inventory_imports": ["openapi", "cyclonedx", "spdx"], "imports": ["nmap", "nuclei", "semgrep", "trivy", "zap", "gitleaks", "checkov"], "ai": bool(os.environ.get("ANTHROPIC_API_KEY")) and find_spec("anthropic") is not None, "limitations": ["Nmap uses TCP connect on four web ports only; no exploit scripts.", "Remote private networks are blocked. Only the managed training target may use loopback.", "Imports are scanner-authored, unverified evidence, not a fresh scan.", "Interrupted jobs are marked interrupted after a worker restart; re-run manually."]}


@router.get("/workspace")
async def workspace(project_id: str | None = None, ctx=Depends(get_ctx)):
    ctx.require("read")
    repo = Repository(ctx)
    filters = {"project_id": project_id} if project_id else {}
    if project_id:
        await repo.get("projects", project_id)
    data = {"truncated_collections": []}
    async def visible_rows(collection, query=None):
        rows = await repo.list(collection, query, limit=1001)
        if len(rows) > 1000:
            data["truncated_collections"].append(collection)
        return rows[:1000]
    data["projects"] = await visible_rows("projects")
    for collection in ("scopes", "assets", "assessments", "jobs", "findings", "tasks", "evidence", "reports"):
        data[collection] = await visible_rows(collection, filters)
    for job in data["jobs"]:
        job.pop("raw_output", None)
    data["audit"] = await repo.list("audit_events", limit=100)
    data["role"] = ctx.role
    return data


@router.get("/findings")
async def list_findings(
    project_id: str | None = None,
    assessment_id: str | None = None,
    search: str = Query(default="", max_length=120),
    severity: Literal["critical", "high", "medium", "low", "info"] | None = None,
    status: Literal["open", "confirmed", "false_positive", "accepted_risk", "resolved"] | None = None,
    scanner: str | None = Query(default=None, max_length=50),
    offset: int = Query(default=0, ge=0, le=1_000_000),
    limit: int = Query(default=25, ge=1, le=100),
    ctx=Depends(get_ctx),
):
    ctx.require("read")
    repo = Repository(ctx)
    filters = {}
    if project_id:
        await repo.get("projects", project_id)
        filters["project_id"] = project_id
    if assessment_id:
        assessment = await repo.get("assessments", assessment_id)
        if project_id and assessment["project_id"] != project_id:
            raise HTTPException(404, "Resource not found")
        filters["assessment_id"] = assessment_id
    for key, value in (("severity", severity), ("status", status), ("scanner", scanner)):
        if value:
            filters[key] = value
    if search.strip():
        expression = {"$regex": re.escape(search.strip()), "$options": "i"}
        filters["$or"] = [{field: expression} for field in ("title", "target", "description")]
    return await repo.page("findings", filters, offset=offset, limit=limit)


@router.post("/projects")
async def create_project(body: ProjectInput, ctx=Depends(get_ctx)):
    ctx.require("write")
    repo = Repository(ctx)
    fields = body.model_dump()
    if body.template_id:
        template = await repo.get("project_templates", body.template_id)
        if not fields["description"]:
            fields["description"] = template["description"]
    return await repo.add("projects", {**fields, "status": "active"})


@router.get("/project-templates")
async def list_project_templates(ctx=Depends(get_ctx)):
    ctx.require("read")
    return await Repository(ctx).complete_list("project_templates", max_rows=500)


@router.post("/project-templates")
async def create_project_template(body: ProjectTemplateInput, ctx=Depends(get_ctx)):
    ctx.require("write")
    return await Repository(ctx).add("project_templates", body.model_dump())


@router.patch("/projects/{project_id}")
async def update_project(project_id: str, body: ProjectUpdate, ctx=Depends(get_ctx)):
    ctx.require("write")
    return await Repository(ctx).update("projects", project_id, body.model_dump(exclude={"template_id"}))


@router.post("/scopes")
async def create_scope(body: ScopeInput, ctx=Depends(get_ctx)):
    ctx.require("authorize")
    repo = Repository(ctx)
    await repo.get("projects", body.project_id)
    try:
        host = target_host(body.target)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    if body.ends_at <= body.starts_at:
        raise HTTPException(422, "Authorization end must follow the start")
    if not set(body.allowed_scanners) <= SCANNERS:
        raise HTTPException(422, "Unsupported scanner permission")
    return await repo.add("scopes", {**body.model_dump(mode="json"), "host": host})


@router.post("/scopes/{scope_id}/revoke")
async def revoke_scope(scope_id: str, body: ScopeRevocationInput, ctx=Depends(get_ctx)):
    ctx.require("authorize")
    repo = Repository(ctx)
    scope = await repo.get("scopes", scope_id)
    if not scope.get("authorized"):
        return scope
    result = await repo.update("scopes", scope_id, {"authorized": False,
        "revoked_at": iso(), "revoked_by": ctx.uid, "revocation_reason": body.reason})
    await audit(ctx, "scope.revoked", "scopes", scope_id, {"reason": body.reason})
    return result


@router.post("/assets")
async def create_asset(body: AssetInput, ctx=Depends(get_ctx)):
    ctx.require("write")
    repo = Repository(ctx)
    await repo.get("projects", body.project_id)
    scope = await repo.get("scopes", body.scope_id)
    try:
        host = target_host(body.target)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    if scope["project_id"] != body.project_id or host != scope["host"]:
        raise HTTPException(403, "Asset is outside the project's exact authorized host scope")
    return await repo.add("assets", body.model_dump())


@router.post("/assets/bulk")
async def bulk_assets(body: BulkAssetInput, ctx=Depends(get_ctx)):
    ctx.require("write")
    repo = Repository(ctx)
    # Preflight every relationship before writing any row. Registration never
    # grants scan permission, extends scope windows or changes existing assets.
    for row in body.assets:
        await repo.get("projects", row.project_id)
        scope = await repo.get("scopes", row.scope_id)
        try:
            host = target_host(row.target)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        if scope["project_id"] != row.project_id or host != scope["host"]:
            raise HTTPException(403, "Batch contains an asset outside its project's exact host scope")
    results = []
    async with ASSET_IMPORT_LOCK:
        for index, row in enumerate(body.assets):
            try:
                existing = await repo.list("assets", {"project_id": row.project_id,
                    "scope_id": row.scope_id, "target": row.target}, limit=1)
                if existing:
                    results.append({"index": index, "status": "duplicate", "id": existing[0]["id"]})
                else:
                    asset = await repo.add("assets", row.model_dump())
                    results.append({"index": index, "status": "created", "id": asset["id"]})
            except PyMongoError:
                results.append({"index": index, "status": "failed", "error": "Storage unavailable; retry this row"})
    return {"results": results, **{status: sum(row["status"] == status for row in results)
            for status in ("created", "duplicate", "failed")}}


@router.get("/assets")
async def list_assets(
    project_id: str | None = None,
    search: str = Query(default="", max_length=120),
    criticality: Literal["critical", "high", "medium", "low"] | None = None,
    offset: int = Query(default=0, ge=0, le=1_000_000),
    limit: int = Query(default=25, ge=1, le=100),
    ctx=Depends(get_ctx),
):
    ctx.require("read")
    repo = Repository(ctx)
    filters = {}
    if project_id:
        await repo.get("projects", project_id)
        filters["project_id"] = project_id
    if criticality == "medium":
        filters["$and"] = [{"$or": [{"criticality": "medium"}, {"criticality": {"$exists": False}}]}]
    elif criticality:
        filters["criticality"] = criticality
    if search.strip():
        expression = {"$regex": re.escape(search.strip()), "$options": "i"}
        filters["$or"] = [{field: expression} for field in ("name", "target", "owner", "tags")]
    return await repo.page("assets", filters, offset=offset, limit=limit)


@router.get("/assets/{asset_id}/history")
async def asset_history(asset_id: str, ctx=Depends(get_ctx)):
    ctx.require("read")
    repo = Repository(ctx)
    await repo.get("assets", asset_id)
    events = await repo.list("audit_events", {"resource_type": "assets", "resource_id": asset_id}, limit=101)
    return {"events": events[:100], "has_more": len(events) > 100,
            "notice": "Latest 100 asset activity events. Audit records list changed fields, not previous values."}


@router.patch("/assets/{asset_id}")
async def update_asset(asset_id: str, body: AssetUpdate, ctx=Depends(get_ctx)):
    ctx.require("write")
    # Target, scope, project and kind stay immutable: historical observations keep
    # their original association. Register another asset for a different target.
    return await Repository(ctx).update("assets", asset_id, body.model_dump())


@router.post("/assessments")
async def create_assessment(body: AssessmentInput, ctx=Depends(get_ctx)):
    ctx.require("write")
    repo = Repository(ctx)
    await repo.get("projects", body.project_id)
    for aid in body.asset_ids:
        asset = await repo.get("assets", aid)
        if asset["project_id"] != body.project_id:
            raise HTTPException(400, "All assets must belong to this project")
    return await repo.add("assessments", {**body.model_dump(), "status": "draft", "baseline_id": None})


@router.post("/scans")
async def create_scan(body: ScanInput, background: BackgroundTasks, ctx=Depends(get_ctx)):
    ctx.require("scan")
    repo = Repository(ctx)
    assessment = await repo.get("assessments", body.assessment_id)
    asset = await repo.get("assets", body.asset_id)
    async with SCAN_LOCK:
        assessment = await repo.get("assessments", body.assessment_id)
        await validate_scope(repo, assessment, asset, body.scanner)
        active = await repo.list("jobs", {"status": {"$in": ["queued", "running", "cancelling"]}})
        if len(active) >= 2:
            raise HTTPException(429, "Two scans are already active in this organization")
        job = await repo.add("jobs", {**body.model_dump(), "project_id": assessment["project_id"], "status": "queued", "source": "execution", "logs": ["Queued for authorization verification"], "checks": [], "finding_count": 0})
    background.add_task(run_job, ctx, job["id"])
    return job


@router.post("/imports")
async def import_scan(body: ImportInput, ctx=Depends(get_ctx)):
    ctx.require("scan")
    repo = Repository(ctx)
    assessment = await repo.get("assessments", body.assessment_id)
    asset = await repo.get("assets", body.asset_id)
    await validate_scope(repo, assessment, asset, body.scanner)
    try:
        rows = parse_report(body.scanner, body.content)
        if len(rows) > 2000:
            raise ValueError("Maximum 2,000 findings per import")
    except Exception as exc:
        raise HTTPException(422, f"Cannot parse this {body.scanner} report: {str(exc)[:180]}")
    async with JOB_LOCK:
        assessment = await repo.get("assessments", body.assessment_id)
        await validate_scope(repo, assessment, asset, body.scanner)
        job = await repo.add("jobs", {"assessment_id": assessment["id"], "asset_id": asset["id"], "project_id": assessment["project_id"], "scanner": body.scanner, "source": "import", "status": "completed", "raw_output": "Raw report omitted to avoid retaining secret values or code blocks" if body.scanner in {"gitleaks", "checkov"} else body.content, "checks": [], "logs": ["Imported scanner-authored output. Not independently verified; asset association declared by uploader."], "finished_at": iso()})
        count = await store_findings(repo, assessment, asset, job, rows)
        await repo.update("assessments", assessment["id"], {"status": "review"}, log=False)
        return await repo.update("jobs", job["id"], {"finding_count": count}, log=False)


@router.get("/jobs/{job_id}")
async def get_job(job_id: str, ctx=Depends(get_ctx)):
    ctx.require("read")
    return await Repository(ctx).get("jobs", job_id)


@router.post("/findings/bulk-triage")
async def bulk_triage(body: BulkTriageInput, ctx=Depends(get_ctx)):
    ctx.require("triage")
    repo = Repository(ctx)
    ids = list(dict.fromkeys(body.finding_ids))
    # Validate the entire selected set before making any change.
    current = {oid: await repo.get("findings", oid) for oid in ids}
    results = []
    for oid in ids:
        try:
            await triage(oid, TriageInput(status=body.status,
                notes=body.notes,
                owner=body.owner), ctx)
            results.append({"id": oid, "status": "updated"})
        except HTTPException as exc:
            results.append({"id": oid, "status": "failed", "code": exc.status_code, "error": str(exc.detail)})
        except PyMongoError:
            results.append({"id": oid, "status": "failed", "code": 503, "error": "Storage unavailable; retry this finding"})
    return {"results": results, "updated": sum(row["status"] == "updated" for row in results),
            "failed": sum(row["status"] == "failed" for row in results)}


@router.patch("/findings/{finding_id}")
async def triage(finding_id: str, body: TriageInput, ctx=Depends(get_ctx)):
    ctx.require("triage")
    repo = Repository(ctx)
    current = await repo.get("findings", finding_id)
    previous_status = current.get("status", "open")
    previous_notes = current.get("notes", "")
    notes = previous_notes if body.notes is None else body.notes
    previous_owner = current.get("owner", "")
    owner = previous_owner if body.owner is None else body.owner
    if body.status == previous_status and notes == previous_notes and owner == previous_owner:
        return current
    timestamp = iso()
    event = {"previous_status": previous_status, "status": body.status,
             "previous_notes": previous_notes, "notes": notes,
             "actor_id": ctx.uid, "actor_email": ctx.user.get("email"),
             "created_at": timestamp}
    if body.owner is not None:
        event.update(previous_owner=previous_owner, owner=owner)
    # Compare the exact state read, including absent fields on legacy documents.
    # The counter additionally rejects ABA races where status/notes cycle back.
    expected = {key: current[key] if key in current else {"$exists": False}
                for key in ("status", "notes", "history_total")}
    if body.owner is not None:
        expected["owner"] = current["owner"] if "owner" in current else {"$exists": False}
    updated = await db.findings.find_one_and_update(
        repo.query({"_id": finding_id, **expected}),
        {"$set": {"status": body.status, "notes": notes, "updated_at": timestamp, **({"owner": owner} if body.owner is not None else {})},
         "$push": {"triage_history": {"$each": [event], "$slice": -100}},
         "$inc": {"history_total": 1}},
        return_document=ReturnDocument.AFTER,
    )
    if updated is None:
        raise HTTPException(409, "Finding changed during triage. Reload it and try again.")
    await audit(ctx, "finding.triaged", "findings", finding_id,
                {"previous_status": previous_status, "status": body.status})
    return DomainDocument.from_mongo(updated).model_dump()


@router.get("/findings/{finding_id}/history")
async def finding_history(finding_id: str, ctx=Depends(get_ctx)):
    ctx.require("read")
    item = await Repository(ctx).get("findings", finding_id)
    events = item.get("triage_history", [])[-100:]
    total = item.get("history_total", len(events))
    return {"events": events, "has_more": total > len(events), "total": total}


@router.post("/tasks")
async def create_task(body: TaskInput, ctx=Depends(get_ctx)):
    ctx.require("remediate")
    repo = Repository(ctx)
    finding = await repo.get("findings", body.finding_id)
    return await repo.add("tasks", {**body.model_dump(), "project_id": finding["project_id"], "status": "todo", "progress": 0, "completed_at": None})


@router.patch("/tasks/{task_id}")
async def update_task(task_id: str, body: TaskUpdate, ctx=Depends(get_ctx)):
    ctx.require("remediate")
    repo = Repository(ctx)
    current = await repo.get("tasks", task_id)
    fields = body.model_dump(exclude_unset=True)
    if not fields or any(value is None for value in fields.values()):
        raise HTTPException(422, "Provide at least one non-null task field; use an empty string to clear assignment or due date")
    status = fields.get("status", current["status"])
    if status in {"todo", "done"}:
        expected = 100 if status == "done" else 0
        if "progress" in fields and fields["progress"] != expected:
            raise HTTPException(422, "Todo tasks require 0% progress; done tasks require 100%")
        fields["progress"] = expected
    elif status == "in_progress" and current["status"] == "done" and "progress" not in fields:
        fields["progress"] = 0
    elif fields.get("progress", current.get("progress", 0)) == 100:
        raise HTTPException(422, "Mark the task done to record 100% progress")
    if status == "done" and current["status"] != "done":
        fields["completed_at"] = iso()
    elif status != "done":
        fields["completed_at"] = None
    return await repo.update("tasks", task_id, fields)


@router.get("/assessments")
async def list_assessments(project_id: str | None = None,
    search: str = Query(default="", max_length=120),
    status: Literal["draft", "review", "cancelled"] | None = None,
    offset: int = Query(default=0, ge=0, le=1_000_000),
    limit: int = Query(default=25, ge=1, le=100), ctx=Depends(get_ctx)):
    ctx.require("read")
    repo = Repository(ctx)
    filters = {}
    if project_id:
        await repo.get("projects", project_id)
        filters["project_id"] = project_id
    if search.strip():
        filters["name"] = {"$regex": re.escape(search.strip()), "$options": "i"}
    if status:
        filters["status"] = status
    return await repo.page("assessments", filters, offset=offset, limit=limit)


@router.post("/assessments/{assessment_id}/cancel")
async def cancel_assessment(assessment_id: str, body: ScopeRevocationInput, ctx=Depends(get_ctx)):
    ctx.require("scan")
    repo = Repository(ctx)
    async with JOB_LOCK:
        assessment = await repo.get("assessments", assessment_id)
        if assessment.get("status") == "cancelled":
            return assessment
        jobs = await repo.complete_list("jobs", {"assessment_id": assessment_id, "status": {"$in": ["queued", "running", "cancelling"]}})
        result = await repo.update("assessments", assessment_id, {"status": "cancelled",
            "cancelled_at": iso(), "cancelled_by": ctx.uid, "cancellation_reason": body.reason})
        for job in jobs:
            task = ACTIVE_CHECKS.get((ctx.org_id, job["id"]))
            await repo.update("jobs", job["id"], {"status": "cancelling" if task else "cancelled",
                "cancellation_reason": body.reason, **({"cancellation_requested_at": iso()} if task else {"finished_at": iso()})}, log=False)
            if task:
                task.cancel()
        await audit(ctx, "assessment.cancelled", "assessments", assessment_id, {"reason": body.reason})
    return result


@router.post("/assessments/{assessment_id}/retry")
async def retry_assessment(assessment_id: str, ctx=Depends(get_ctx)):
    ctx.require("scan")
    repo = Repository(ctx)
    previous = await repo.get("assessments", assessment_id)
    if previous.get("status") != "cancelled":
        raise HTTPException(409, "Only cancelled assessments can be retried; use retest for reviewed assessments")
    return await repo.add("assessments", {"project_id": previous["project_id"],
        "name": previous["name"][:100] + " · Retry", "asset_ids": previous["asset_ids"],
        "status": "draft", "baseline_id": previous.get("baseline_id"), "retry_of": assessment_id})


@router.get("/assessments/{assessment_id}/history")
async def assessment_history(assessment_id: str, ctx=Depends(get_ctx)):
    ctx.require("read")
    repo = Repository(ctx)
    await repo.get("assessments", assessment_id)
    events = await repo.list("audit_events", {"resource_type": "assessments", "resource_id": assessment_id}, limit=101)
    return {"events": events[:100], "has_more": len(events) > 100}


@router.post("/assessments/{assessment_id}/retest")
async def retest(assessment_id: str, ctx=Depends(get_ctx)):
    ctx.require("scan")
    repo = Repository(ctx)
    previous = await repo.get("assessments", assessment_id)
    return await repo.add("assessments", {"project_id": previous["project_id"], "name": (previous["name"][:100] + " · Retest"), "asset_ids": previous["asset_ids"], "status": "draft", "baseline_id": assessment_id})


@router.get("/assessments/{assessment_id}/comparison")
async def comparison(assessment_id: str, ctx=Depends(get_ctx)):
    ctx.require("read")
    repo = Repository(ctx)
    current = await repo.get("assessments", assessment_id)
    if not current.get("baseline_id"):
        raise HTTPException(400, "This assessment has no retest baseline")
    baseline = await repo.get("assessments", current["baseline_id"])
    before = await repo.complete_list("findings", {"assessment_id": baseline["id"]})
    after = await repo.complete_list("findings", {"assessment_id": assessment_id})
    jobs = await repo.complete_list("jobs", {"assessment_id": assessment_id, "status": "completed", "source": "execution"})
    coverage = {(j["asset_id"], j["scanner"]) for j in jobs}
    old = {f["fingerprint"]: f for f in before}
    new = {f["fingerprint"]: f for f in after}
    missing = [f for key, f in old.items() if key not in new]
    return {"baseline": baseline["name"], "current": current["name"], "persistent": [f for key, f in new.items() if key in old], "new": [f for key, f in new.items() if key not in old], "not_observed": [f for f in missing if (f["asset_id"], f["scanner"]) in coverage], "not_retested": [f for f in missing if (f["asset_id"], f["scanner"]) not in coverage], "notice": "Not observed is not proof of resolution. Only matching completed execution coverage is compared; imports do not prove coverage."}
