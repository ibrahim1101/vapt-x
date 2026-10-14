import asyncio
import os
import shutil
from importlib.util import find_spec
from datetime import datetime, timezone
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field, field_validator
from core import get_ctx, iso, audit
from repository import Repository
from scanners import target_host, validate_scope, run_job, SCANNERS, store_findings
from importers import parse_report

router = APIRouter(prefix="/api")
SCAN_LOCK = asyncio.Lock()


class ProjectInput(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    description: str = Field(default="", max_length=3000)


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


class AssetInput(BaseModel):
    project_id: str
    scope_id: str
    name: str = Field(min_length=2, max_length=120)
    target: str = Field(max_length=500)
    kind: Literal["web", "host", "repository", "container"] = "web"


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
    scanner: Literal["nmap", "nuclei", "semgrep", "trivy", "zap"]
    content: str = Field(min_length=2, max_length=2_000_000)


class TriageInput(BaseModel):
    status: Literal["open", "confirmed", "false_positive", "accepted_risk", "resolved"]
    notes: str = Field(default="", max_length=5000)


class TaskInput(BaseModel):
    finding_id: str
    title: str = Field(min_length=2, max_length=200)
    assignee: str = Field(default="", max_length=150)
    due_date: str = Field(default="", max_length=30)


class TaskUpdate(BaseModel):
    status: Literal["todo", "in_progress", "done"]


@router.get("/capabilities")
async def capabilities(ctx=Depends(get_ctx)):
    ctx.require("read")
    return {"safe": True, "nmap": bool(shutil.which(os.environ["NMAP_BINARY"])), "imports": ["nmap", "nuclei", "semgrep", "trivy", "zap"], "ai": bool(os.environ.get("ANTHROPIC_API_KEY")) and find_spec("anthropic") is not None, "limitations": ["Nmap uses TCP connect on four web ports only; no exploit scripts.", "Remote private networks are blocked. Only the managed training target may use loopback.", "Imports are scanner-authored, unverified evidence, not a fresh scan.", "Interrupted jobs are marked interrupted after a worker restart; re-run manually."]}


@router.get("/workspace")
async def workspace(project_id: str | None = None, ctx=Depends(get_ctx)):
    ctx.require("read")
    repo = Repository(ctx)
    filters = {"project_id": project_id} if project_id else {}
    if project_id:
        await repo.get("projects", project_id)
    data = {"projects": await repo.list("projects")}
    for collection in ("scopes", "assets", "assessments", "jobs", "findings", "tasks", "evidence", "reports"):
        data[collection] = await repo.list(collection, filters)
    for job in data["jobs"]:
        job.pop("raw_output", None)
    data["audit"] = await repo.list("audit_events", limit=100)
    data["role"] = ctx.role
    return data


@router.post("/projects")
async def create_project(body: ProjectInput, ctx=Depends(get_ctx)):
    ctx.require("write")
    return await Repository(ctx).add("projects", {**body.model_dump(), "status": "active"})


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
    await validate_scope(repo, assessment, asset, body.scanner)
    async with SCAN_LOCK:
        active = await repo.list("jobs", {"status": {"$in": ["queued", "running"]}})
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
    job = await repo.add("jobs", {"assessment_id": assessment["id"], "asset_id": asset["id"], "project_id": assessment["project_id"], "scanner": body.scanner, "source": "import", "status": "completed", "raw_output": body.content, "checks": [], "logs": ["Imported scanner-authored output. Not independently verified; asset association declared by uploader."], "finished_at": iso()})
    count = await store_findings(repo, assessment, asset, job, rows)
    await repo.update("assessments", assessment["id"], {"status": "review"}, log=False)
    return await repo.update("jobs", job["id"], {"finding_count": count}, log=False)


@router.get("/jobs/{job_id}")
async def get_job(job_id: str, ctx=Depends(get_ctx)):
    ctx.require("read")
    return await Repository(ctx).get("jobs", job_id)


@router.patch("/findings/{finding_id}")
async def triage(finding_id: str, body: TriageInput, ctx=Depends(get_ctx)):
    ctx.require("triage")
    return await Repository(ctx).update("findings", finding_id, body.model_dump())


@router.post("/tasks")
async def create_task(body: TaskInput, ctx=Depends(get_ctx)):
    ctx.require("remediate")
    repo = Repository(ctx)
    finding = await repo.get("findings", body.finding_id)
    return await repo.add("tasks", {**body.model_dump(), "project_id": finding["project_id"], "status": "todo"})


@router.patch("/tasks/{task_id}")
async def update_task(task_id: str, body: TaskUpdate, ctx=Depends(get_ctx)):
    ctx.require("remediate")
    return await Repository(ctx).update("tasks", task_id, body.model_dump())


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
    before = await repo.list("findings", {"assessment_id": baseline["id"]})
    after = await repo.list("findings", {"assessment_id": assessment_id})
    jobs = await repo.list("jobs", {"assessment_id": assessment_id, "status": "completed", "source": "execution"})
    coverage = {(j["asset_id"], j["scanner"]) for j in jobs}
    old = {f["fingerprint"]: f for f in before}
    new = {f["fingerprint"]: f for f in after}
    missing = [f for key, f in old.items() if key not in new]
    return {"baseline": baseline["name"], "current": current["name"], "persistent": [f for key, f in new.items() if key in old], "new": [f for key, f in new.items() if key not in old], "not_observed": [f for f in missing if (f["asset_id"], f["scanner"]) in coverage], "not_retested": [f for f in missing if (f["asset_id"], f["scanner"]) not in coverage], "notice": "Not observed is not proof of resolution. Only matching completed execution coverage is compared; imports do not prove coverage."}
