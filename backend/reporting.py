import asyncio
from datetime import datetime,timezone
import base64
import json
from typing import Literal
from pydantic import BaseModel,Field
from pymongo import ReturnDocument
from io import BytesIO
from html import escape
from collections import Counter
from fastapi import APIRouter, Depends, Response, HTTPException, Query
import reportlab
from pathlib import Path
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from core import get_ctx, iso, audit, sha256_hex, db
from repository import Repository

_FONT_DIR=Path(reportlab.__file__).parent / "fonts"
pdfmetrics.registerFont(TTFont("VaptSans",str(_FONT_DIR / "Vera.ttf")))
pdfmetrics.registerFont(TTFont("VaptSans-Bold",str(_FONT_DIR / "VeraBd.ttf")))
pdfmetrics.registerFontFamily("VaptSans",normal="VaptSans",bold="VaptSans-Bold",italic="VaptSans",boldItalic="VaptSans-Bold")

router = APIRouter(prefix="/api")


class ReportSection(BaseModel):
    heading: str = Field(min_length=1,max_length=100)
    text: str = Field(min_length=1,max_length=5000)


class ReportOptions(BaseModel):
    template: Literal["technical","executive","remediation"] = "technical"
    branding: str = Field(default="VAPT-X",max_length=100)
    sections: list[ReportSection] = Field(default_factory=list,max_length=10)


def build_pdf(project, assessment, findings, jobs, evidence, scopes, tasks, options=None):
    options = options or ReportOptions()
    buffer = BytesIO()
    styles = getSampleStyleSheet()
    for style in styles.byName.values():
        style.fontName = "VaptSans-Bold" if style.name.startswith("Heading") or style.name=="Title" else "VaptSans"
    styles.add(ParagraphStyle(name="TinyText", fontName="VaptSans", fontSize=8, leading=12, textColor=colors.HexColor("#475569"), splitLongWords=True))
    styles["BodyText"].splitLongWords = True
    styles["BodyText"].leading = 15
    styles["Title"].alignment = TA_LEFT
    doc = SimpleDocTemplate(buffer, pagesize=(595, 842), rightMargin=46, leftMargin=46, topMargin=48, bottomMargin=50, title="VAPT-X Assessment Report")
    p = lambda text, style="BodyText": Paragraph(escape(str(text)).replace("\n", "<br/>"), styles[style])
    story = [p(f"{options.branding or 'VAPT-X'} / {options.template.upper()} ASSESSMENT", "TinyText"), Spacer(1, 18), p(project["name"], "Title"), p(assessment["name"], "Heading2"), p(f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · CONFIDENTIAL", "TinyText"), Spacer(1, 20), p("Executive summary", "Heading2")]
    counts = Counter(f["severity"] for f in findings)
    story.append(p(f"This assessment contains {len(findings)} recorded observations from {len(jobs)} scan/import jobs. Findings are observations, not proof of exploitability. Imported reports are attributed to their source and are not independently verified. This report reflects stored results at generation time."))
    table = Table([[p(s.upper(), "TinyText") for s in ("critical", "high", "medium", "low", "info")], [str(counts.get(s, 0)) for s in ("critical", "high", "medium", "low", "info")]], colWidths=[100]*5)
    table.setStyle(TableStyle([("FONTNAME",(0,0),(-1,-1),"VaptSans"),("BACKGROUND", (0,0), (-1,0), colors.HexColor("#e8eef3")), ("BOTTOMPADDING", (0,0), (-1,-1), 10), ("TOPPADDING", (0,0), (-1,-1), 10)]))
    story.extend([Spacer(1, 16), table, Spacer(1, 16)])
    if options.template!="executive":
        story.append(p("Scope & execution record", "Heading2"))
    else:
        story.append(p(f"Execution coverage: {sum(j.get('status')=='completed' for j in jobs)} completed jobs; {sum(j.get('status') in {'failed','interrupted','cancelled'} for j in jobs)} failed/interrupted/cancelled jobs. Imports remain unverified.", "TinyText"))
    for scope in ([] if options.template=="executive" else scopes):
        story.append(p(f"Authorized target: {scope['target']}", "Heading4"))
        story.append(p(f"Reference: {scope['authorization_reference']}", "TinyText"))
        story.append(p(f"Window: {scope['starts_at']} to {scope['ends_at']} | Approved: {scope['authorized']}", "TinyText"))
        story.append(p(f"Permitted sources: {', '.join(scope['allowed_scanners'])}", "TinyText"))
    if tasks:
        story.append(p("Remediation tracking", "Heading3"))
        for task in tasks:
            story.append(p(f"{task['title']} | {task['status']} | Owner: {task.get('assignee') or 'Unassigned'} | Due: {task.get('due_date') or 'Not set'} | Progress: {task.get('progress',100 if task['status']=='done' else 0)}%", "TinyText"))
    if not jobs:
        story.append(p("No scan jobs have been executed. This is an incomplete assessment, not a clean bill of health."))
    for job in ([] if options.template=="executive" else jobs):
        story.append(p(f"{job['scanner']} · {job['source']} · {job['status']} · {job.get('finding_count', 0)} observations", "BodyText"))
        if job.get("error"):
            story.append(p(job["error"], "TinyText"))
        for check in job.get("checks", []):
            story.append(p(f"{check['name']}: {check['status']} — {check['detail']}", "TinyText"))
    if options.template=="executive":
        story.extend([Spacer(1,16),p("Priority observations", "Heading2")])
        for finding in sorted(findings,key=lambda f:("critical","high","medium","low","info").index(f["severity"]))[:10]:
            story.append(p(f"{finding['severity'].upper()} | {finding['title']} | {finding['verification']}","TinyText"))
        story.append(p("Executive view lists up to ten priority observations. The immutable JSON snapshot contains the complete assessment source set.","TinyText"))
    if options.template=="remediation":
        story.append(p("Remediation verification", "Heading2"))
        story.append(p("Task progress does not prove resolution. Confirm changes through authorized retesting; accepted risk and false positives remain analyst decisions."))
    if options.template!="executive":
        story.extend([Spacer(1, 16), p("Finding details", "Heading2")])
    for number, finding in enumerate([] if options.template=="executive" else findings, 1):
        story.extend([KeepTogether([Spacer(1, 14), p(f"{number:02}. {finding['title']}", "Heading3"), p(f"{finding['severity'].upper()} | {finding['status']} | {finding['verification']} | {finding['scanner']}", "TinyText")]), p(f"Target: {finding['target']}", "TinyText"), p(finding["description"][:12000] if options.template=="technical" else "Observation details are retained in the immutable source snapshot."), Spacer(1, 6), p("Remediation", "Heading4"), p(finding["remediation"]), p(f"Analyst notes: {finding.get('notes') or 'None'}", "TinyText")])
        for item in evidence:
            if item["finding_id"] == finding["id"] and item["status"] == "ready":
                story.append(p(f"Evidence: {item['filename']} · SHA-256 {item['sha256']}", "TinyText"))
    for section in options.sections:
        story.extend([Spacer(1,16),p(section.heading,"Heading2"),p(section.text)])
    story.extend([Spacer(1, 22), p("Limitations", "Heading2"), p("Point-in-time, non-exploitative assessment. Unassessed services, skipped checks, failed jobs and external dependencies limit coverage. A missing observation on retest does not establish remediation. Only test systems for which you hold explicit authorization.")])
    def footer(canvas, document):
        canvas.setFont("VaptSans", 8)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(46, 28, "VAPT-X / Confidential · Authorized assessment")
        canvas.drawRightString(549, 28, str(document.page))
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


async def report_sources(assessment_id, ctx):
    repo = Repository(ctx)
    assessment = await repo.get("assessments", assessment_id)
    project = await repo.get("projects", assessment["project_id"])
    findings = await repo.complete_list("findings", {"assessment_id": assessment_id})
    jobs = await repo.complete_list("jobs", {"assessment_id": assessment_id})
    evidence = await repo.complete_list("evidence", {"project_id": project["id"]})
    evidence = [item for item in evidence if item.get("finding_id") in {f["id"] for f in findings}]
    scopes = await repo.complete_list("scopes", {"project_id": project["id"]})
    tasks = await repo.complete_list("tasks", {"finding_id": {"$in": [f["id"] for f in findings]}})
    return project,assessment,findings,jobs,evidence,scopes,tasks


def snapshot_bytes(sources, options):
    project,assessment,findings,jobs,evidence,scopes,tasks = sources
    def fields(rows,keys):
        return [{key:row.get(key) for key in keys} for row in rows]
    data={"schema_version":1,"generated_at":iso(),"options":options.model_dump(),
        "project":{key:project.get(key) for key in ("id","name","description")},
        "assessment":{key:assessment.get(key) for key in ("id","name","status","baseline_id","asset_ids")},
        "findings":fields(findings,('id','title','severity','status','verification','source','scanner','target','rule_id','description','remediation','notes','owner','cve_ids','cwe_ids','created_at')),
        "jobs":fields(jobs,('id','scanner','source','status','finding_count','checks','error','inventory_count')),
        "evidence":fields(evidence,('id','finding_id','filename','status','size','sha256')),
        "scopes":fields(scopes,('id','target','authorization_reference','starts_at','ends_at','authorized','allowed_scanners','revoked_at')),
        "tasks":fields(tasks,('id','finding_id','title','status','assignee','due_date','progress','completed_at')),
        "notice":"Immutable source snapshot. Uploaded inventory and scanner observations do not confirm exploitability. No raw report or evidence bytes are included."}
    raw=json.dumps(data,ensure_ascii=False,sort_keys=True).encode()
    if len(raw)>6_000_000:raise HTTPException(413,"Report source snapshot exceeds 6 MB; narrow the assessment")
    return raw


@router.post("/assessments/{assessment_id}/report/preview")
async def preview_report(assessment_id:str,options:ReportOptions,ctx=Depends(get_ctx)):
    ctx.require("report")
    sources=await report_sources(assessment_id,ctx)
    snapshot_bytes(sources,options)  # Apply identical completeness/size guards.
    raw=await asyncio.to_thread(build_pdf,*sources,options)
    return Response(raw,media_type="application/pdf",headers={"Content-Disposition":"inline; filename=VAPT-X-preview.pdf","X-Content-Type-Options":"nosniff"})


@router.post("/assessments/{assessment_id}/report")
async def report(assessment_id: str, ctx=Depends(get_ctx), options:ReportOptions=ReportOptions()):
    ctx.require("report")
    repo=Repository(ctx)
    sources=await report_sources(assessment_id,ctx)
    snapshot=snapshot_bytes(sources,options)
    raw=await asyncio.to_thread(build_pdf,*sources,options)
    if len(raw)>8_000_000:raise HTTPException(413,"PDF exceeds 8 MB; narrow the assessment")
    sequence=await db.report_sequences.find_one_and_update(
        {"_id":ctx.org_id+":"+assessment_id}, {"$inc":{"value":1}},upsert=True,return_document=ReturnDocument.AFTER)
    project,assessment,findings,*_=sources
    record=await repo.add("reports",{"project_id":project["id"],"assessment_id":assessment_id,
        "name":assessment["name"]+" "+options.template.title()+" Report","version":sequence["value"],
        "template":options.template,"branding":options.branding,"sections":options.model_dump()["sections"],
        "sha256":sha256_hex(raw),"snapshot_sha256":sha256_hex(snapshot),"finding_count":len(findings),"status":"generating"},log=False)
    await repo.add("report_files",{"report_id":record["id"],"project_id":project["id"],"data":base64.b64encode(raw).decode()},log=False)
    await repo.add("report_snapshots",{"report_id":record["id"],"project_id":project["id"],"data":base64.b64encode(snapshot).decode()},log=False)
    result=await repo.update("reports",record["id"],{"status":"ready"},log=False)
    await audit(ctx,"reports.created","reports",record["id"])
    return result


@router.get("/reports/{report_id}/snapshot")
async def download_snapshot(report_id:str,ctx=Depends(get_ctx)):
    ctx.require("read")
    repo=Repository(ctx)
    record=await repo.get("reports",report_id)
    if record.get("status")!="ready":raise HTTPException(409,"Report snapshot is not ready")
    files=await repo.list("report_snapshots",{"report_id":report_id},limit=2)
    try:
        if len(files)!=1:raise ValueError()
        raw=base64.b64decode(files[0]["data"],validate=True)
        if sha256_hex(raw)!=record.get("snapshot_sha256"):raise ValueError()
    except (ValueError,KeyError,TypeError):raise HTTPException(409,"Report snapshot integrity verification failed")
    await audit(ctx,"report.snapshot_downloaded","reports",report_id)
    return Response(raw,media_type="application/json",headers={"Content-Disposition":"attachment; filename=VAPT-X-snapshot.json","X-Content-Type-Options":"nosniff"})


@router.get("/reports/{report_id}/download")
async def download_report(report_id: str, ctx=Depends(get_ctx)):
    ctx.require("read")
    repo = Repository(ctx)
    record = await repo.get("reports", report_id)
    if record.get("status") not in {None,"ready"}:
        raise HTTPException(409,"Report generation is incomplete")
    files = await repo.list("report_files", {"report_id": report_id})
    import base64
    from binascii import Error as Base64Error
    if not files:
        raise HTTPException(404, "Report file not found")
    if len(files) != 1:
        raise HTTPException(409, "Report file integrity verification failed")
    try:
        raw = base64.b64decode(files[0]["data"], validate=True)
    except (KeyError, TypeError, ValueError, Base64Error):
        raise HTTPException(409, "Report file integrity verification failed") from None
    if sha256_hex(raw) != record.get("sha256"):
        raise HTTPException(409, "Report file integrity verification failed")
    await audit(ctx, "report.downloaded", "reports", report_id)
    return Response(raw, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="VAPT-X-{report_id[:8]}.pdf"'})


EXPORT_FIELDS = (
    'id', 'title', 'severity', 'status', 'verification', 'source', 'scanner',
    'target', 'asset_id', 'assessment_id', 'project_id', 'rule_id',
    'description', 'remediation', 'notes', 'created_at',
)


def csv_cell(value):
    """Prevent imported text from becoming spreadsheet formulas on CSV open."""
    text = '' if value is None else str(value)
    if text.lstrip().startswith(('=', '+', '-', '@')) or text.startswith(('\t', '\r', '\n')):
        return "'" + text
    return text


@router.get('/assessments/{assessment_id}/findings/export')
async def export_findings(assessment_id: str, format: str = 'json', ctx=Depends(get_ctx)):
    from fastapi import HTTPException
    import csv
    import json
    from io import StringIO
    ctx.require('read')
    if format not in {'json', 'csv'}:
        raise HTTPException(422, 'Export format must be json or csv')
    repo = Repository(ctx)
    assessment = await repo.get('assessments', assessment_id)
    findings = await repo.complete_list('findings', {'assessment_id': assessment_id})
    rows = [{key: finding.get(key) for key in EXPORT_FIELDS} for finding in findings]
    notice = 'Scanner observations and imported reports are not proof of exploitability. Verification and provenance are recorded separately.'
    if format == 'json':
        body = json.dumps({'schema_version': 1, 'assessment_id': assessment_id,
            'project_id': assessment['project_id'], 'generated_at': iso(),
            'notice': notice, 'finding_count': len(rows), 'findings': rows}, ensure_ascii=False)
        media_type = 'application/json'
    else:
        output = StringIO(newline='')
        writer = csv.writer(output)
        writer.writerow(EXPORT_FIELDS)
        writer.writerows([[csv_cell(row[key]) for key in EXPORT_FIELDS] for row in rows])
        body = output.getvalue()
        media_type = 'text/csv'
    await audit(ctx, 'findings.exported', 'assessments', assessment_id, {'format': format, 'finding_count': len(rows)})
    return Response(body, media_type=media_type, headers={
        'Content-Disposition': f'attachment; filename="VAPT-X-findings.{format}"',
        'X-Content-Type-Options': 'nosniff',
    })
