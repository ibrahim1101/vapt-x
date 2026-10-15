from io import BytesIO
from html import escape
from collections import Counter
from fastapi import APIRouter, Depends, Response, HTTPException
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from core import get_ctx, iso, audit, sha256_hex
from repository import Repository

router = APIRouter(prefix="/api")


def build_pdf(project, assessment, findings, jobs, evidence, scopes, tasks):
    buffer = BytesIO()
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="TinyText", fontSize=8, leading=12, textColor=colors.HexColor("#475569"), wordWrap="CJK"))
    styles["BodyText"].wordWrap = "CJK"
    styles["BodyText"].leading = 15
    styles["Title"].alignment = TA_LEFT
    doc = SimpleDocTemplate(buffer, pagesize=(595, 842), rightMargin=46, leftMargin=46, topMargin=48, bottomMargin=50, title="VAPT-X Assessment Report")
    p = lambda text, style="BodyText": Paragraph(escape(str(text)).replace("\n", "<br/>"), styles[style])
    story = [p("VAPT-X / SECURITY ASSESSMENT", "TinyText"), Spacer(1, 18), p(project["name"], "Title"), p(assessment["name"], "Heading2"), p(f"Generated {iso()} · CONFIDENTIAL", "TinyText"), Spacer(1, 20), p("Executive summary", "Heading2")]
    counts = Counter(f["severity"] for f in findings)
    story.append(p(f"This assessment contains {len(findings)} recorded observations from {len(jobs)} scan/import jobs. Findings are observations, not proof of exploitability. Imported reports are attributed to their source and are not independently verified. This report reflects stored results at generation time."))
    table = Table([[p(s.upper(), "TinyText") for s in ("critical", "high", "medium", "low", "info")], [str(counts.get(s, 0)) for s in ("critical", "high", "medium", "low", "info")]], colWidths=[100]*5)
    table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#e8eef3")), ("BOTTOMPADDING", (0,0), (-1,-1), 10), ("TOPPADDING", (0,0), (-1,-1), 10)]))
    story.extend([Spacer(1, 16), table, Spacer(1, 16), p("Scope & execution record", "Heading2")])
    for scope in scopes:
        story.append(p(f"Authorized target: {scope['target']}", "Heading4"))
        story.append(p(f"Reference: {scope['authorization_reference']}", "TinyText"))
        story.append(p(f"Window: {scope['starts_at']} to {scope['ends_at']} | Approved: {scope['authorized']}", "TinyText"))
        story.append(p(f"Permitted sources: {', '.join(scope['allowed_scanners'])}", "TinyText"))
    if tasks:
        story.append(p("Remediation tracking", "Heading3"))
        for task in tasks:
            story.append(p(f"{task['title']} | {task['status']} | Owner: {task.get('assignee') or 'Unassigned'} | Due: {task.get('due_date') or 'Not set'}", "TinyText"))
    if not jobs:
        story.append(p("No scan jobs have been executed. This is an incomplete assessment, not a clean bill of health."))
    for job in jobs:
        story.append(p(f"{job['scanner']} · {job['source']} · {job['status']} · {job.get('finding_count', 0)} observations", "BodyText"))
        if job.get("error"):
            story.append(p(job["error"], "TinyText"))
        for check in job.get("checks", []):
            story.append(p(f"{check['name']}: {check['status']} — {check['detail']}", "TinyText"))
    story.extend([Spacer(1, 16), p("Finding details", "Heading2")])
    for number, finding in enumerate(findings, 1):
        story.extend([KeepTogether([Spacer(1, 14), p(f"{number:02}. {finding['title']}", "Heading3"), p(f"{finding['severity'].upper()} | {finding['status']} | {finding['verification']} | {finding['scanner']}", "TinyText")]), p(f"Target: {finding['target']}", "TinyText"), p(finding["description"][:12000]), Spacer(1, 6), p("Remediation", "Heading4"), p(finding["remediation"]), p(f"Analyst notes: {finding.get('notes') or 'None'}", "TinyText")])
        for item in evidence:
            if item["finding_id"] == finding["id"] and item["status"] == "ready":
                story.append(p(f"Evidence: {item['filename']} · SHA-256 {item['sha256']}", "TinyText"))
    story.extend([Spacer(1, 22), p("Limitations", "Heading2"), p("Point-in-time, non-exploitative assessment. Unassessed services, skipped checks, failed jobs and external dependencies limit coverage. A missing observation on retest does not establish remediation. Only test systems for which you hold explicit authorization.")])
    def footer(canvas, document):
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(46, 28, "VAPT-X / Confidential · Authorized assessment")
        canvas.drawRightString(549, 28, str(document.page))
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


@router.post("/assessments/{assessment_id}/report")
async def report(assessment_id: str, ctx=Depends(get_ctx)):
    ctx.require("report")
    repo = Repository(ctx)
    assessment = await repo.get("assessments", assessment_id)
    project = await repo.get("projects", assessment["project_id"])
    findings = await repo.complete_list("findings", {"assessment_id": assessment_id})
    jobs = await repo.complete_list("jobs", {"assessment_id": assessment_id})
    evidence = await repo.complete_list("evidence", {"project_id": project["id"]})
    scopes = await repo.complete_list("scopes", {"project_id": project["id"]})
    tasks = await repo.complete_list("tasks", {"finding_id": {"$in": [f["id"] for f in findings]}})
    raw = build_pdf(project, assessment, findings, jobs, evidence, scopes, tasks)
    import base64
    record = await repo.add("reports", {"project_id": project["id"], "assessment_id": assessment_id, "name": assessment["name"] + " Report", "sha256": sha256_hex(raw), "finding_count": len(findings)})
    await repo.add("report_files", {"report_id": record["id"], "data": base64.b64encode(raw).decode()}, log=False)
    return record


@router.get("/reports/{report_id}/download")
async def download_report(report_id: str, ctx=Depends(get_ctx)):
    ctx.require("read")
    repo = Repository(ctx)
    record = await repo.get("reports", report_id)
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
