# VAPT-X operations guide

## Start and explore
Sign in with the owner credentials configured in the backend environment, or register an email/password account. A newly registered user creates an organization; organization admins can add already-registered users. A user may belong to multiple organizations; role permissions are resolved for the active organization on every request.

An initial **Controlled training lab** project is included in the owner's workspace. Its findings come from an actual check against the application-owned `training://local` target, not simulated results or a scan of a third-party website. This intentionally minimal, non-sensitive training response omits protective headers.

## Core workflow
1. Create a project.
2. In Assets & scope, authorize an exact host, record your authorization reference, select permitted scanners, and define a start/end time. For controlled verification, use the training-target button.
3. Register assets matching that exact host.
4. Create an assessment selecting project assets.
5. Launch built-in safe checks or constrained Nmap; monitor Scans and inspect check details. Nmap availability is shown accurately for the current environment.
6. Alternatively, paste genuine Nmap XML, Nuclei JSON/JSONL, Semgrep JSON, Trivy JSON, or ZAP JSON into Import report. Imported findings are labeled imported-unverified. The uploader declares the asset association. Maximum 2 MB text / 2,000 observations.
7. Review Findings. Set triage status and notes. Attach private evidence (10 MB max) or create a remediation task.
8. Advance tasks through To do / In progress / Done. Task completion does not mark a finding resolved.
9. Generate a PDF under Reports. It is a stored point-in-time snapshot with genuine observations and evidence hashes.
10. Create a retest from an assessment and run matching checks. Compare new/persistent/not observed/not retested observations. Missing observations never automatically establish remediation.
11. Use Audit trail for the latest 100 events. Database administrators can still modify records; this is application-level append-only, not a cryptographic external ledger.
12. Optionally use AI analyst. Claude receives up to 30 stored project findings and the conversation history. Raw evidence files are not sent. AI text never changes stored findings automatically.

## Roles
- Organization administrator: full organization permissions, memberships, scopes.
- Security lead: write, authorize scopes, scans, triage, remediation, reports, evidence, AI.
- Analyst: write, scans, triage, remediation, reports, evidence, AI; cannot approve scopes or manage members.
- Auditor / viewer: read-only access and existing report/evidence downloads.
- Owner has a separate platform administrator designation; it does **not** bypass organization memberships. A separate platform administration interface is not implemented.

## Safety and limitations
- Explicit approved scope and current authorization window required for scans/import association.
- No wildcard or CIDR scope, shell command input, arbitrary Nmap flags, exploit modules, brute force, or intrusive templates.
- Public HTTP(S) targets are resolved and pinned; all resolved addresses must be globally routable. Redirects are not followed. Supported web ports: 80, 443, 8080, 8443.
- Only the managed training target has a server-selected loopback exception. Training TLS and DNS checks are clearly skipped.
- Nmap: installed binary from `NMAP_BINARY`, TCP connect, four web ports, 45-second host limit / 60-second process limit. The training target only scans the internal API port. Open ports are informational observations, not vulnerabilities.
- Safe HTTP checks inspect a point-in-time response, not the full application or authenticated pages. Response body capped at 1 MB; no credentials are sent.
- Jobs persist in MongoDB; process restarts mark in-flight jobs interrupted. Manual restart required; no distributed durable worker queue yet.
- At most two active jobs per organization in the current single-worker environment. Horizontal worker coordination is not implemented.
- Evidence chunks and generated report bytes are private MongoDB records. Evidence is SHA-256 checked on download, always served as attachment. No antivirus scanning, abandoned-upload cleanup, or external object-storage lifecycle policy yet.
- Organization-wide project access; finer project-level memberships are backlog.
- UI workspace snapshot currently capped at 1,000 records per collection, newest first; audit 100. Server-side cursor pagination is backlog for larger datasets.
- Claude failures return a clear error; provider balance/availability may require attention. Only Claude is integrated; other adapters are backlog.

## Environment and persistence
Preserve the configured `MONGO_URL`, `DB_NAME`, and frontend `REACT_APP_BACKEND_URL`. Backend needs `JWT_SECRET`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `FRONTEND_URL`, `EMERGENT_LLM_KEY`, `CLAUDE_MODEL`, `INTERNAL_API_URL`, and `NMAP_BINARY`. Never expose their values in documentation or frontend code. Owner seeding is insert-only and never resets a changed password on startup.

FastAPI is supervisor-managed on port 8001, frontend on 3000. All routes use `/api`. Restart services only through supervisor. Nmap is an OS dependency and may be absent in a new deployment; the app then reports it unavailable instead of fabricating success. Python dependencies are recorded in backend/requirements.txt. No authentication tokens in localStorage; secure HttpOnly cookies, CSRF token + Origin checks, persisted revocable sessions. LocalStorage holds only non-secret organization ID and theme preference.

## Backlog (not claimed implemented)
MFA/TOTP; email verification/recovery; advanced session-management UI; independent authorization approval; granular project permissions; scheduled scans and distributed queue; notification/webhook delivery; API tokens; additional AI providers; external integrations; advanced scanner modules; richer report templates and graphs.
