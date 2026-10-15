# Implementation-status matrix

Audit: 2026-10-14 UTC; baseline `a2dcdae`. “Implemented, untested” means relevant source exists, not that acceptance criteria have passed. “In progress” includes incomplete workflows/helpers. Historical generated test narratives are not current verification. Session checks are recorded in [DEVELOPMENT_LOG.md](DEVELOPMENT_LOG.md). PR links are added after a PR actually exists.

Priority: P0 security/startup blockers, P1 core product, P2 expansion, P3 later capabilities.

| Feature | Category | Priority | Implementation status | Test status | Known limitations | Relevant source files | Related pull request |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Required environment validation/startup diagnostics | Foundation | P0 | In progress | Settings and failure-cleanup unit tests pass | Production configuration and live startup need verification | `backend/config.py`, `backend/server.py`, `backend/core.py` | Pending |
| Bounded request bodies and database health | Foundation | P0 | Verified working | ASGI limit and mocked health regression tests pass | Proxy/deployment limits need validation | `backend/server.py`, `backend/request_limits.py` | Pending |
| Runtime dependency cleanup/reproducible installs | Foundation | P0 | In progress | Backend clean install and pip check pass; frontend build blocked | Baseline dependency set was oversized; full lock/build evidence required | `backend/requirements.txt`, `frontend/package.json`, frontend lockfile (absent) | Pending |
| MongoDB development service | Foundation | P0 | Implemented, untested | Not run in this environment | Docker unavailable here; local-only unauthenticated DB | `compose.local.yml` | Pending |
| Application containers and Linux deployment | Foundation | P1 | In progress | Docker unavailable locally | Non-root API Dockerfile/profile added; frontend image and production deployment absent | `backend/Dockerfile`, `compose.local.yml` | Pending |
| Registration/login/logout/refresh | Identity | P0 | Implemented, untested | Current end-to-end checks pending | Refresh race/session lifecycle and production cookie behavior need tests | `backend/auth.py`, `backend/core.py`, `frontend/src/components/access.jsx`, `frontend/src/lib/api.js` | Pending |
| Local cookie policy, CSRF, CORS | Identity | P0 | Implemented, untested | Regression checks pending | Strict loopback development mode; one configured frontend origin | `backend/auth.py`, `backend/server.py` | Pending |
| Password policy/login throttling | Identity | P0 | In progress | Regression checks pending | Email failure counter only; no general distributed API rate limiter | `backend/auth.py` | Pending |
| Organizations, switching, fixed roles, members | Identity | P0 | Implemented, untested | Membership and permission unit tests pass; lifecycle pending | Add existing registered users only; no invitation lifecycle/removal workflow | `backend/auth.py`, `backend/core.py`, `frontend/src/App.js` | Pending |
| Organization-scoped repository | Governance | P0 | Implemented, untested | Tenant filter unit test passes; full endpoint suite pending | Raw DB helpers also require review; no project ACL | `backend/repository.py`, `backend/core.py` | Pending |
| MFA, reset, verification, account disable, device sessions | Identity | P1 | Not started | None | Core account lifecycle incomplete | `backend/auth.py` | — |
| Project ACL/custom roles/service accounts/API tokens | Identity | P1 | Not started | None | Token generation helper is not an authentication workflow | `backend/core.py` | — |
| Optional OIDC/SSO | Identity | P3 | Deferred | None | Follow verified core identity | — | — |
| Project creation/listing/dashboard | Projects | P1 | Implemented, untested | Persistent workflow pending | Edit/archive/templates/ownership/export absent | `backend/workflow.py`, `frontend/src/components/dashboard.jsx` | Pending |
| Exact-host scope and rules of engagement | Authorization | P0 | Implemented, untested | Negative scope tests pending | Text reference only, no approval attachment workflow | `backend/workflow.py`, `backend/scanners.py`, `frontend/src/components/workspace-forms.jsx` | Pending |
| Asset registration and inventory | Assets | P1 | Implemented, untested | Workflow pending | Four kind labels, web target syntax; no bulk import/ownership/criticality | `backend/workflow.py`, `frontend/src/components/workspace-pages.jsx` | Pending |
| Asset relationships/history/exposure scoring | Assets | P2 | Not started | None | No specialized cloud/API/mobile inventory | — | — |
| Assessment creation and job status/logs | Assessments | P1 | Implemented, untested | Workflow pending | BackgroundTasks, no durable queue, process-local concurrency | `backend/workflow.py`, `backend/scanners.py`, `frontend/src/components/workspace-pages.jsx` | Pending |
| Cancellation/scheduling/retry/worker recovery | Assessments | P1 | In progress | Restart behavior unverified | Startup marks jobs interrupted; no resumable recovery/cancel API | `backend/server.py`, `backend/scanners.py` | Pending |
| Safe HTTP/cookie/TLS/security.txt/DNS checks | Scanners | P0 | Implemented, untested | Controlled transport tests pending | DNS is resolution only; TLS checks certificate/expiry; no exhaustive posture audit | `backend/scanners.py` | Pending |
| Constrained Nmap execution | Scanners | P1 | Implemented, untested | Nmap execution unverified | External binary; four web ports only; no worker sandbox | `backend/scanners.py` | Pending |
| Nmap/Nuclei/Semgrep/Trivy/ZAP report imports | Scanners | P1 | Implemented, untested | Parser fixtures pending | Import-only except Nmap; limited schema variants; uploader-declared attribution | `backend/importers.py`, `backend/workflow.py` | Pending |
| OpenAPI/Schemathesis/Gitleaks/Checkov/Prowler/MobSF/SBOM | Scanners | P2 | Not started | None | No adapter or functioning UI found | — | — |
| Finding normalization/deduplication/triage/search | Findings | P1 | Implemented, untested | Parser/persistence/UI pending | Scanner-specific fingerprints; no cross-scanner correlation; list truncation | `backend/importers.py`, `backend/scanners.py`, `backend/workflow.py`, `frontend/src/components/dashboard.jsx` | Pending |
| CVSS/CVE/CWE structured intelligence, EPSS/KEV/OSV/NVD | Findings | P2 | Not started | None | CVE text in imports is not structured enrichment | — | — |
| Advanced filters/bulk actions/SLA/history/exports | Findings | P2 | Not started | None | Basic client-side filters only | `frontend/src/components/dashboard.jsx` | — |
| Remediation tasks/assignee/due date/status | Remediation | P1 | Implemented, untested | Workflow pending | Assignee/due date are free text; no validated member assignment/SLA | `backend/workflow.py`, `frontend/src/components/workspace-pages.jsx` | Pending |
| Retest/baseline comparison | Remediation | P1 | Implemented, untested | Coverage regressions pending | Not-observed does not mean resolved; 1,000-row list limit | `backend/workflow.py`, `frontend/src/components/workspace-pages.jsx` | Pending |
| Evidence chunks/signatures/checksums/download | Evidence | P0 | Implemented, untested | Integrity/ownership/race tests pending | 10 MiB/file; no retention/tenant quota/malware scanning | `backend/evidence.py`, `frontend/src/lib/api.js` | Pending |
| Stored PDF report snapshots | Reporting | P1 | Implemented, untested | Generation/layout/API pending | No report download checksum validation; default query limits; one template | `backend/reporting.py`, `frontend/src/components/workspace-pages.jsx` | Pending |
| Branding/report scheduling/sharing/CSV/JSON | Reporting | P2 | Not started | None | No public sharing controls or exporters | — | — |
| Optional Claude analyst/history | AI | P1 | Implemented, untested | Live provider not invoked | Key/SDK required; at most 30 findings; no secret redaction | `backend/analyst.py`, `frontend/src/components/workspace-pages.jsx` | Pending |
| Multi-provider/local AI/cost visibility | AI | P2 | Not started | None | Provider map only includes Claude | `backend/analyst.py` | — |
| Dashboard/severity chart/search/theme/responsive nav | UI/analytics | P1 | Implemented, untested | Browser/accessibility pending | Counts reflect loaded rows; no historical/coverage scoring | `frontend/src/App.js`, `frontend/src/components/dashboard.jsx`, `frontend/src/App.css` | Pending |
| Advanced analytics/relationships/attack paths | UI/analytics | P2 | Not started | None | No fabricated or inferred attack graph supplied | — | — |
| Audit trail UI and events | Governance | P0 | Implemented, untested | Audit isolation pending | Latest 100; application append-only, not tamper-evident; auth gaps | `backend/core.py`, `frontend/src/components/workspace-pages.jsx` | Pending |
| Webhook signing/retry helper | Integrations | P1 | In progress | No delivery performed | No management API/UI; DNS pinning/secret storage gaps | `backend/webhooks.py` | — |
| GitHub/GitLab/Jira/Slack/Teams/email/SIEM/OpenTelemetry | Integrations | P2 | Not started | None | No activated integration workflow | — | — |
| Encryption/retention/backup/restore/compliance | Governance | P1 | Not started | None | Operational controls must precede sensitive deployment | — | — |
| Backend regression suite/CI | Quality | P0 | In progress | 14 passed, 1 skipped locally; CI pending | Baseline contained no executable suite beyond empty package | `backend/pytest.ini`, `backend/tests/`, `.github/workflows/backend.yml` | Pending |
| Browser E2E/Docker integration/restore drills | Quality | P1 | Not started | None | Requires isolated runtime and repeatable fixtures | — | — |
| Desktop packaging | Release | P3 | Deferred | None | Web stability first | — | — |

A feature becomes **Verified working** only for a stated tested scope. Passing helper tests does not establish browser functionality, persistence, full authorization or absence of unrelated regressions. Use **Blocked** when a concrete dependency prevents the next required check, and document it in the development log.
