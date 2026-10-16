# Implementation status

Updated 2026-10-16. Review: [draft PR #1](https://github.com/ibrahim1101/vapt-x/pull/1). Current verified code: `283f7e46c5028da013ec0a7ce42d7bd8ccb5c882`. This document describes implemented behavior; passing synthetic tests do not establish production readiness or exhaustive security coverage.

| Area | Implemented and exercised | Remaining limits |
|---|---|---|
| Runtime | Validated configuration, bounded request bodies/health, pinned backend dependencies and frozen Yarn installation | Production deployment and upgrade/restore drills remain |
| Containers | Non-root API and Nginx frontend, fixed API proxy, Compose health/smoke tests | One API worker; local Mongo service is for development |
| Authentication | Cookie sessions, CSRF/origin controls, atomic refresh rotation, coordinated browser credential changes/retries, password changes and database-enforced attempt budgets | No email verification or password-reset flow |
| MFA | Encrypted TOTP enrollment, atomic anti-replay, hash-only one-use recovery codes, replacement/removal, step-up for password changes | Optional operator key; no automatic key rewrapping |
| Accounts | Private paginated security history; platform-owner search and disable/reactivate with password/MFA | History is best effort; owner accounts protected; in-flight work may finish |
| Organizations | Switching, fixed roles, membership grants/removal, fresh actor and anti-orphan guards, complete member directory/search/role filters | Registered accounts only; invitations/OIDC/custom roles remain |
| API tokens | One-time display, hash-only storage, expiry/revocation, organization/current-role and membership binding | No service identities or project ACL |
| Tenant boundaries | Organization-scoped repositories and negative API/browser tests including downloads and jobs | Project-level authorization remains absent |
| Projects | Metadata, archive/restore, owner labels, templates, complete server pagination/search and related counts | Archive does not withdraw scanning authorization |
| Assets | Metadata/criticality/tags, bulk registration receipts, server pagination/search/activity | Owner labels confer no permission; target/scope immutable |
| Authorization | Exact targets, explicit reference/time window/scanner profiles, scope withdrawal, fresh destination checks, complete authorization register/search/approval-flag filter | No authorization attachment/approval workflow |
| Assessments | Creation, pagination/search, cancellation/retry/history, coverage-aware retest comparison | Process-local check ownership; restart marks interrupted jobs; no scheduler/durable assessment queue |
| Scan jobs | Complete server pagination, literal ID/engine search, status/source filters, scoped asset names and independently loaded execution records | Records reflect stored execution; no durable scheduling or automatic polling |
| Checks | Bounded HTTP headers/cookies/TLS/security.txt/DNS and constrained Nmap; managed training target | Non-exploitative and intentionally limited; no exhaustive scanner or production sandbox |
| Finding imports | Nmap, Nuclei, Semgrep, Trivy, ZAP, Gitleaks and Checkov with synthetic fixtures | Import assertions remain unverified; not every upstream schema is supported |
| API/SBOM inventory | OpenAPI and CycloneDX/SPDX JSON import, deduplication and asset inventory view | Inventory only; no endpoint execution, external references or dependency completeness guarantee |
| Findings | Normalization, scanner fingerprints, server filters/search/pagination, atomic triage history, bulk triage/owner and comments | Cross-scanner correlation and advanced CVSS/version workflows remain |
| Intelligence | Cached FIRST EPSS/CISA KEV/NVD/direct OSV CVE facts, offline/stale behavior and attribution | Heuristic prioritization; direct OSV ID misses do not rule out aliases |
| Remediation | Task creation/edit, complete stage pagination/search/assignee/UTC-overdue filters, progress/completion and organization SLA policy | Assignees are labels; task completion does not resolve findings |
| Exports/evidence | Private CSV/JSON export, formula escaping, chunk integrity/completion, download checksum checks and complete evidence register/search/upload-status filter | Complete-set operation caps; evidence size limits; no malware scanning or retention policy |
| Reports | Technical/executive/remediation PDFs, preview, branding/custom sections, versions, integrity-checked source snapshots and complete report register/search/template/status filters | Bounded complete sets and output sizes; no public sharing or scheduling |
| AI | Optional Claude/OpenAI/Gemini/Ollama/compatible interfaces, model allowlists, health, usage and context redaction | No live provider validation; redaction is heuristic; no tool invocation |
| Overview | Complete server counts and severity chart, query-time coverage disclosures and explicit failure states | Not a security score; counts can change between queries; previews/selectors remain bounded |
| Webhooks | Encrypted opt-in configuration, pinned HTTPS/HMAC delivery, leased outbox, bounded retries/history, secret rotation and removal | No exactly-once delivery or atomic domain-write/outbox transaction; no live destination activated |
| Audit | Complete organization event navigation/filter/detail view and private account history with attribution/tenant checks | Not tamper-proof; account history is best effort |
| Other integrations | Generic signed webhooks are available | Native ticket/chat/email/SIEM adapters remain |
| Operations/release | Backend/frontend/Docker/real Nginx Chromium pipelines | Retention, backup/restore, monitored deployment, rollback, broader accessibility and release controls remain |

## Latest acceptance evidence

| Check | Result | Run |
|---|---|---|
| Backend Python 3.11/3.12 with MongoDB | 189 passed | [38891351963](https://github.com/ibrahim1101/vapt-x/actions/runs/38891351963) |
| Frontend unit/components and production build | 65 passed, 24 suites; build passed | [38891351892](https://github.com/ibrahim1101/vapt-x/actions/runs/38891351892) |
| Docker smoke | Passed | [38891351914](https://github.com/ibrahim1101/vapt-x/actions/runs/38891351914) |
| Chromium against Nginx/Compose | Passed | [38891351931](https://github.com/ibrahim1101/vapt-x/actions/runs/38891351931) |

Mongo tests include tenant boundaries, concurrent authentication/MFA budgets, membership demotion races, account disable/reactivation, token membership lifetime, imports, evidence, PDF snapshots and retests. The browser uses synthetic identities and the controlled training target. No external scan, live AI request, actual user disablement, merge, release or deployment was performed.

Evidence, report, authorization, membership, scan-job, remediation and audit registers now query complete matching collections, with live 25-row pages. Pagination offsets remain capped at 1,000,000. Selection menus and workspace previews remain bounded; dedicated registers query complete server collections.
