# Implementation status

Updated 2026-10-16. Review: [draft PR #1](https://github.com/ibrahim1101/vapt-x/pull/1). Current verified code: `a078dd3bacfa7528d4e506c378680d18f3c0bfb0`. This document describes implemented behavior; passing synthetic tests do not establish production readiness or exhaustive security coverage.

| Area | Implemented and exercised | Remaining limits |
|---|---|---|
| Runtime | Validated configuration, bounded request bodies/health, pinned backend dependencies and frozen Yarn installation | Production deployment and upgrade/restore drills remain |
| Containers | Non-root API and Nginx frontend, fixed API proxy, Compose health/smoke tests | One API worker; local Mongo service is for development |
| Authentication | Cookie sessions, CSRF/origin controls, atomic refresh rotation, coordinated browser credential changes/retries, password changes, stored-session expiry, database-enforced attempt budgets and open/invitation-only/closed registration | Identity/mail integrations require explicit configuration |
| OIDC | Explicit existing-account link/unlink, fixed provider code flow with PKCE/nonce/signature checks, one-use browser proof, local MFA and epoch invalidation | Disabled by default; no discovery/provisioning/forced SSO/provider logout synchronization or live provider acceptance |
| Email verification | Optional TLS mail, hash-only 24-hour one-use links, account/address/epoch binding, explicit confirmation, private status and optional required workspace admission | Limited account sessions remain usable; delivery stays opt-in and mocked |
| Invitations | Optional administrator send/list/revoke, authenticated organization/role preview, matching-email acceptance, seven-day expiry, fresh issuer authority and role preservation | Single-worker lock; non-transactional claim/membership/audit writes; no durable mail queue |
| Password recovery | Optional TLS SMTP, hash-only expiring one-use links, credential-epoch binding, MFA preservation and old credential invalidation; private fragment-based form | Disabled by default; no durable mail queue or live delivery acceptance |
| MFA | Encrypted TOTP enrollment, atomic anti-replay, hash-only one-use recovery codes, replacement/removal, step-up for password changes | Optional operator key; no automatic key rewrapping |
| Accounts | Private paginated security history; platform-owner search and disable/reactivate with password/MFA | History is best effort; owner accounts protected; in-flight work may finish |
| Organizations | Switching, fixed roles, membership grants/removal, fresh actor and anti-orphan guards, complete member directory/search/role filters and email-bound invitation lifecycle | Invitation acceptance requires the registered matching account; Custom roles and independent service identities remain |
| API tokens | One-time display, hash-only storage, expiry/revocation, organization/current-role/membership binding, live owner project admission and optional fixed project caps | No independent service identities or custom roles |
| Tenant boundaries | Organization and membership-project predicates, negative API/browser tests including downloads and jobs | Per-project role overrides/custom roles remain |
| Project access | Administrator all/selected membership grants, live browser/token enforcement, scoped counts/files/audit and version-checked updates | Existing grants/invitations default to all; admins retain all; in-flight work and previously downloaded data cannot be recalled |
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
| Key rotation | Operator-only streaming MFA/webhook/OIDC secret rewrapping; dry-run default, ciphertext compare-and-swap and original timestamp preservation | No automatic schedule, key distribution/escrow or backup/restore acceptance; retain keys for in-flight/old writers |
| Operations/release | Backend/frontend/Docker/real Nginx Chromium pipelines | Retention, backup/restore, monitored deployment, rollback, broader accessibility and release controls remain |

## Latest acceptance evidence

| Check | Result | Run |
|---|---|---|
| Backend Python 3.11/3.12 with MongoDB | 245 passed | [38931136162](https://github.com/ibrahim1101/vapt-x/actions/runs/38931136162) |
| Frontend unit/components and production build | 98 passed, 29 suites; build passed | [38931136262](https://github.com/ibrahim1101/vapt-x/actions/runs/38931136262) |
| Docker smoke | Passed | [38931136342](https://github.com/ibrahim1101/vapt-x/actions/runs/38931136342) |
| Chromium against Nginx/Compose | Passed | [38931136205](https://github.com/ibrahim1101/vapt-x/actions/runs/38931136205) |

Mongo tests include tenant boundaries, concurrent authentication/MFA budgets, membership demotion races, account disable/reactivation, token membership lifetime, imports, evidence, PDF snapshots and retests. The browser uses synthetic identities and the controlled training target. No external scan, live AI request, actual user disablement, merge, release or deployment was performed.

Evidence, report, authorization, membership, scan-job, remediation and audit registers now query complete matching collections, with live 25-row pages. Pagination offsets remain capped at 1,000,000. Selection menus and workspace previews remain bounded; dedicated registers query complete server collections.
