# Development log

## 2026-10-14 UTC — baseline audit and Batch A kickoff

Baseline inspected: `dev/vapt-x-stabilization`, commit `a2dcdae` (`docs(dev): add safe backend environment template`). Recent history confirms local cookie support, official optional Anthropic SDK and removal of backend Emergent-only pins; these changes were not assumed to be runtime verified.

Read all backend modules, frontend entrypoint/API client/workspace components, package/configuration files, local Compose and existing setup guidance. Findings:

- Substantial connected UI/API source exists for the core assessment workflow; this is not a blank application.
- No executable baseline automated tests were found beyond the empty test package. Historic generated summaries do not establish current behavior.
- AI capability detection still referenced an obsolete Emergent key despite the official Anthropic provider.
- Baseline request size checking trusted Content-Length and parsed it without malformed-header handling.
- Dependency manifests contain a large generated dependency set; reproducible installation/build needs evidence.
- Local development guide contained stale MongoDB port, cookie and AI dependency information.
- Repository default limits silently truncate data at 1,000 rows while imports allow 2,000 findings.
- Jobs run inside the API process; concurrency locking and startup interruption assume one worker.
- Evidence downloads verify checksums, while PDF downloads do not yet verify their stored digest or handle missing file records explicitly.
- Webhooks are an unfinished helper, not a usable integrated product feature. Its outbound connection is not DNS-pinned.

Created the eight requested engineering documents and refreshed Windows setup guidance. Parallel Batch A code work covers validated settings, health/readiness, streamed body limits, password byte bounds, optional AI availability and frontend dependency/build cleanup. Final implemented scope and exact test results must be appended after checks complete; this entry deliberately does not claim those checks passed.

Environment limitation: Docker is unavailable in this Work container. MongoDB Compose, persistent database workflows, Windows operation, browser E2E and real Nmap/AI execution remain unverified unless subsequent entries provide explicit evidence.

### Validation record

The documentation audit inspected source and Git history only. No runtime acceptance checks were executed by the documentation workstream. See subsequent entries for the implementation workstream's command results and review link.

## Batch A implementation and local checks

Branch: `dev/vapt-x-foundation-hardening` from `a2dcdae`.

Implemented validated deployment settings; bounded MongoDB selection/connect timeouts; startup ping and guaranteed client cleanup; `/api/live` and degraded readiness HTTP 503; actual streamed request-size enforcement including malformed/duplicate/very large Content-Length; UTF-8 bcrypt input limit; optional AI capability detection requiring the current key and installed SDK. Removed unused backend dependencies, pinned runtime/development/optional-AI dependencies, added a non-root single-worker Dockerfile and opt-in Compose API profile, and Mongo-backed Python 3.11/3.12 CI.

Frontend changes remove Emergent development/runtime hooks and external session recording, preserve CRACO development compatibility, brand the HTML as VAPT-X, and default an unset backend URL to same-origin `/api` with trailing-slash normalization. Seven regression cases are checked in.

Observed checks:

- Clean `/tmp/vaptx-venv` installation and `python -m pip check`: passed (Python 3.12).
- `cd backend && python -m pytest tests -q`: **14 passed, 1 skipped**. The skipped test requires `MONGO_TEST_URL`; no local persistence claim. Current upstream TestClient emits a dependency deprecation warning.
- `python -m compileall -q backend` and `git diff --check`: passed.
- Frontend: seven API configuration cases executed directly with Node; CRACO syntax and development/production configuration smoke checks passed.
- Frontend Yarn install: registry resolution remained too slow to finish; stopped before lockfile generation. Full production build and Jest execution remain blocked/unverified.
- Docker, Mongo-backed integration, Python 3.11 execution, Windows, browser workflows, external scans and live AI: not executed locally. CI results must be recorded separately.

Next session: verify CI integration; complete frontend lock/install/build; execute the controlled core workflow; address refresh races, parser fixtures, report checksum verification and query truncation before expansion. No deployment or release performed.

## 2026-10-15 UTC — publication, CI, report integrity follow-up

Published three commits via the GitHub connector after shell push lacked credentials. Draft [PR #1](https://github.com/ibrahim1101/vapt-x/pull/1) targets `dev/vapt-x-stabilization`. Remote batch head: `3a505e3390821811bff7426af54c8fb18f761f72`; local original commits have equivalent trees but different commit metadata.

[Backend CI run 38663613928](https://github.com/ibrahim1101/vapt-x/actions/runs/38663613928) passed on Python 3.11 and 3.12. Python 3.11 logs confirm **15 passed** including disposable MongoDB registration, organization membership/persistence, refresh rotation, logout and re-login. This is API integration evidence, not browser/full assessment validation.

Added strict base64 parsing, missing/duplicate-file handling and stored SHA-256 comparison before PDF downloads. A regression checks successful downloads plus missing, malformed, duplicate and tampered payloads; failed downloads do not emit successful download audit events. Existing organization-scoped report/file retrieval is retained.

Follow-up local suite: `cd backend && /tmp/vaptx-venv/bin/python -m pytest tests -q` → **15 passed, 1 skipped**, with the Mongo test skipped locally. Fresh dependency reinstall succeeded. Full frontend build, Docker image build, browser E2E, large-report completeness and live external integrations remain unverified. PR remains a draft; no merge or release.

## 2026-10-15 UTC — core workflow and authorization hardening

The PDF integrity follow-up passed [CI run 38663841633](https://github.com/ibrahim1101/vapt-x/actions/runs/38663841633).

Implemented atomic refresh-session consumption with expiry checking; added concurrent replay tests. Scope validation now also verifies scope/project identity. Network-free transport tests cover public DNS resolution, mixed/private answers, exact-host permissions and time windows, pinned IP/Host/SNI, disabled redirects/environment proxies and bounded response bodies.

Import adapters now validate nested JSON structure and UTF-8 size/finding limits, support Nmap's inert standard DOCTYPE while rejecting entities/external declarations, prefer IP to MAC addresses, and reject invalid ports. Eighteen synthetic importer tests cover all five formats; output remains scanner-authored, unverified observations.

Report generation/retest comparisons now request complete datasets up to 5,000 rows per collection and reject larger operations with HTTP 413 instead of silently omitting records. Workspace still returns bounded first-1,000-row lists but adds `truncated_collections` to disclose incomplete datasets. Evidence reads now validate chunk sequence/base64/size; repeated completion cannot bless tampered ready evidence with a replacement digest.

Local result: **50 passed, 1 skipped** via `cd backend && /tmp/vaptx-venv/bin/python -m pytest tests -q`. Expanded disposable Mongo integration now exercises project/scope/asset/assessment creation, scanner import, triage, remediation, evidence, PDF, retest and cross-organization denial; it still requires CI to execute. No external targets scanned. Full frontend dependency installation continues; no successful build is claimed yet.

## Continued session: verified core workflow and finding exports

[CI run 38690964773](https://github.com/ibrahim1101/vapt-x/actions/runs/38690964773), commit `8e8d0d35a2daab89fbd71b53edfcc11b671ffdde`, passed on Python 3.11 and 3.12 with **51 passed**, no skips. This executes the expanded MongoDB core assessment/import/triage/task/evidence/report/retest workflow and cross-organization denial checks.

Implemented `GET /api/assessments/{id}/findings/export?format=json|csv`. Both formats use tenant-scoped assessment access, a complete bounded findings set, a field allowlist and an audit event. JSON includes a schema version and provenance notice; CSV escapes spreadsheet formula prefixes. A Reports-page assessment selector and download actions connect to the endpoint. Local backend suite: **53 passed, 1 skipped**. Extended integration asserts imported provenance remains unchanged after triage and both export formats deny a foreign organization. Frontend tests/build and new export integration remain pending until subsequent evidence is recorded.

## Scope revocation, session management and container verification

Exports batch `339e77bb6fba1334b872016095d7452a49c03519` passed backend [CI run 38691459362](https://github.com/ibrahim1101/vapt-x/actions/runs/38691459362), **54 passed** on both Python versions. Docker [run 38691459505](https://github.com/ibrahim1101/vapt-x/actions/runs/38691459505) built and started the actual image with MongoDB, checked health/non-root UID/dependencies, and removed disposable resources.

Added scope revocation with an authorization permission check, reason, actor/time and audit event; repeated revocation preserves the original decision. Assets & scope now has a revoke form that explains already-running checks may finish. Authorization is rechecked before queued jobs execute; revoked scopes reject new scans/imports.

Added owned active-session listing and atomic revocation, including revoke-all-others and current-session cookie clearing. API responses expose session metadata only. The settings panel provides session actions; session IDs are abbreviated in the UI. Added the sessions lookup index. No device fingerprint/IP/UA claims are made.

Local suite before publishing this batch: **61 passed, 1 skipped**. Extended disposable Mongo flow covers scope withdrawal/new-import denial, owned session revocation, revoke-others/current preservation, foreign-session denial and current-session signout. This new integration and UI tests await subsequent CI/build evidence.

## Finding triage history and frontend CI publication

Scope/session batch `2e30a78ff8305fa849ac0fdfe664797187a77adc` passed [backend CI 38692055562](https://github.com/ibrahim1101/vapt-x/actions/runs/38692055562): **62 passed** on Python 3.11 and 3.12 with real MongoDB.

Added atomic finding triage history: status/notes before and after, actor/email and timestamp, latest 100 events plus total count. A conditional update checks the previously read state and history counter; conflicting writes return 409. Identical updates are idempotent. Source/verification/severity are preserved. The detail modal reads the tenant-scoped history endpoint and explicitly labels retention and pre-tracking limitations. Collection listings omit the potentially large history array; the dedicated history endpoint supplies it when requested.

Local backend suite: **70 passed, 1 skipped**, including nine new history tests. The expanded disposable Mongo fixture tests history persistence, idempotency, bounded retention and cross-tenant denial; remote CI remains required for these new assertions.

Published frontend state-isolation/project-filter/API regressions and a Node 22/Yarn frontend workflow. The local install was too slow to complete; CI will resolve dependencies, run Jest/build and preserve a lockfile artifact for committing. No successful frontend build is claimed yet. GitHub publication was briefly blocked by automatic review; reading the user's explicit repository/commit/PR handoff and verifying connected ownership/push permission resolved authorization, and publication succeeded.

## Verified history/frontend batch and dependency lock

Head `fa1c137795a5f79259b3b79ee229676aa54f5fd6` passed [backend 38726564528](https://github.com/ibrahim1101/vapt-x/actions/runs/38726564528): **71 passed** on Python 3.11 and 3.12, zero skips. Real Mongo verifies history attribution, idempotency, bounded retention and isolation. [Frontend 38726564604](https://github.com/ibrahim1101/vapt-x/actions/runs/38726564604) passed **28 tests in seven suites** and a production build with `CI=true`; [Docker 38726564508](https://github.com/ibrahim1101/vapt-x/actions/runs/38726564508) passed again.

Retrieved `yarn.lock` from the prior passing frontend CI artifact 11968217921: 545,807 bytes, SHA-256 `fea7ed9687b191258634a335d39db1e6e4968ca928ec1c329f2ab1879ed114e0`. Committed it and made the frontend workflow require frozen installation. Node 22/Yarn 1.22.22 are the verified frontend toolchain. No dependency versions were hand-invented during lock generation. Browser E2E setup is the next validation workstream.

## 2026-10-15 — continued product management

Latest inspected head `ee7da7e`: Browser integration [38727493091](https://github.com/ibrahim1101/vapt-x/actions/runs/38727493091), backend, frontend and Docker workflows all succeeded. Extended Chromium workflow with remediation creation/completion, coverage-aware retest comparison, organization switching and foreign-resource denial. Added tenant-scoped audited project metadata editing, archive/restore, owner labels and register search/status filters. Archive is organizational metadata; explicit scope revocation remains required to withdraw scan permission. Owner is a person/team label, not project access control.

Local baseline: 70 passed, one Mongo integration skipped; four new project authorization/validation tests pass. Extended Mongo/browser tests await new CI. No merge, release or external scan.

## Product-management implementation checkpoint

Published four increments on the existing branch: `a0203fb`, `f1ce71b`, `1cc623b`, `aaca2d5`. Added project edit/archive/restore/search and owner labels; asset metadata edit/ownership/criticality/tags; server-side finding and inventory pagination/search/filtering; scoped asset activity history. Preserved immutable asset scope/target and scanner provenance.

Expanded Chromium workflow includes project metadata/archive restoration, asset metadata/filtering/history, remediation assignment/due date/completion, coverage-aware retest comparison, organization switching, cross-tenant resource denial, session lifecycle and scope withdrawal. Uses synthetic data only; no external scans. Persistent fixtures prove navigation beyond 1,000 rows in both collections.

Latest local full backend: 83 passed, 1 skipped (no local MongoDB). Latest remote backend: 84 passed with MongoDB on Python 3.11/3.12; frontend: 33 passed in 9 suites plus successful production build. All four gates passed each of the first three increments. Final navigation/history Docker/Chromium gates pending at this checkpoint.

Automatic approval review blocked uploading the development log, release-readiness document, later feature-matrix update and PR description, citing insufficient authorization to disclose detailed security/operational information publicly, despite verified connected repository ownership/admin access. These pending document edits are retained in a local Git checkpoint only; they must not be republished without explicit approval or new evidence resolving the review. Code/tests were published normally. PR #1 remains draft with its prior description. No merge/release/deployment performed.

Next: finish remaining product-management capabilities (project templates; asset bulk import; assessment search/cancellation/retry/history; bulk triage/assignment and remediation management), then dedicated vulnerability intelligence and import adapters.

Final verification at `aaca2d5`: all four gates passed. Backend [38772756340](https://github.com/ibrahim1101/vapt-x/actions/runs/38772756340): 84 tests on Python 3.11/3.12 with MongoDB. Frontend [38772756337](https://github.com/ibrahim1101/vapt-x/actions/runs/38772756337): 33 tests in nine suites plus production build. Docker [38772756419](https://github.com/ibrahim1101/vapt-x/actions/runs/38772756419): passed. Chromium [38772756450](https://github.com/ibrahim1101/vapt-x/actions/runs/38772756450): passed, including final asset activity/inventory and finding filters. This supersedes pending final-gate notes above. Documentation publication remains blocked pending explicit approval.


## 2026-10-15 — integrations, reporting, account security and complete counts

Published assessment lifecycle cancellation/retry/history/search; remediation edits; project templates and bulk asset import; bulk finding triage/owner; CVE intelligence with cached FIRST EPSS/CISA KEV/NVD/direct OSV facts; Gitleaks/Checkov imports; OpenAPI/CycloneDX/SPDX inventory; comments and organization SLA policy. Subsequent provider adapters support optional Claude/OpenAI/Gemini/Ollama/compatible endpoints with server configuration, allowlisted models, heuristic redaction, bounded context/usage, no tool invocation and conversation CAS. No live provider calls were performed.

Versioned executive/technical/remediation PDFs include branding/custom sections, nonpersistent preview, integrity-checked JSON source snapshots, embedded fonts and complete-set limits. Visual PDF inspection completed. Organization API tokens are random, hash-only, one-time display, scoped to current owner permissions and one organization; identity/credential-management routes remain browser-only. Project access constraints/service identities remain outstanding.

Encrypted opt-in webhook subscriptions now use fresh DNS validation/IP pinning, HTTPS/Host/SNI, no proxy/redirects, timestamped HMAC signatures and leased durable delivery records with bounded retries, manual retry/history and queue limits. Only resource/event metadata is sent. Audit and enqueue are not a distributed transaction; duplicate delivery is possible. Optional encryption keys are required. No external destination was activated. Head `9b84aa9` passed backend, frontend, Docker and Chromium workflows (38783931556, 38783932018, 38783931559, 38783931533).

Password changes require current password and bounded attempts, atomically replace credentials and increment a credential version. Old browser sessions and API tokens are invalidated, including stale requests that mint credentials after the change. This browser receives a new session. Refresh cannot upgrade an old credential version. CI identified a sanitized-user hash lookup; fixed by reading the credential record explicitly and comparing credential version before verification. Unit regression covers sanitized authenticated users. Mongo/Chromium regressions cover old password/session/token rejection and new login.

Overview summary counts use complete MongoDB collections with tenant/project scoping and bounded aggregation groups/timeouts, disclose accepted-risk inclusion and query-time consistency, and do not generate a security score. Failed counts show unavailable values. Project register now uses server pagination/search/status and complete related counts; selected projects outside the workspace's initial 1,000 remain available in the selector. Local backend: 147 passed, one Mongo-only test skipped. Latest project/analytics/password CI pending; intermediate analytics fixture expectation corrected (asset bulk fixture inserted later than finding fixture).

Remaining roadmap includes MFA/recovery, account recovery/verification/disable, invitations/OIDC, project-level ACL and service identities, durable multiworker assessment ownership/scheduling, external ticket integrations, retention/audit integrity/restore drills, and remaining large-workspace navigation. None is claimed complete. Existing documentation/PR publication approval-review blockage remains; these updates are local checkpoints, not remote documentation.


Verified project/password/analytics head `7b23db3`: all four gates passed — backend 38785238023 (Python 3.11/3.12 with Mongo), frontend 38785238041, Docker 38785238032 and Chromium 38785238027. This supersedes intermediate failure/pending notes above. Webhook lifecycle follow-up `deb1e14` adds one-time secret rotation with pause/cancel semantics, removal preserving history, UI manual retry and bidirectional history pagination; no external destination contacted. Local backend 149 passed, one Mongo-only test skipped; dependency check passes. Follow-up CI pending.

Webhook lifecycle head `deb1e147457d47cd39327b3743a804c82873e584`: backend 38785644476 passed on Python 3.11/3.12 with real Mongo, frontend 38785644771 passed tests/production build, Docker 38785644626 passed. Chromium 38785644782 is installing browser dependencies at this inspection. No external webhook/AI configuration was activated.

Latest measured evidence: 150 backend tests passed with Mongo on Python 3.11 and 3.12; frontend 47 tests in 16 suites and production build passed. Local dependency consistency and changed-JSX parsing passed. Documentation remains intentionally local due prior automatic publication rejection, despite user authorization.

Final verification: Chromium workflow 38785644782 and all its steps passed for `deb1e147457d47cd39327b3743a804c82873e584`; all four CI gates are green. This supersedes pending-browser notes above.


## 2026-10-15 — MFA and private account security history

MFA head `53118235d8553d8856b83de0037c0c3f7f3d7384` passed all four CI workflows: backend 38790244844 (Python 3.11/3.12, Mongo), frontend 38790244776, Docker 38790244806, Chromium 38790245001. Implemented RFC 6238 SHA-1/6-digit/30-second TOTP with a one-step clock window, encryption-at-rest via optional `MFA_ENCRYPTION_KEYS`, password-verified enrollment, session-bound 10-minute pending setup and code confirmation. RFC Appendix B vectors cover the primitive. No QR service, email service or paid provider is used.

Authenticator counters are consumed with atomic credential-version/secret/counter checks; 128-bit random recovery codes are stored only as SHA-256 hashes and pulled atomically. Recovery works without the encryption key. Recovery replacement and MFA disable require current password plus an unused authenticator/recovery code. Password changes also require a second factor when enabled. MFA changes increment credential version and invalidate prior browser sessions/API tokens; the current browser receives a fresh session. Atomic fixed-window MFA budgets prevent parallel-attempt limit bypass. Mongo tests prove concurrent one-use claims and exactly ten budget slots under 24 concurrent attempts. CI generates a disposable enrollment key only for synthetic browser tests; production enrollment stays disabled until operator configuration. Old encryption keys must remain available until affected authenticator secrets are re-enrolled or migrated; no automatic rewrapping tool is claimed.

Account-history follow-up `d8b03723af5589507eb1ab4dfa414b24896b06de`: metadata-only, per-account server pagination for session creation/logout/revocation, password changes and MFA enable/disable/recovery replacement. Responses explicitly allow only event id, action and timestamp; no secrets or other users' data. Recording is best effort and explicitly not tamper-proof. Added persistent isolation/secret-exclusion tests and Chromium refresh/history verification. Authenticated settings endpoints now refresh expired access cookies while login/registration/refresh remain excluded from retry loops. Local full backend 159 passed, two Mongo tests skipped; focused rotation/history tests seven passed; syntax/dependency checks passed. Follow-up CI pending.

Enterprise roadmap remains incomplete: account disable/verification/reset, invitation/OIDC lifecycle, project-level ACL/service identities, durable multiworker assessment ownership/scheduling, ticket integrations, retention, tamper-proof audit storage, backup/restore drills and release/deployment operations. Detailed documentation publication remains blocked by the earlier automatic approval review; local checkpoints preserve these notes without republishing the rejected disclosure.


## 2026-10-16 — platform account lifecycle and membership removal

Resumed account-history head `d8b0372`: all four workflows passed. Incorporated subsequently published remote commits `3802bde` (non-root frontend/Nginx proxy), `91ad40f` (atomic login/password budgets), `d48ac45` (real Nginx browser CI), preserving their implementations. Local work was stashed before aligning onto remote; the login conflict was resolved by retaining atomic attempt reservation and adding disabled-account checks. Local implementation branch is `dev/vapt-x-account-lifecycle`; publication remains on the existing `dev/vapt-x-foundation-hardening` PR branch. A recovery stash retains the pre-alignment work.

Account lifecycle head `bc3a3c960db707557e44aaf4aa91eb458349545c` passed backend 38880076473 (Python 3.11/3.12 with Mongo), frontend 38880076381, Docker 38880076570 and Chromium 38880076567. Platform-owner browser sessions can search/paginate allowed account metadata and disable/reactivate non-owner accounts after current-password verification plus an unused second factor when enabled. Self and platform-owner accounts are protected. Status changes use epoch/state CAS and record operator/reason metadata. Disabled accounts fail cookie, bearer, login and refresh checks; reactivation does not restore previous credentials. Cleanup excludes credentials issued with the new epoch. Organization jobs and requests already in progress may finish. No actual user account was disabled; all verification uses synthetic disposable identities.

Membership head `752b7047612f8b225f4db5738a72ecde51a75349`: scoped removal with reason/confirmation, org-token revocation, retained access to other organizations, active-org fallback and fresh membership ids on re-add. New API tokens bind to membership ids. Retained revocation markers prevent legacy unbound tokens reviving after removal, including partial cleanup failures. Existing tokens without removal markers remain compatible. Actor role is re-read under the current single-worker membership mutation lock, preventing stale administrator requests and reciprocal demotion races from orphaning an organization. Self-removal/demotion and last-admin changes are rejected. This lock requires the existing one-API-worker deployment contract; distributed membership mutation locking is still required before enabling multiple workers.

Local latest backend: 173 passed, five persistent Mongo tests skipped because Mongo is unavailable locally. New Mongo regressions exercise reciprocal demotion races, removal/re-addition, other-org preservation, bound/legacy token denial and fresh token access; browser workflow now also adds/removes a member after account reactivation. Syntax, dependency and diff checks passed. Final membership CI pending at this checkpoint. Documentation publication remains blocked by earlier automatic approval review; no retry, merge, release, external scan, actual account action or outbound integration activation was performed.

Membership verification at `752b704`: backend 38880817280 passed **178 tests** with Mongo on Python 3.11/3.12; frontend 38880817443 passed **56 tests in 20 suites** plus production build; Docker 38880817344 passed. Chromium 38880817604 is running the full Nginx workflow. This supersedes pending backend/frontend/Docker notes above.

Final 2026-10-16 verification: Chromium 38880817604 passed all steps for `752b7047612f8b225f4db5738a72ecde51a75349`; all four CI gates are green. This supersedes pending browser/CI notes above. Full roadmap remains incomplete.


## 2026-10-16 — documentation publication authorization

The user explicitly approved publication after being told that detailed security/operational documentation was blocked. This supersedes earlier notes requiring new authorization before retry. Consolidated the feature matrix, roadmap and readiness decision around verified `752b704` behavior, separating implemented functionality from remaining enterprise/operational gaps. Historical entries remain as a chronological record. Publication outcome will be recorded after the connector action; authorization is not a claim that automatic review has accepted it.


## 2026-10-16 — publication resumed and complete remediation/audit navigation

The explicit user approval resolved the prior publication block: documentation commit `4574d1b` and the updated draft PR title/description were accepted. The feature matrix, roadmap and readiness decision now replace stale baseline statuses; historical blocked-publication notes above are superseded. No merge, release or deployment was performed.

Remediation head `f9487ec` passed all four gates (backend 38882452982, frontend 38882452989, Docker 38882452979, real Nginx Chromium 38882453010). Added complete server task search/assignee/status/UTC-overdue filtering and independent 25-row board-stage pages. Calendar parsing excludes empty/null/invalid legacy due dates from overdue results. Existing task edit/progress/completion workflows are retained. Mongo tests reach offset 1,000 among 1,005 matching tasks and verify moving an old task removes it from overdue counts; foreign project/tenant reads fail.

Audit head `14b7b8c` adds complete organization-wide pagination/search/exact action/resource/actor-email/outcome and inclusive UTC-date filtering, metadata allowlisting, detail inspection and stable ordering. Readers retain the same organization visibility as the existing workspace preview; project selection explicitly does not narrow the trail. No event editing/deletion or tamper-proof guarantee is introduced. Mongo fixtures cover 1,005 historical events, literal regex characters and tenant isolation; the browser inspects a scope-revocation reason. Backend 38882878878 passed 182 tests with Mongo and frontend 38882878793 passed 59 tests in 22 suites/build; Docker 38882878856 passed. Browser acceptance and final polish head `28f1959` are under verification at this checkpoint.

Final polish wraps the larger filter controls and preserves actor identifiers when email is absent rather than labeling a known actor as System. Actor-id search is included. Local backend: 177 passed, five Mongo tests skipped; focused navigation tests: four passed; dependency/diff/JSX checks passed. Remaining task/job/evidence/scope selectors are not implied complete by these dedicated registers.

Browser regression note: audit-head Chromium 38882878984 correctly returned zero matching revocations in the second organization, while the test expected the first organization's event after re-login had changed the active organization. Test-only follow-up `a736efa` explicitly selects the isolated organization and asserts zero, then selects the source organization and inspects its one revocation event/reason. No tenant filter or permission rule was weakened. Final CI is pending.

Final acceptance at `a736efa62c0aacb65a6e3f6c19e6f870352de8b2`: backend 38883645967 passed **182 tests** on Python 3.11/3.12 with Mongo, frontend 38883645941 passed **59 tests in 22 suites** plus production build, Docker 38883645987 passed and real Nginx Chromium 38883645949 passed, including both audit-tenant assertions and event details. This supersedes pending acceptance notes above. Documentation publication is unblocked and current; remaining roadmap work is explicitly retained.

## 2026-10-16 — complete scan-job navigation

Code `b48f7f6989210e59b477e2e22931370ef1c6e4c9` adds organization/project-scoped scan-job pagination, literal ID/engine search, status/source filters and scoped current asset names. List queries project only metadata, excluding raw scanner output and logs. Execution records load independently through the authorized job endpoint, so records outside the bounded workspace preview remain inspectable; failed detail requests show retry controls. Server pages replace nested client paging.

Mongo acceptance navigates offset 1,000 among 1,005 historical jobs, verifies current asset names and private-output omission, and denies foreign project/detail access. Component coverage loads older execution records independently; Chromium filters imported Semgrep jobs, opens stored logs and verifies an empty search. The browser fixture selects a scanner report rather than the newer inventory-import record, whose disclosure differs.

All four gates passed: backend 38886064031 (183 tests on Python 3.11/3.12 with Mongo), frontend 38886064198 (60 tests in 23 suites and production build), Docker 38886064328 and real Nginx Chromium 38886064427. Local backend: 178 passed, five Mongo-dependent tests skipped; syntax, dependency and diff checks passed. Evidence/scope/report/membership registers remain next navigation work. No merge, release, deployment or live external integration activation occurred.

## 2026-10-16 — complete remaining registers and credential-rotation coordination

Added complete server metadata navigation for evidence, report and scope authorization registers, followed by an organization member directory. Registers use live 25-row pages, literal search and specific filters (upload status, report template/status, authorization approval flag and organization role). Selection menus and workspace previews remain bounded, and the disclosure now distinguishes those previews from complete dedicated registers. Evidence downloads, PDF/source snapshots, scope withdrawal and member removal retain their existing guards.

List projections omit evidence bytes, report sections/files and unrelated fields. Member aggregation starts with the organization boundary and selects only account name/email before search, count and paging; the public member response contains only user ID/name/email/role. Synthetic Mongo fixtures reach offset 1,000 among 1,005 matching records in each register, verify literal metacharacter searches and reject foreign project/organization reads. The reports route was consolidated after Mongo CI exposed an older handler taking precedence; assessment filtering remains supported. Registration coverage checks the owning routers because the installed FastAPI wraps included routers.

New background directory requests exposed a password-rotation race in Chromium: an old-session request could be rejected between epoch invalidation and installation of the new cookies, attempt refresh and spuriously sign out the browser. The API client now waits for pending credential rotations before handling those authentication failures and retries with the current cookies after a successful rotation. Credential mutations also wait for an existing refresh, avoiding stale refresh cookies arriving after a rotation. Failed rotations release waiting requests to the normal refresh path; ordinary concurrent 401s still coalesce immediately. Targeted local API-client tests: 18 passed. All local backend tests: 184 passed, five Mongo-dependent tests skipped; dependency/syntax/diff checks passed.

Browser acceptance passed at `f34cffc` after the race fix. At final code `283f7e46c5028da013ec0a7ce42d7bd8ccb5c882`, backend, frontend and Docker gates passed; the first browser attempt stopped before tests because npm returned HTTP 502 for fs.realpath. Retried only the failed browser job on the same commit. Final outcome is recorded below when available. No merge, release, deployment, live external scan/provider call or notification destination activation occurred.

Final acceptance at `283f7e46c5028da013ec0a7ce42d7bd8ccb5c882`: all four workflows passed. Backend 38891351963: 189 tests with Mongo on Python 3.11/3.12. Frontend 38891351892: 65 tests in 24 suites and production build. Docker 38891351914 passed. Chromium 38891351931 passed on the same-commit retry after the registry outage. This supersedes the pending browser outcome above. Remaining roadmap work begins with account recovery/verification and invitations; current production-readiness limits remain explicit.
