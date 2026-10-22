Warning: truncated output (original token count: 17057)
Total output lines: 359

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

The user explicitly approved publication after being tol…3057 tokens truncated…tadata/search/status, revocation, authenticated organization/role preview and explicit matching-email acceptance. Links last seven days and are hash-only. Issuer account state, administrator membership identity and credential epoch are checked again before granting access. Recipient state/credentials and normal Origin/CSRF checks remain required. API tokens cannot enter these account/administration routes. Existing roles and other memberships remain unchanged, and removed-member credentials do not revive when the recipient rejoins.

Mongo acceptance races a single invitation, checks wrong-account and cross-organization denial, preserves a role granted after issuance, tests revocation/expiry/stale issuer permissions and credentials, preserves another organization's token, rejects removed-member tokens after rejoining and navigates offset 1,000 among 1,005 matching records. The initial multi-account fixture copied cookies into plain dictionaries, losing domain/path attributes and causing HTTPX CookieConflict after a later registration. Preserving cookie objects corrected the fixture without changing application authorization. Added app-level tests for initial invitation landing without organizations and same-document links followed by switching accounts, sign-in and acceptance. Preview shows the organization and role before a separate grant action; a failed preview disables acceptance.

Final code `2a4f6d2195a004f56cc1ad03a7d9f94556b6322b` passed all four gates: backend 38918636255 (219 tests on Python 3.11/3.12 with Mongo), frontend 38918636500 (84 tests in 27 suites and production build), Docker 38918636232 and real Nginx Chromium 38918636285. Local full-backend checkpoint: 210 passed, eight Mongo-dependent tests skipped; final focused invitation tests: 10 passed. Syntax, dependency and diff checks passed. Mail remains disabled by example configuration; all delivery tests are mocked.

Updated the feature matrix, roadmap, security model, readiness decision, testing instructions and README guide links. Single-worker membership/scan coordination, non-transactional invitation claim/membership/audit writes, no durable mail queue, mandatory verification/registration policy, OIDC, project ACL and operational release gates remain explicit. No merge, release, production deployment, real user invitation, live external scan or live mail/AI/webhook activation occurred.

## 2026-10-16 — admission policy and stored-session expiry

Added explicit open, invitation-only and closed self-registration policy with public discovery and matching signup controls. Invitation-only signup validates pending expiry, email and current issuer account/membership/credential authority before account insertion. It does not consume the invitation or grant access; acceptance remains separate and rechecks authority. Configuration rejects unsupported modes and missing invitation/verification prerequisites. Defaults remain open registration and optional proof, with mail disabled.

Required email proof now gates every authenticated workspace request, including existing API tokens and platform owners. Unverified browser sessions retain identity, password, own-session/history, email-proof and invitation-preview controls. The browser suppresses workspace loading until verification, resumes after confirmed status, and clears cached workspace state when an existing session receives the policy denial. Invitation state remains in memory through signup/sign-in, and proof tokens stay out of form markup. Rollout, owner access, failed delivery and same-tab invitation handling are documented in IDENTITY_POLICY.md.

Continued after the policy push into session lifetime enforcement: a fresh access JWT cannot authenticate against an expired or missing stored session deadline. Refresh already checked that deadline. Added strict-boundary/missing-expiry unit coverage and disposable-Mongo checks for ordinary request and refresh rejection. All delivery remains mocked. Local backend checkpoint: 216 passed, nine Mongo-dependent tests skipped; dependency, JSX syntax and diff checks passed. Final CI evidence follows below.

Final code `8bb58f2fcd0524a8961aa75f4c1c55dccfad9b58` passed backend 38927206284 (225 tests on Python 3.11/3.12 with Mongo), frontend 38927206314 (90 tests in 28 suites and production build), Docker 38927206294 and real Nginx Chromium 38927206397. The new App regression initially failed because Jest resets mock implementations before each test; the fixture now restores its gate implementation in setup. Application behavior was unchanged by that correction. Updated feature matrix, readiness, roadmap and account guides with current evidence and remaining limits. No merge, release, production deployment, live external scan or mail/AI/webhook activation occurred.

## 2026-10-16 — explicitly linked OIDC sign-in

Added an independently opt-in confidential OIDC client for existing accounts. Fixed issuer/authorization/token/JWKS endpoints and client credentials are operator configuration, with no startup network traffic or dynamic discovery. Authorization uses PKCE S256, nonce and hash-only browser-bound one-use state; short-lived PKCE verifiers are encrypted. Fixed token/key requests require public HTTPS port 443, DNS pinning with original Host/TLS identity, no redirects/proxies, bounded time/bytes and process-local slots. ID tokens require an allowed signing algorithm/key, exact issuer, audience/authorized party, nonce and valid time claims.

Linking requires the current local password and unused local MFA factor when enabled, binds the initiating session/credential epoch, and uses a unique issuer/subject index. There is no email matching, automatic registration, role grant or implicit registered-email proof. Identity sign-in produces a five-minute browser challenge followed by explicit confirmation and local MFA before a one-use session grant. Linking/unlinking increments the credential epoch and revokes old sessions/API tokens; unlinking remains available after OIDC is disabled. Cancellation invalidates browser-owned pending state and proof cookies; in-flight exchanges may finish. Nginx omits callback access logs and Uvicorn redacts callback queries.

Synthetic disposable-Mongo acceptance uses generated signing keys and mocked provider responses for PKCE exchange, linking, collision across accounts, local MFA, replay/concurrent completion, stale epochs, required email proof, cancellation and unlink credential invalidation. Frontend tests cover explicit completion, disabled settings/sign-in, MFA, unlink coordination and cancellation. Chromium checks failed-callback fragment navigation in the actual Nginx container while OIDC remains disabled. The first Mongo fixture failed before an anonymous request because it passed a missing CSRF cookie as a None header; it now sends an empty string. No application authorization was relaxed. Local final checkpoint: 229 passed, ten Mongo-dependent tests skipped; focused OIDC route/protocol tests passed, and syntax/dependency/diff checks passed. Final CI evidence follows below.

The provider is not activated and no real identities were linked. Discovery, provisioning, multiple providers, forced SSO, provider lifecycle/back-channel logout and live compatibility acceptance remain separate work. Password recovery retains the identity link; local session/account administration and explicit unlinking remain necessary when the provider identity is compromised. The supported topology is still one API worker. No merge, release, production deployment or live scan/mail/AI/webhook/provider activation occurred.

Final code `45b95b7fa61a833fbad440387cd51d1639df44cf` passed all four workflows: backend 38930019585 (239 tests on Python 3.11/3.12 with Mongo), frontend 38930019760 (98 tests in 29 suites and production build), Docker 38930019555 and real Nginx Chromium 38930020247. Updated account/security guides, feature matrix, roadmap and readiness with the implemented flow and remaining limits. No live provider compatibility claim is made.

## 2026-10-16 — operator secret key rewrapping

Continued after OIDC publication into the key-retirement tooling gap. Added a standalone operator command with explicit selected purpose/key rings, dry-run default and opt-in apply. It streams bounded Mongo cursor batches for active/pending MFA secrets, webhook configurations and OIDC flow verifiers. It skips current-primary ciphertext, uses MultiFernet rotation to preserve plaintext and the original encryption timestamp, and conditionally updates only the ciphertext that was read. Concurrent credential/secret edits therefore cannot be overwritten. Credentials, enablement, session bindings, MFA recovery hashes and provider trust are unchanged.

Summaries contain counts/field families only, separate remaining work from unreadable/conflicting records, and return failure for configuration/database errors or invalid/conflicting records without echoing URI/key/ciphertext/record identifiers. Partial runs are resumable and idempotent. The operator guide requires retained keys, matching backups, updated writers, drained in-flight operations, zero remaining/error counts and restore validation before retiring keys. There is no automatic schedule, key distribution/escrow or missing-key recovery.

Unit tests cover dry-run privacy/no writes, preserved plaintext/timestamps/metadata, idempotency and conditional conflicts. Disposable-Mongo acceptance runs the actual CLI with generated synthetic key rings through dry-run, apply, repeat, invalid ciphertext and old-key removal checks. Local backend: 234 passed, eleven Mongo-dependent tests skipped; dependency, syntax and diff checks passed. No real stored secrets were rewrapped or operational keys retired. Final CI evidence follows below.

Final code `a078dd3bacfa7528d4e506c378680d18f3c0bfb0` passed backend 38931136162 (245 tests on Python 3.11/3.12 with Mongo), frontend 38931136262 (98 tests in 29 suites and production build), Docker 38931136342 and real Nginx Chromium 38931136205. Published operator/security/testing guides and refreshed the current matrix, roadmap and readiness decision. Project ACL/service identities, durable coordination/scheduling, structured CVSS/correlation, native adapters, retention, tamper-proof audit and backup/restore/monitored release gates remain incomplete. No merge, release, production deployment or real key retirement/provider activation was performed.

## 2026-10-16 — live project admission and immutable token caps

Added all/selected project admission to organization memberships. Legacy/new memberships retain all-project access until an administrator explicitly restricts them; empty selections deny project data and malformed stored policy fails closed. Organization administrators retain all-project membership access. Grant writes require fresh browser/admin/account authority, validate selected project ownership, share membership mutation coordination, and compare membership identity/role/policy/version. Member metadata exposes grant IDs/version only to administrators and the affected member; stale editors must reload.

The repository combines project predicates independently of caller search/OR filters. Scope covers workspace/register pages, aggregate counts, findings/tasks/assessments/jobs/imports/inventory/AI and report/evidence data. Project/parent relationships cannot be moved through repository updates. Legacy evidence chunks and PDF/snapshot files without project IDs require an accessible parent. New audit events receive authoritative project attribution; restricted readers omit historical unattributed/org-wide events. Restricted leads cannot manage org-wide subscriptions or SLA writes, and restricted contexts cannot create projects/shared templates. Existing roles still control actions inside admitted projects.

Continued after the membership push into immutable project caps for personal API tokens. Optional selected IDs are validated against current access at issuance and intersect live grants on each request and the queued-scan recheck. Legacy/uncapped credentials inherit current grants; empty caps deny project data; owner grant expansion cannot expand a capped token beyond its original selection. The token and member editors share complete server-paginated selection with retained off-page choices. Changing a cap requires a replacement token. Independent service identities/custom roles remain design requirements rather than implemented controls.

Added disposable-Mongo tests for browser/pre-existing bearer admission, counts/search/audit, hidden-project reads/mutations/bulk/report/export paths, legacy file downloads, empty grants, restoration and fixed caps. Unit tests cover predicate composition, invalid policies, administrator/fresh-actor protections, queued-scan denial, metadata privacy and stale versions. Chromium uses two synthetic accounts to select/clear/restore project grants and create a capped token through the actual UI. The first Mongo run found an older exact-fields assertion that needed the new public policy metadata. The later full browser run found an older coverage-copy assertion; the new two-account grant test had passed. Assertions now validate the new intended contracts. No authorization checks were weakened.

Local final backend checkpoint: 247 passed, twelve Mongo-dependent tests skipped; dependency, Python/JSX syntax and diff checks passed. The supported topology remains one API worker. Running work may finish and cached/downloaded data cannot be recalled; default membership/invitation access remains all until explicitly changed. No real membership, token, provider, destination, production deployment, merge or release was activated. Final CI evidence follows below.

Final code `d2172a55c68e31c3de8d320fc62d6112233b0d99` passed backend 38945662027 (259 tests on Python 3.11/3.12 with Mongo), frontend 38945662160 (101 tests in 30 suites and production build), Docker 38945662024 and real Nginx Chromium 38945662072. Published the project-access and authorization-evolution guides and refreshed architecture, security, testing, feature matrix, roadmap and readiness. Custom roles/service identities, durable coordination/scheduling, structured CVSS/correlation, native adapters, retention, tamper-proof audit and backup/restore/monitored release remain incomplete. No production readiness, merge, release or live activation is claimed.

## Queued execution credential admission

Queued scans now revalidate initiating account status/credential epoch and the session or API token at the execution boundary, before scope resolution or network activity. Token action and project caps are loaded again from the live record. Invalid credentials fail the queued job through existing failure/audit handling. This does not introduce durable scheduling or cancel running checks. Focused negative tests and the existing lifecycle/project suites cover the boundary; verification results follow below.

Local validation: `/tmp/vaptx-venv/bin/python -m pytest tests -q` from `backend`: **250 passed, 12 Mongo-dependent skipped, 154 subtests passed**. `git diff --check` passed. CI database, container and browser acceptance remains pending for this increment.

Final acceptance at code `0a78ac3bff83a567009e68984629e94a6cf0a0a7`:

- Backend Python 3.11/3.12 with disposable Mongo: **263 passed** on both versions — [38959015377](https://github.com/ibrahim1101/vapt-x/actions/runs/38959015377). The new database test exercises 13 synthetic account/session/token cases, including valid controls, live action/project caps and token membership changes.
- Frontend: **101 tests, 30 suites and production build passed** — [38959015379](https://github.com/ibrahim1101/vapt-x/actions/runs/38959015379).
- Docker smoke passed — [38959015374](https://github.com/ibrahim1101/vapt-x/actions/runs/38959015374).
- Real Nginx/Compose Chromium integration passed — [38959015397](https://github.com/ibrahim1101/vapt-x/actions/runs/38959015397).
- Local full suite after adding the persistence test: **250 passed, 13 Mongo-dependent skipped, 154 subtests passed**; dependency consistency and whitespace checks passed.

Updated the architecture to remove outdated baseline claims about unavailable cancellation/webhook workflows, synchronous PDF rendering and missing aggregate/register work. All acceptance used synthetic data. No live external execution, merge, release or production deployment occurred. Custom roles/service identities, durable assessment ownership and the remaining operational roadmap are still incomplete.

## Cloud/configuration import expansion

Implemented Prowler ASFF failed resource imports and Trivy mixed vulnerability/misconfiguration/secret imports through the existing scope-authorized workflow. Added source metadata display, raw-report omission, source-code/match omission, strict status/range/schema validation and cumulative size/row limits. Added parser, frontend, Mongo persistence/authorization/deduplication tests and Chromium import fixtures. Local focused parsers: 31 passed with 91 subtests; full local suite before the additional Mongo test: 259 passed, 13 skipped, 179 subtests. CI acceptance pending.

## MobSF Android static import continuation

Continued after the cloud/configuration push with an Android static JSON adapter, separate code/manifest provenance, canonical file/line identity, secure/good omission, mobile/cloud report-association asset labels and frontend source details. Extended real-Mongo import acceptance and Chromium fixtures for the third adapter. Focused parser validation: 32 passed, 100 subtests; frontend/E2E syntax and whitespace checks passed. No APK, cloud credential or external scanner execution was introduced. Full CI acceptance pending.

## Structured scanner scoring/package facts continuation

Continued after the MobSF push with syntax-validated CVSS 3.0/3.1/4.0 source facts for Trivy and Nuclei, explicit classification IDs, safe reference URLs and structured installed/fixed package version strings. Added distinct source-facts UI, source metadata in immutable report snapshots, PDF fact labels and additive JSON/CSV export columns. Scores are not recomputed and neither fix applicability nor version ordering is inferred. Parser/report/export/frontend tests and real-Mongo/browser acceptance were extended; CI evidence follows after completion.

## Cross-scanner candidate continuation

Continued after the scoring/package push with a read-only, indexed, paginated candidate endpoint and finding-detail register. Candidates share a normalized CVE and exact stored project/asset with a different scanner; each observation and analyst decision stays independent. Added literal-search/field-minimization tests, real-Mongo pagination with 30 candidates plus tenant/project/asset/scanner/CVE decoys, restricted-project regression and a Chromium source-pair assertion. Full acceptance is pending at this checkpoint.

Local final correlation checkpoint: full backend suite **273 passed, 14 Mongo-dependent skipped, 208 subtests passed**; frontend/E2E parser checks, dependency consistency and whitespace checks passed. Prior MobSF and structured-fact heads passed all four CI workflows; final-head evidence remains pending below.

## Analyst severity decision continuation

Continued after the fully green correlation head (`0ef1e8a`) with explicit severity override/restoration. New findings preserve scanner severity; legacy observations capture their unchanged baseline on first decision. Reasoned changes use durable compare-and-swap versions and atomic bounded history; list pages omit history payloads. Details, PDFs, snapshots and exports distinguish effective and original severity. Added API/permission/race/restore regressions, real-Mongo concurrent writes and reimport preservation, component tests and Chromium form acceptance. Local suite before the final Mongo/component additions: **277 passed, 14 skipped, 211 subtests**. CI acceptance pending.

## Final scanner and analyst workflow acceptance — 2026-10-16

Code head `1f15da7ae96195b5cef1fb5685060c1a640c6b34` passed all four CI gates after the severity-decision form-selector correction and PDF limitations-layout correction. The latest code increment preserves the label `severity-decision-submit` so generic form-submit browser assertions remain unambiguous, and keeps the PDF limitations heading with its paragraph. Targeted report tests passed after the layout fix.

- Backend: **291 tests passed on Python 3.11 and 3.12 with disposable MongoDB** — [38964644949](https://github.com/ibrahim1101/vapt-x/actions/runs/38964644949).
- Frontend: **109 tests in 34 suites and production build passed** — [38964644950](https://github.com/ibrahim1101/vapt-x/actions/runs/38964644950).
- Docker smoke passed — [38964644939](https://github.com/ibrahim1101/vapt-x/actions/runs/38964644939).
- Chromium against Nginx/Compose passed — [38964645043](https://github.com/ibrahim1101/vapt-x/actions/runs/38964645043).

This acceptance covers Prowler ASFF and expanded Trivy imports, MobSF Android static JSON imports, structured CVSS/package/reference facts, same-asset/shared-CVE cross-scanner candidate review, and reasoned versioned severity override/restoration. Mongo and browser checks use synthetic fixtures. The candidate register does not merge findings or assign confidence; scanner scores are not recalculated, and applicability/version ordering is not inferred. Mobile/cloud asset kinds are report associations, not active discovery. No live scanner, provider, mail, AI, webhook or OIDC activation; production deployment; merge; or release occurred. The branch remains a draft PR.

The roadmap is still incomplete. Next broad areas are custom roles and service identities; durable assessment ownership/scheduling and multi-process coordination; more upstream import variants and broader correlation/CVSS consistency/version applicability; native scanner/provider adapters; retention, tamper-evident audit, backup/restore and monitored release acceptance. See the current feature matrix and readiness decision for exact boundaries.

## Organization roles and service identities

Custom roles and capped organization service identities were implemented after the scanner/analyst acceptance. Roles use explicit action permissions, organization scope, live versioned updates, guarded deletion and membership assignment. Service credentials are hash-only, shown once, time-bounded and explicitly limited by both identity grants and fixed credential caps. Owner membership/account loss suspends use until an administrator transfers ownership. Queue execution revalidates the current service credential, owner, identity grants and project intersection.

The initial Mongo service-identity acceptance found that its hidden-project assertion used a nonexistent project-detail GET route. The test now uses the supported workspace project selector. Local backend suite: **293 passed, 17 Mongo-dependent skipped, 219 subtests passed**. The Mongo service lifecycle and durable queue integration tests are exercised in backend CI, not in this local runtime.

## Durable scan queue and lease recovery

Execution scans now remain queued in Mongo until an API-lifespan worker atomically claims them with a private 30-second lease. Private job metadata stores only the initiating session/token/service-credential references; worker execution reloads current authority and scope. Leases heartbeat while a scan runs, and cancellation state is observed across worker processes. Queued jobs can resume after restart. A running job with an expired lease becomes interrupted and requires a new scan; the system does not automatically replay partially executed scanner work. Private authority and lease fields are removed from repository responses.

Added Mongo integration coverage for competing claims, private metadata filtering and stale-lease recovery. Local unit/backend validation passes with Mongo integration cases skipped because this runtime has no Mongo service. The supported deployment remains one API worker: membership/service coordination, per-organization concurrency admission, cancellation/result atomicity and multiworker failure acceptance are still open. No recurring scan schedule or production readiness is claimed.

## Custom authorization and durable queue acceptance — 2026-10-21

Code head `22ae65292fa6c4682ab0758b59f2bc84d92f2644` passed all current CI workflows. Backend passed **312 tests on Python 3.11 and 3.12 with Mongo** ([39588413237](https://github.com/ibrahim1101/vapt-x/actions/runs/39588413237)); frontend passed **112 tests in 36 suites and production build** ([39588413096](https://github.com/ibrahim1101/vapt-x/actions/runs/39588413096)); Docker smoke passed ([39588413098](https://github.com/ibrahim1101/vapt-x/actions/runs/39588413098)); Chromium against the Nginx/Compose app passed ([39588413333](https://github.com/ibrahim1101/vapt-x/actions/runs/39588413333)).

The Mongo suite validated service identity project caps using the supported workspace selector and cross-tenant rejection before credential revocation, plus competing durable scan claims, private authority metadata and expired lease recovery. The browser check validated distinct submit selectors on organization settings after custom roles and service identity forms were added. Local backend suite is **295 passed, 17 Mongo-dependent skips, 219 subtests passed**. Multiworker coordination/recovery is still not accepted; no production deployment, merge or release occurred.
## Scan coordination and source-fact follow-up — 2026-10-21

Code head `77b14d30466adddefde84b16b1569e639574ca40` passed all CI workflows: backend **317 tests on Python 3.11 and 3.12** ([run 39594215369](https://github.com/ibrahim1101/vapt-x/actions/runs/39594215369)), frontend **112 tests in 36 suites and production build** ([run 39594215287](https://github.com/ibrahim1101/vapt-x/actions/runs/39594215287)), Docker smoke ([run 39594215290](https://github.com/ibrahim1101/vapt-x/actions/runs/39594215290)) and Chromium against the Nginx/Compose app ([run 39594215289](https://github.com/ibrahim1101/vapt-x/actions/runs/39594215289)). The backend run caught an indentation failure in a generated subprocess script; the harness now compiles in both parent and child forms and the Mongo-backed cross-process lease test passes in CI.

The increment adds renewable organization-wide scan admission and per-assessment state leases, remote cancellation observation, CVSS 3 base-only score consistency checks, conservative exact npm SemVer ordering facts, and the above cross-process lease test. Multiworker API restart, failure and recovery acceptance remains open; supported deployment remains one API worker. No merge, production deployment or release occurred.

## Organization-wide scan admission race across API processes — 2026-10-21

Code head `5f56322950fdd74a17429295dcb64b08341416dc` passed backend (**318 tests on Python 3.11 and 3.12 with Mongo**), frontend (**112 tests in 36 suites and production build**), Docker smoke and Chromium against Nginx/Compose: [backend](https://github.com/ibrahim1101/vapt-x/actions/runs/39595092689), [frontend](https://github.com/ibrahim1101/vapt-x/actions/runs/39595092484), [Docker](https://github.com/ibrahim1101/vapt-x/actions/runs/39595092371), [Chromium](https://github.com/ibrahim1101/vapt-x/actions/runs/39595092642).

Added a Mongo-backed route-level test with two independent Python processes and a project-restricted analyst. Both processes race to create scans while one active scan belongs to another project in the same organization; exactly one request is admitted, proving the admission check serializes and counts organization-wide activity. This does not validate two live ASGI servers, cancellation during execution, worker restart/loss or full recovery; those remain open before any multiworker deployment.
