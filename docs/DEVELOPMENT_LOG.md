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
