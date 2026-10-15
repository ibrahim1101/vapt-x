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
