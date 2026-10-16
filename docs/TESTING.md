# Testing and verification

Audit date: 2026-10-14 UTC. Baseline `a2dcdae` had `backend/pytest.ini` and `tests/__init__.py`, but no executable regression suite found by the audit. Historical `test_result.md`/generated reports are provenance only; they are not evidence that this branch works today.

## Evidence policy

Record the exact command, commit/environment, outcome and scope for each check in [DEVELOPMENT_LOG.md](DEVELOPMENT_LOG.md). Distinguish syntax, mocked unit tests, database-backed API tests, browser tests and actual scanner execution. Mark unavailable checks blocked rather than passed. Never mark the whole product verified because a narrow test passes.

The local Work environment has no Docker/Mongo service. Local Mongo tests are skipped unless a disposable server is supplied. GitHub Actions runs Mongo-backed tests, Compose smoke checks and Chromium against the actual Nginx containers; current successful run links are in FEATURE_MATRIX.md. The Windows walkthrough is documented, not executed here. Do not connect to a founder's localhost or use a production database for tests.

## Running checks

From the repository root, after installing the branch's declared test dependencies:

```sh
python -m compileall -q backend
cd backend
python -m pytest
```

`backend/pytest.ini` requires pytest-xdist and configures two workers with loadscope. Keep isolated per-test database names and unique identities; do not depend on shared mutable fixtures. Use project-provided test commands if the implementation adds a more specific suite. A compile check establishes syntax only.

For frontend validation, use the declared Yarn version and a reproducible lockfile, then run the build/test scripts in `frontend/package.json`. Record installation/build failures exactly; dependency resolution is not a successful production build.

## Required regression coverage

| Layer | Required scenarios |
| --- | --- |
| Configuration | Missing/invalid values, production HTTPS and secrets, explicit loopback local mode, malformed URLs, AI disabled |
| Middleware | Origin/CSRF rejection, exact limit, malformed/negative/missing Content-Length, streamed body above limit, security headers, readiness failure without secret disclosure |
| Authentication | UTF-8 bcrypt byte limit, registration uniqueness, login throttle, valid/expired/revoked tokens, refresh rotation, logout cookies and inactive-account policy |
| Tenant/roles | Two organizations, guessed foreign IDs, role downgrade, every resource/download, AI session owner, background authorization recheck |
| Scope/transport | Exact-host/subdomain mismatch, forbidden IP classes, mixed DNS answers, IPv6, pinned Host/SNI, redirects, proxy bypass, approved scanner and time-window bounds |
| Jobs | Concurrency, restart interruption, failures, subprocess timeout, cancellation cleanup when implemented, duplicate submissions |
| Imports/findings | All five formats, malformed/empty payloads, XML entities, normalization, attribution, duplicate rules, large findings and pagination |
| Evidence | Invalid extension/signature/base64/index/size, ownership, incomplete uploads, tampering, cross-tenant download, completion races |
| Reporting/retest | Source labels, PDF output/layout, missing file/hash mismatch, 2,000+ findings, coverage-aware comparison and import exclusion |
| AI | Disabled SDK/key behavior, provider timeout, owner/project isolation, context bounds, redaction and prompt injection; mocked provider by default |
| Browser | Login → organization → project → scope → asset → assessment → scan/import → triage → evidence → remediation → PDF → retest; read-only roles, keyboard/mobile/error states |
| Operations | Clean install/image build, MongoDB persistence/restart, health degradation, backup/restore drill and secret/dependency checks |

## Controlled integration procedure

Start isolated MongoDB 7; set a unique disposable database and development-only secrets. Run a single API worker. Register two test users/organizations. Use only `training://local` and synthetic report fixtures. Verify records survive API restart; reauthenticate and test ownership boundaries. Run frontend against that API and verify downloads and error states. Explicitly label any not-executed steps. Remove disposable resources only after verifying the exact test database/volume identity.

No live Anthropic calls, third-party scanning or webhook delivery are necessary for default tests. Use mocks to prove limits and error paths; perform authorized live checks separately when infrastructure exists.

## Batch A test layout

`backend/tests/test_foundation.py` covers settings, body limits, readiness, password byte limits, repository tenant-filter enforcement and permission checks with isolated mocks. `backend/tests/test_persistence.py` runs an opt-in MongoDB identity/organization/session flow in a subprocess. Set `MONGO_TEST_URL` only to a disposable MongoDB server; the test creates and drops a uniquely named `vaptx_test_*` database. Without that variable the integration test is skipped. `.github/workflows/backend.yml` provisions MongoDB 7 and runs the suite on Python 3.11 and 3.12; workflow presence is not proof of a passing CI run.

Additional regression modules: `test_auth_rotation.py` (atomic refresh/concurrent replay), `test_importers.py` (five synthetic formats and malformed inputs), and `test_scanner_safety.py` (authorization/DNS/pinned HTTP, no external traffic). The disposable Mongo subprocess now covers the core import/evidence/report/retest workflow and a second organization's denied reads/mutations. It intentionally performs no external scans.


## Identity mail acceptance

`test_recovery_persistence.py`, `test_verification_persistence.py` and `test_invitation_persistence.py` use disposable databases and mocked SMTP. They cover reset races/MFA/credential invalidation, one-use email proof across account contexts, invitation email matching, fresh issuer authority, role preservation, removal/rejoining, old API-token rejection, revocation, expiry and navigation beyond 1,000 invitation records. Cookie snapshots retain domain/path attributes while switching synthetic accounts. No real email is sent.

Frontend coverage includes explicit confirmation/acceptance, private fragments, account switching before invitation acceptance and disabled-feature controls. Chromium exercises same-document reset/verification/invitation navigation in addition to the complete existing assessment workflow. Admission-policy tests cover defaults/configuration dependencies, closed registration before writes, invitation-backed signup without implicit acceptance, limited-session verification and subsequent workspace access. Fresh access JWTs are rejected when their stored session deadline is expired or missing. Browser component tests cover required-proof gating, resume after status refresh and policy changes during an existing session. Live mail delivery remains separate acceptance work.

`test_oidc.py` covers fixed endpoint configuration, RS256/ES256 signature and claim validation, nonce/authorized-party/algorithm/key restrictions, PKCE/state storage, stale credential and local MFA boundaries, pinned HTTPS/byte limits, callback log redaction, trusted Origin/CSRF and cancellation. `test_oidc_persistence.py` uses generated signing keys and mocked provider JSON against disposable Mongo: explicit linking, unique identity ownership, local MFA, replay/concurrent completion, stale epoch, required email proof and unlink invalidation. Frontend tests cover disabled controls, explicit completion, password step-up, cancellation and unlink credential coordination. Chromium checks failed-callback fragment handling while OIDC stays disabled. No real provider was activated or validated.

`test_rewrap_secrets.py` verifies dry-run privacy/no writes, plaintext and original timestamp preservation, idempotency, field-only conditional updates, conflicts and invalid ciphertext. `test_rewrap_persistence.py` runs the actual operator CLI against a uniquely named disposable Mongo database for dry-run/apply/repeat/error paths and verifies only the new key decrypts updated synthetic records. No real stored secrets are rotated during acceptance.

`test_project_access.py` covers fail-closed stored policies, predicate intersection, empty selection, legacy blob parent admission, forbidden writes, administrator/fresh-account checks, queued-scan admission and stale grant versions. Directory tests check that versions reach authorized editors without exposing another member’s grant IDs. `test_project_access_persistence.py` exercises real Mongo browser and pre-existing bearer credentials across lists/search/aggregates/audit, mutations/bulk validation, legacy evidence/PDF/snapshot downloads, reports/exports, empty grants, fixed token caps and restoration. The Chromium project-access test uses two synthetic accounts to select/save/clear/restore grants through the actual member editor and verify subsequent requests, fixed-cap token creation/intersection and UI visibility.

`test_execution_credentials.py` checks queued execution rejection before target resolution for missing/disabled/rotated accounts, session expiry/revocation/epoch filters, and API token owner/tenant/epoch/expiry/membership binding plus refreshed action/project caps. Existing cancellation and project-admission regressions remain required.

`test_execution_credentials_persistence.py` uses disposable Mongo records for disabled/rotated accounts, revoked/expired sessions and tokens, foreign-organization and stale-epoch tokens, and valid session/token controls. It verifies persisted job status, unchanged rejected assessments, audit events and no network resolution; scanner output and scope validation are synthetic.

Cloud/mobile/scoring/correlation acceptance: `test_cloud_config_imports.py`, `test_mobsf_import.py` and `test_scanner_facts.py` cover supported schemas, status/line/vector/score validation, row limits, omission and explicit provenance. `test_cloud_config_persistence.py` exercises actual API/Mongo import persistence, repeat-import deduplication, raw/secret/code omission, scoped rejection before writes, structured exports, 30 correlation candidates plus tenant/project/asset/scanner/CVE decoys, literal search and complete pages. `test_finding_correlations.py` verifies fixed predicates, source admission and field minimization. Reporting tests preserve source facts/provenance in snapshots and JSON-encoded CSV cells. Frontend tests and the Chromium workflow cover source details/scoring, all three new/expanded imports and cross-scanner candidate display. No live cloud/mobile execution or source-score recalculation is claimed.

Severity acceptance: `test_finding_severity.py` covers reason validation, permission/source admission, version conflicts, conditional writes and original-severity restoration. Real-Mongo acceptance races two decisions at one version (one success/one conflict), checks duplicate imports retain the active override, and verifies source CVSS, exports and restricted access. Chromium overrides/restores through the finding form; component tests cover read-only controls and history errors.
