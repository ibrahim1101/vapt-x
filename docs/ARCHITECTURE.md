# VAPT-X architecture

Updated 2026-10-16 UTC for the current implementation. Runtime acceptance and limits are tracked in [FEATURE_MATRIX.md](FEATURE_MATRIX.md), [TESTING.md](TESTING.md) and [RELEASE_READINESS.md](RELEASE_READINESS.md).

## Components and boundaries

| Component | Source | Responsibility |
| --- | --- | --- |
| React workspace | `frontend/src/App.js`, `components/` | Authentication/onboarding, organization selection, project filters, assessments, findings, evidence, remediation, reports, AI and audit views |
| Browser API client | `frontend/src/lib/api.js` | Axios credentials, CSRF and organization headers, single-flight refresh, evidence chunks and downloads |
| FastAPI entrypoint | `backend/server.py` | Lifespan, middleware, CORS, health, owned training routes and router registration |
| Identity and authorization | `backend/auth.py`, `core.py` | Users, sessions, MFA, organization membership, role permissions, project admission and audit events |
| Tenant repository | `backend/repository.py` | Organization/project-scoped reads and writes, legacy blob parent admission and protected identity fields |
| Domain workflow | `backend/workflow.py` | Projects, scopes, assets, assessments, jobs, imports, triage, tasks and retest comparisons |
| Scanner adapters | `backend/scanners.py`, `importers.py` | Exact-host/time-window validation, pinned safe requests, constrained Nmap, report normalization |
| Evidence and reports | `backend/evidence.py`, `reporting.py` | MongoDB-backed chunks, checksums, threaded PDF generation and versioned source snapshots |
| Optional AI | `backend/analyst.py` | Opt-in multi-provider interpretations of at most 30 stored findings, redacted context, usage and bounded conversation history |
| Optional webhooks | `backend/webhooks.py` | Encrypted configuration, bounded pinned HTTPS/HMAC delivery, durable leased outbox, retries and delivery history |
| MongoDB | `compose.local.yml` | Local MongoDB 7, persistent named volume, loopback host port 27018 |

The frontend calls `/api` over HTTP(S). Cookie authentication identifies a user/session; `X-Org-Id` chooses an organization but membership is rechecked server-side. `Ctx.require` checks organization-role permissions. Current membership supplies all/selected project admission, and optional immutable API-token project caps intersect it. `Repository` forces organization scope and an independent project predicate into domain queries; legacy evidence/report blobs require accessible parents. Organization administrators retain all-project membership access. See [project access](PROJECT_ACCESS.md) and [authorization evolution](AUTHORIZATION_EVOLUTION.md).

## Data model

Identity documents use `_id` UUID strings in MongoDB and expose `id` in API models. Domain records add `org_id`, `created_by` and `created_at`. Relationships are application-enforced identifiers, not database foreign keys.

- Organizations have memberships linking users and fixed roles.
- Projects own scopes, assets and assessments.
- Scopes record exact host, authorization reference, approved scanner set and UTC-aware time window.
- Assets reference a scope. Assessments reference selected project assets.
- Jobs reference an assessment and asset; findings reference the job and scanner source.
- Tasks/evidence reference findings; reports reference assessments and separate stored PDF records.
- Retests reference a baseline assessment. Comparison uses fingerprints and completed execution coverage.

MongoDB stores evidence as base64 chunks (192 KiB raw each, 10 MiB/file) and reports as base64 bytes. The filesystem evidence directory declared in `core.py` is not the evidence persistence path used by the current upload implementation.

## Execution model and limits

An API-lifespan worker polls the durable Mongo queue and atomically leases queued jobs for 30 seconds, refreshing the lease during execution. Jobs retain only private references to the initiating session, API token or service credential; the worker reloads current account, membership, role, project, credential and scope authority before execution. Queued work survives an API restart. A running job whose lease expires is marked interrupted and is not automatically replayed, avoiding a duplicate partially executed scan. Cancellation changes durable job state and the worker observes it during lease refresh; retries create a separate draft. A process-local lock still protects selected workflow writes, per-organization admission limits are not cross-worker atomic, and cancellation/result persistence is not yet a multiworker acceptance gate. Keep the supported single API worker until those coordination and recovery boundaries are completed and tested.

Safe checks pin a validated public IP, set the original Host/SNI, disable redirects and environment proxies, and cap a response at 1 MiB. Nmap uses argument-list subprocess execution with fixed TCP-connect ports and a 60-second process deadline. No exploit scripts or credential attacks are supported.

Dedicated registers use complete matching server queries with 25-row pages and a maximum offset of 1,000,000. Overview counts use aggregates; workspace previews and selection menus remain bounded. Complete-set report/retest operations enforce explicit row/size limits instead of silently truncating. PDF rendering runs in a worker thread. Multi-document workflow writes are not transactions; partial-failure recovery remains incomplete.

## Development and production

The supplied MongoDB Compose service and optional non-root API profile are local development infrastructure, not a production deployment. `backend/Dockerfile` uses a single worker and excludes Nmap; the API/Nginx/Compose profiles are exercised by CI smoke and Chromium workflows. Host port 27018 maps to container port 27017. Never assume a cloud workspace can reach the founder's localhost. Use isolated test databases and the application-owned training target.

Production needs authenticated/private MongoDB, TLS termination, validated configuration, controlled registration/bootstrap, bounded workers, backups with tested restore, secrets management and monitoring. Optional AI requires explicit provider configuration and, where applicable, SDK dependencies and credentials; core assessment workflows work without AI.
