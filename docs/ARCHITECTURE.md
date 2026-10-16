# VAPT-X architecture

Source audit: 2026-10-14 UTC, baseline `a2dcdae`. Runtime validation is tracked separately in [TESTING.md](TESTING.md).

## Components and boundaries

| Component | Source | Responsibility |
| --- | --- | --- |
| React workspace | `frontend/src/App.js`, `components/` | Authentication/onboarding, organization selection, project filters, assessments, findings, evidence, remediation, reports, AI and audit views |
| Browser API client | `frontend/src/lib/api.js` | Axios credentials, CSRF and organization headers, single-flight refresh, evidence chunks and downloads |
| FastAPI entrypoint | `backend/server.py` | Lifespan, middleware, CORS, health, owned training routes and router registration |
| Identity and authorization | `backend/auth.py`, `core.py` | Users, sessions, organization membership, role permissions, audit events |
| Tenant repository | `backend/repository.py` | Organization-injected reads/writes and protected identity fields |
| Domain workflow | `backend/workflow.py` | Projects, scopes, assets, assessments, jobs, imports, triage, tasks and retest comparisons |
| Scanner adapters | `backend/scanners.py`, `importers.py` | Exact-host/time-window validation, pinned safe requests, constrained Nmap, report normalization |
| Evidence and reports | `backend/evidence.py`, `reporting.py` | MongoDB-backed chunks, checksums and point-in-time PDF bytes |
| Optional AI | `backend/analyst.py` | Claude interpretations of at most 30 stored findings and recent conversation history |
| Dormant integration helper | `backend/webhooks.py` | Signing/retry helper; no management API or usable integration workflow found |
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

FastAPI BackgroundTasks execute scans in the API process. A process-local lock checks a per-organization maximum of two queued/running jobs. Startup marks unfinished jobs interrupted. There is no durable queue, scheduler, cancellation endpoint or distributed worker lease; use a single API worker until these are implemented and tested. A second worker starting could interrupt another worker's jobs.

Safe checks pin a validated public IP, set the original Host/SNI, disable redirects and environment proxies, and cap a response at 1 MiB. Nmap uses argument-list subprocess execution with fixed TCP-connect ports and a 60-second process deadline. No exploit scripts or credential attacks are supported.

Repository list calls default to 1,000 rows. This is a correctness limitation for dashboard counts, PDFs and retest comparisons; pagination and complete aggregation are required before scale claims. Report generation is synchronous and may block the event loop. Multi-document workflow writes are not transactions; partial-failure recovery remains to be designed.

## Development and production

The supplied MongoDB Compose service and optional non-root API profile are local development infrastructure, not a production deployment. `backend/Dockerfile` uses a single worker and excludes Nmap; the profile has not been built in this environment. Host port 27018 maps to container port 27017. Never assume a cloud workspace can reach the founder's localhost. Use isolated test databases and the application-owned training target.

Production needs authenticated/private MongoDB, TLS termination, validated configuration, controlled registration/bootstrap, bounded workers, backups with tested restore, secrets management and monitoring. Optional AI requires a separate SDK and API key; core assessment workflows must work without AI.
