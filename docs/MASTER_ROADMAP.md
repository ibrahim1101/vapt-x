# VAPT-X engineering roadmap

Updated 2026-10-21. The existing React/FastAPI/Mongo/Docker application is retained. This roadmap tracks work and evidence, not promised release dates. Current code `22ae652` passed backend (312 tests with Mongo on Python 3.11/3.12), frontend (112 tests in 36 suites/build), Docker and real Nginx Chromium workflows. See [FEATURE_MATRIX.md](FEATURE_MATRIX.md) and [RELEASE_READINESS.md](RELEASE_READINESS.md).

## Completed increments

- Reasoned analyst severity override/restoration, preserved original scanner severity, conditional policy versions and most-recent-100 decision history, with UI and report/export attribution.

- Prowler ASFF and MobSF Android static imports; expanded Trivy configuration/secret findings; source metadata UI and raw-report/code omission.
- Structured Trivy/Nuclei CVSS/source scores, package versions, references and explicit classification IDs, carried into UI, PDF/source snapshots and JSON/CSV exports. Read-only cross-scanner candidates share a normalized CVE and exact stored asset/project, with complete paginated results.

- Queued scans revalidate initiating account status/credential epoch, session or API-token expiry/revocation, token membership and current action/project caps before execution. Running checks retain existing cancellation boundaries.

- Membership project admission across browser/token queries, aggregates, reports/evidence and audit; admin grant editor with version checks and optional immutable API-token project caps. Custom-role/service-identity design boundaries are documented.
- Organization-scoped custom roles with explicit permissions, versioned live updates and human membership assignment. Independent service identities now have explicit human ownership/handoff, fixed hash-only credentials, expiry, rotation/revocation, live action/project intersections and queued-scan revalidation.
- Durable scan queue claims use atomic Mongo leases and private initiator references; queued jobs resume after restart, while abandoned running jobs become interrupted rather than replaying potentially partial scans. Cross-worker coordination and acceptance remain in progress.
- Membership/project grants, invitation changes, custom-role deletion and service-identity management/credential issuance now share renewable Mongo leases across API processes; individual record updates retain version/CAS guards.
- Operator-only dry-run/apply key rewrapping for MFA, webhooks and OIDC, with conditional updates and original timestamp preservation.
- Runtime validation, request/resource limits, reproducible dependencies, API/frontend containers and CI.
- Cookie sessions, atomic refresh and password budgets, password changes, encrypted TOTP/recovery, private account history and owner-only account disable/reactivate.
- Optional one-use password recovery with TLS mail configuration, MFA preservation, epoch invalidation and browser reset-link handling.
- Optional registered-email proof and seven-day email-bound invitation lifecycle with explicit preview/acceptance, issuer authority checks and role preservation.
- Explicit open/invitation-only/closed registration and optional mandatory email proof with limited browser account sessions; stored-session expiry enforced on every browser request.
- Optional explicitly linked OIDC code sign-in with PKCE, issuer/nonce/signature validation, local MFA and credential-epoch invalidation.
- Organization role/membership lifecycle, anti-orphan guards, scoped hash-only tokens and membership-lifetime invalidation.
- Project edits/archive/templates/navigation; asset metadata/bulk registration/navigation/history; assessment cancellation/retry/history/navigation.
- Finding filters/pagination, bulk triage/owner/history, comments, organization SLA policy, remediation edits and coverage-aware retests.
- Complete scan-job pagination/search/status/source filters and independently loaded execution records.
- Evidence/report/scope metadata navigation and organization membership directory with complete server pages, literal search and specific filters.
- Scanner/import safety, secret/IaC imports, API/SBOM inventory, cached CVE intelligence and private exports/evidence integrity.
- Versioned PDF templates/preview/branding/custom sections/source snapshots; optional multi-provider AI with bounded redaction/usage.
- Complete overview counts, dedicated complete remediation/audit navigation and encrypted opt-in signed webhook outbox with retries, rotation/removal and delivery history.

## Next implementation order

1. Add durable scan admission and cancellation/result coordination, test worker restart/lease-loss/cancellation across API processes, and exercise membership/service-identity lease takeover. Keep one API worker until the full multiworker acceptance passes. Recurring scan schedules remain separate work.
2. Expand upstream import schema fixtures, CVSS score/vector consistency and package affected-range/version evaluation; broaden correlation beyond the implemented same-asset/CVE candidates; distinguish observations, imported assertions and analyst decisions.
3. Add one native ticket/notification integration at a time with credential storage, bounded egress, tenant isolation and explicit activation.
4. Define retention/quotas, key distribution/retirement policy, tamper-proof audit storage and backup/restore drills; implement monitored deployment, rollback and versioned release procedures.
5. Broaden large-dataset, responsive/keyboard/error-state acceptance. Desktop packaging follows web stability.

## Constraints and handoff

Dedicated registers now query complete server collections. Selection menus and workspace previews remain bounded; report operations retain explicit size and coverage limits.

OIDC provider discovery, provisioning, forced SSO, lifecycle synchronization and live provider compatibility remain separate work. The implemented flow explicitly links existing accounts and preserves local MFA/admission policy.

The deployment remains single-worker. Membership and service-identity mutations use Mongo leases, while scan concurrency admission and cancellation/result atomicity still lack cross-worker acceptance. Webhook delivery leases are durable but do not make domain writes and enqueue atomic. No production release or multiworker-readiness claim is made.

Read the development log, inspect current branch/PR/CI and preserve any newer remote changes before editing. Favor complete tested increments, synthetic fixtures and reviewable commits. Do not activate live scanners/providers/destinations or merge/release as part of ordinary development. Earlier historical checkpoint notes are superseded by the current matrix and latest CI evidence.
