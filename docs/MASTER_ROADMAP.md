# VAPT-X engineering roadmap

Updated 2026-10-16. The existing React/FastAPI/Mongo/Docker application is retained. This roadmap tracks work and evidence, not promised release dates. Current code `a078dd3` passed backend (245 tests with Mongo), frontend (98 tests/build), Docker and real Nginx Chromium workflows. See [FEATURE_MATRIX.md](FEATURE_MATRIX.md) and [RELEASE_READINESS.md](RELEASE_READINESS.md).

## Completed increments

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

1. Introduce project-level permissions, custom-role/service-identity design and comprehensive negative authorization regressions before broadening token access.
2. Add durable assessment ownership/cancellation/recovery and scheduling. Replace process-local membership coordination before enabling multiple API workers.
3. Expand import schema fixtures, structured CVSS/version handling and cross-scanner correlation; distinguish observations, imported assertions and analyst decisions.
4. Add one native ticket/notification integration at a time with credential storage, bounded egress, tenant isolation and explicit activation.
5. Define retention/quotas, key distribution/retirement policy, tamper-proof audit storage and backup/restore drills; implement monitored deployment, rollback and versioned release procedures.
6. Broaden large-dataset, responsive/keyboard/error-state acceptance. Desktop packaging follows web stability.

## Constraints and handoff

Dedicated registers now query complete server collections. Selection menus and workspace previews remain bounded; report operations retain explicit size and coverage limits.

OIDC provider discovery, provisioning, forced SSO, lifecycle synchronization and live provider compatibility remain separate work. The implemented flow explicitly links existing accounts and preserves local MFA/admission policy.

The deployment remains single-worker. Assessment checks and membership mutation coordination are process-local. Webhook delivery leases are durable but do not make domain writes and enqueue atomic. No production release or multiworker-readiness claim is made.

Read the development log, inspect current branch/PR/CI and preserve any newer remote changes before editing. Favor complete tested increments, synthetic fixtures and reviewable commits. Do not activate live scanners/providers/destinations or merge/release as part of ordinary development. Earlier historical checkpoint notes are superseded by the current matrix and latest CI evidence.
