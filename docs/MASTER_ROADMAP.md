# VAPT-X engineering roadmap

Audit date: 2026-10-14 UTC. Baseline: `dev/vapt-x-stabilization`, commit `a2dcdae`.

This roadmap tracks implementation work, not promised release dates. The existing application is retained. Source presence is not proof that a workflow runs; see [FEATURE_MATRIX.md](FEATURE_MATRIX.md) and [RELEASE_READINESS.md](RELEASE_READINESS.md).

## Batch A — make the application run (current)

- Validate required configuration before startup; separate local HTTP and production HTTPS settings.
- Bound database startup/health checks, close resources reliably, add actionable startup diagnostics.
- Enforce request size limits for malformed, absent and misleading Content-Length headers.
- Correct optional Anthropic availability reporting and remove remaining Emergent runtime dependencies.
- Reduce backend dependencies to actual runtime needs; establish reproducible, tested dependency installation.
- Verify React build, database persistence and cookie-based authentication with an isolated database.
- Add regression tests and CI; provide reproducible development containers and Windows/Linux setup.

Batch exit: clean install, backend startup, frontend build, login/refresh/logout, organization/project persistence and restart verified. CI and local runtime evidence must accompany the implementation.

## Batch B — complete core assessment workflows

Priority order:

1. Exercise tenant isolation and role enforcement on every resource, including downloads, AI sessions and jobs.
2. Finish server-side pagination/search: workspace truncation is disclosed and reports/comparisons now require complete sets up to 5,000 rows; large inventories still need full navigation.
3. Validate scanner scope, DNS pinning, redirect blocking, time windows and resource limits using synthetic fixtures and the owned training target.
4. Report-download integrity/missing-file handling now has regression coverage; validate large reports and evidence completion races next.
5. Complete assessment cancellation and bounded job cleanup; enforce concurrency across workers before enabling more than one API worker.
6. Extend the 18 importer fixtures to additional upstream schema variants and partial-persistence failure cases.
7. Add project edits/archive and genuine asset search/pagination; preserve historical references.
8. Complete workflow browser tests for project → scope → asset → assessment → scan/import → finding → evidence → task → report → retest.

Batch exit: core UI/API workflows tested with persistent MongoDB, negative authorization tests, scanner mocks and honest coverage reporting.

## Batch C — vulnerability management

Add asset ownership/criticality, validated CVE/CWE fields, versioned CVSS data, cross-scanner correlation, structured triage history, bulk actions, SLA rules, exports and historical snapshots. Introduce EPSS/KEV/OSV/NVD enrichment only with attribution, caching, timeouts and offline behavior. Scanner observations, imported assertions and analyst confirmations remain distinct.

## Batch D — integrations and automation

Introduce scoped API tokens and service identities with explicit revocation and project constraints. Implement scheduling, cancellation and recoverable job ownership before choosing a durable queue. Harden the dormant webhook helper with pinned destinations, proxy controls, bounded delivery workers, encrypted secrets, event subscriptions and audited management routes. Add one useful ticket/notification integration at a time; never activate credentials or external delivery without authorization.

## Batch E — AI and analytics

Expand the existing Claude adapter into optional provider interfaces; add provider health, settings, local inference and usage visibility. Add redaction and prompt-injection tests before sending more context. Build server-side analytics with complete counts and explicit coverage; do not infer a security score from incomplete observations.

## Batch F — enterprise hardening

Add account disable/reset/verification, MFA and recovery codes, session/device administration, project-level permissions, invitation lifecycle and optional OIDC. Define retention, encryption/key management, audit integrity, backup/restore and operational alerting. Gate each feature on tenant-isolation regressions.

## Batch G — polish and release readiness

Complete responsive and keyboard-accessible UI workflows; verify PDF layout, large datasets, loading/error states and empty states. Establish release/version/changelog procedures, reproducible images, dependency/secret checks, restore drills and monitored deployment. Desktop packaging remains deferred until the web application is stable.

## Next-session handoff

Read the development log and feature matrix; inspect current branch/PR/CI state; reproduce the recorded checks. Prioritize security/correctness, blockers, user value and testability. Work on independent modules in parallel only when authorized, and serialize Git writes and migrations. End each session with accurate evidence and reviewable commits; no claim of indefinite background work.
