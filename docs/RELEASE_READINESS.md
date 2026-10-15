# Release readiness

**Decision: not ready for production release.** Audit date: 2026-10-14 UTC. Existing source provides a substantial prototype, but complete workflow, persistent database, authorization and deployment evidence is not yet established.

## Required gates

| Gate | Audit status | Evidence required |
| --- | --- | --- |
| Reproducible backend/frontend installs | In progress | Clean environment installs, dependency lock/constraints, successful build |
| Configuration/startup/health/request limits | In progress | Regression tests and live startup/degraded readiness |
| MongoDB persistence and upgrade behavior | Blocked in current environment | Isolated real MongoDB integration and restart checks; Docker absent here |
| Authentication/CSRF/cookie/tenant regressions | Pending | Positive and negative API tests, two-tenant access tests and browser cookie validation |
| Core assessment workflow | Pending | Full UI/API path using owned training target and synthetic imports |
| Scanner destination/resource controls | Pending | Mocked transport and authorized controlled execution; process timeout/cancellation behavior |
| Complete reports/comparisons | Blocking defect identified | Remove silent 1,000-row truncation; verify report hash/missing-file behavior and layout |
| Job safety for deployment topology | Blocking limitation | Single-worker constraint until distributed ownership/restart/concurrency semantics exist |
| Dependency and secret checks | Pending | Clean scans with reviewed exceptions, no committed credentials/customer evidence |
| Backup/restore, encryption and retention | Not started | Documented operational settings and successful restore drill |
| Accessibility/responsiveness/error states | Pending | Browser tests and manual review |
| CI, images, deployment and monitoring | Pending | Passing CI, reproducible images, health monitoring and rollback procedure |
| External integrations | Disabled/not verified | Explicit credentials/authorization, safe egress and audited delivery tests |

A limited local demonstration can be considered only after startup and the selected demonstrated workflows actually pass. Use synthetic data, explicit local configuration and a single worker; clearly label remaining coverage. Do not present the prototype as a verified enterprise deployment.

## Release evidence checklist

- Record branch, commit, PR and CI links; do not invent review/publication evidence.
- Record test commands/results/environment and known skipped checks.
- Confirm no secrets, real customer evidence or unauthorized live scans in repository/artifacts.
- Confirm critical/security regressions and data integrity defects are addressed.
- Confirm Windows/local and Linux deployment instructions match validated commands.
- Obtain explicit approval for a sensitive deployment or release publication; ordinary development/PR work may continue autonomously.
