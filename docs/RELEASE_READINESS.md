# Release readiness

**Decision: not ready for production release.** Audit date: 2026-10-14 UTC. Backend core workflow and Docker startup now have passing CI evidence. Frontend build/browser coverage and enterprise operational controls remain incomplete.

## Required gates

| Gate | Audit status | Evidence required |
| --- | --- | --- |
| Reproducible backend/frontend installs | In progress | Clean environment installs, dependency lock/constraints, successful build |
| Configuration/startup/health/request limits | In progress | Regression tests and live startup/degraded readiness |
| MongoDB persistence and upgrade behavior | Core integration verified in CI | Restart/upgrade/restore behavior still requires dedicated tests |
| Authentication/CSRF/cookie/tenant regressions | Pending | Positive and negative API tests, two-tenant access tests and browser cookie validation |
| Core assessment workflow | API integration verified; UI pending | Mongo CI covers synthetic import/evidence/PDF/retest; browser path remains |
| Scanner destination/resource controls | Pending | Mocked transport and authorized controlled execution; process timeout/cancellation behavior |
| Complete reports/comparisons | Guard and integrity regressions pass | Complete sets capped at 5,000; large PDF layout and snapshot races remain |
| Job safety for deployment topology | Blocking limitation | Single-worker constraint until distributed ownership/restart/concurrency semantics exist |
| Dependency and secret checks | Pending | Clean scans with reviewed exceptions, no committed credentials/customer evidence |
| Backup/restore, encryption and retention | Not started | Documented operational settings and successful restore drill |
| Accessibility/responsiveness/error states | Pending | Browser tests and manual review |
| CI, images, deployment and monitoring | Backend CI and Docker startup verified | Frontend pipeline, deployment monitoring and rollback still pending |
| External integrations | Disabled/not verified | Explicit credentials/authorization, safe egress and audited delivery tests |

A limited local demonstration can be considered only after startup and the selected demonstrated workflows actually pass. Use synthetic data, explicit local configuration and a single worker; clearly label remaining coverage. Do not present the prototype as a verified enterprise deployment.

## Release evidence checklist

- Record branch, commit, PR and CI links; do not invent review/publication evidence.
- Record test commands/results/environment and known skipped checks.
- Confirm no secrets, real customer evidence or unauthorized live scans in repository/artifacts.
- Confirm critical/security regressions and data integrity defects are addressed.
- Confirm Windows/local and Linux deployment instructions match validated commands.
- Obtain explicit approval for a sensitive deployment or release publication; ordinary development/PR work may continue autonomously.

Verified Docker evidence: [run 38691459505](https://github.com/ibrahim1101/vapt-x/actions/runs/38691459505) built the API image, started healthy MongoDB/API containers, checked non-root UID/dependencies, and cleaned up. Backend [run 38691459362](https://github.com/ibrahim1101/vapt-x/actions/runs/38691459362) passed 54 tests on Python 3.11 and 3.12, including exports. No production deployment has been performed.
