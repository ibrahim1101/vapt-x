# Release readiness

Updated 2026-10-21. **Not ready for production release.** Core workflows have repeatable API, container and browser evidence; the full roadmap and operational acceptance are incomplete.

Verified code: `77b14d30466adddefde84b16b1569e639574ca40`. Backend passed with Mongo on Python 3.11/3.12 (**317 tests each**); frontend passed (**112 tests in 36 suites plus production build**); Docker smoke and real Nginx/Compose Chromium passed: [backend](https://github.com/ibrahim1101/vapt-x/actions/runs/39594215369), [frontend](https://github.com/ibrahim1101/vapt-x/actions/runs/39594215287), [Docker](https://github.com/ibrahim1101/vapt-x/actions/runs/39594215290), [Chromium](https://github.com/ibrahim1101/vapt-x/actions/runs/39594215289). See [FEATURE_MATRIX.md](FEATURE_MATRIX.md) for current implementation and [DEVELOPMENT_LOG.md](DEVELOPMENT_LOG.md) for historical checkpoints.

| Gate | Current evidence | Outstanding work |
|---|---|---|
| Reproducible installation/build | Backend pins, frozen Yarn, Python 3.11/3.12, 112 frontend tests in 36 suites and production build | Dependency/secret review and release reproducibility policy |
| Startup/configuration/health/body limits | Unit and Compose startup/smoke checks | Monitored deployment and degraded-service operations |
| Identity and tenant boundaries | Cookie/origin/CSRF, MFA, account lifecycle, membership, invitation, email proof, linked OIDC, project admission, fixed token caps, custom roles, service identities and renewable Mongo mutation leases | Live OIDC provider acceptance; multiworker lease-loss and failure acceptance |
| Core workflow | Chromium against actual non-root Nginx/API/Mongo; synthetic imports/evidence/remediation/PDF/retest | More large datasets, error/accessibility review, upstream schema variants and broader correlation/applicability evaluation |
| Scanner safety | Exact scope/window/profile, fresh queued credential admission, pinned transport, timeout/cancel regression and training target | Broader sandboxing and durable worker ownership |
| Reports/evidence | Checksums, ready-state guards, versioned source snapshots, PDF visual review | Complete-set and size limits still apply; retention/quotas/malware controls |
| Deployment topology | Durable Mongo scan claims/leases, organization-wide admission, per-assessment cancellation/result/import coordination and renewable membership/service-identity leases; stale running work is interrupted without replay | Two-process restart, lease-loss, cancellation and recovery acceptance remain blocking before multiple workers |
| Data operations | Integration/MFA encryption and operator dry-run/CAS secret rewrapping | Retention, backup/restore drills and tamper-proof audit storage |
| Integrations | Mocked safe webhook delivery and optional provider contracts | No live AI/webhook/mail-provider acceptance; native ticket/chat adapters and durable mail delivery remain |
| Release operations | CI, images and synthetic acceptance | Upgrade/restore/rollback drills, monitoring/alerting and release/version policy |

Account disable and membership removal block subsequent authenticated operations; requests and organization jobs already in progress may finish. Archive is project metadata and does not revoke scope. Accepted risk remains open in overview counts. Imported assertions and AI interpretation are not verified findings; absence on retest is not proof of resolution.

No production deployment, merge or release has been performed. Use synthetic data for demonstrations and retain the supported single-worker topology. Readiness requires evidence for the remaining operational gates, not merely a successful build.

The current complete acceptance at `22ae65292fa6c4682ab0758b59f2bc84d92f2644` adds custom roles, service identities and durable scan claims/leases. Backend passed with Mongo on Python 3.11/3.12 (**312 tests each**); frontend passed (**112 tests in 36 suites and production build**); Docker and real Nginx/Compose Chromium passed (links above). Earlier scanner/analyst acceptance is recorded at `1f15da7ae96195b5cef1fb5685060c1a640c6b34`. Remaining gates include multiworker coordination and acceptance, broader import/correlation/CVSS/applicability coverage, native adapters, retention, tamper-evident audit, backup/restore and monitored release acceptance. This is not production-ready.
