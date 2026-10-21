# Release readiness

Updated 2026-10-21. **Not ready for production release.** Core workflows have repeatable API, container and browser evidence; the full roadmap and operational acceptance are incomplete.

Verified code: `0ef1e8ac2fe965e6af94737efefbc122f025cf7e`. See [FEATURE_MATRIX.md](FEATURE_MATRIX.md) for current implementation and CI links, and [DEVELOPMENT_LOG.md](DEVELOPMENT_LOG.md) for historical checkpoints.

| Gate | Current evidence | Outstanding work |
|---|---|---|
| Reproducible installation/build | Backend pins, frozen Yarn, Python 3.11/3.12, 107 frontend tests and production build | Dependency/secret review and release reproducibility policy |
| Startup/configuration/health/body limits | Unit and Compose startup/smoke checks | Monitored deployment and degraded-service operations |
| Identity and tenant boundaries | Cookie/origin/CSRF, MFA, account lifecycle, membership, invitation, email proof, linked OIDC, project admission, fixed token caps, custom roles and service identities | Live OIDC provider acceptance; distributed membership/service-identity coordination |
| Core workflow | Chromium against actual non-root Nginx/API/Mongo; synthetic imports/evidence/remediation/PDF/retest | More large datasets, error/accessibility review, upstream schema variants and broader correlation/applicability evaluation |
| Scanner safety | Exact scope/window/profile, fresh queued credential admission, pinned transport, timeout/cancel regression and training target | Broader sandboxing and durable worker ownership |
| Reports/evidence | Checksums, ready-state guards, versioned source snapshots, PDF visual review | Complete-set and size limits still apply; retention/quotas/malware controls |
| Deployment topology | Durable Mongo scan claims and leases; queued work is recovered after restart, stale running work is interrupted without replay | Multiworker cancellation/result atomicity, per-organization admission coordination and distributed membership mutations are blocking before multiple workers |
| Data operations | Integration/MFA encryption and operator dry-run/CAS secret rewrapping | Retention, backup/restore drills and tamper-proof audit storage |
| Integrations | Mocked safe webhook delivery and optional provider contracts | No live AI/webhook/mail-provider acceptance; native ticket/chat adapters and durable mail delivery remain |
| Release operations | CI, images and synthetic acceptance | Upgrade/restore/rollback drills, monitoring/alerting and release/version policy |

Account disable and membership removal block subsequent authenticated operations; requests and organization jobs already in progress may finish. Archive is project metadata and does not revoke scope. Accepted risk remains open in overview counts. Imported assertions and AI interpretation are not verified findings; absence on retest is not proof of resolution.

No production deployment, merge or release has been performed. Use synthetic data for demonstrations and retain the supported single-worker topology. Readiness requires evidence for the remaining operational gates, not merely a successful build.

Latest complete CI acceptance remains `1f15da7ae96195b5cef1fb5685060c1a640c6b34` until the current custom-role, service-identity and durable-queue changes pass all workflows. The earlier head passed backend on Python 3.11/3.12 with Mongo ([38964644949](https://github.com/ibrahim1101/vapt-x/actions/runs/38964644949)), frontend ([38964644950](https://github.com/ibrahim1101/vapt-x/actions/runs/38964644950)), Docker ([38964644939](https://github.com/ibrahim1101/vapt-x/actions/runs/38964644939)) and real Nginx/Compose Chromium ([38964645043](https://github.com/ibrahim1101/vapt-x/actions/runs/38964645043)). Current local backend suite: 293 passed, 17 Mongo-dependent skips, 219 subtests; the skipped database scenarios require CI Mongo. Remaining gates include multiworker coordination and acceptance, broader import/correlation/CVSS/applicability coverage, native adapters, retention, tamper-evident audit, backup/restore and monitored release acceptance. This is not production-ready.
