# Release readiness

Updated 2026-10-16. **Not ready for production release.** Core workflows have repeatable API, container and browser evidence; the full roadmap and operational acceptance are incomplete.

Verified code: `752b7047612f8b225f4db5738a72ecde51a75349`. See [FEATURE_MATRIX.md](FEATURE_MATRIX.md) for current implementation and CI links, and [DEVELOPMENT_LOG.md](DEVELOPMENT_LOG.md) for historical checkpoints.

| Gate | Current evidence | Outstanding work |
|---|---|---|
| Reproducible installation/build | Backend pins, frozen Yarn, Python 3.11/3.12, 56 frontend tests and production build | Dependency/secret review and release reproducibility policy |
| Startup/configuration/health/body limits | Unit and Compose startup/smoke checks | Monitored deployment and degraded-service operations |
| Identity and tenant boundaries | 178 backend tests with Mongo; cookie/origin/CSRF, MFA, disable/reactivate, membership and token tests | Reset/verification, invitations/OIDC and project ACL |
| Core workflow | Chromium against actual non-root Nginx/API/Mongo; synthetic imports/evidence/remediation/PDF/retest | More large datasets, error/accessibility review and upstream schema variants |
| Scanner safety | Exact scope/window/profile, pinned transport, timeout/cancel regression and training target | Broader sandboxing and durable worker ownership |
| Reports/evidence | Checksums, ready-state guards, versioned source snapshots, PDF visual review | Complete-set and size limits still apply; retention/quotas/malware controls |
| Deployment topology | Explicit one-API-worker contract | Distributed assessment ownership and membership mutation coordination are blocking before multiple workers |
| Data operations | Integration secrets and MFA secrets use optional encryption keys | Key rewrapping, retention, backup/restore drills and tamper-proof audit storage |
| Integrations | Mocked safe webhook delivery and optional provider contracts | No live provider/destination acceptance; native ticket/chat/email adapters remain |
| Release operations | CI, images and synthetic acceptance | Upgrade/restore/rollback drills, monitoring/alerting and release/version policy |

Account disable and membership removal block subsequent authenticated operations; requests and organization jobs already in progress may finish. Archive is project metadata and does not revoke scope. Accepted risk remains open in overview counts. Imported assertions and AI interpretation are not verified findings; absence on retest is not proof of resolution.

No production deployment, merge or release has been performed. Use synthetic data for demonstrations and retain the supported single-worker topology. Readiness requires evidence for the remaining operational gates, not merely a successful build.
