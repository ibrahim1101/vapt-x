# Release readiness

Updated 2026-10-16. **Not ready for production release.** Core workflows have repeatable API, container and browser evidence; the full roadmap and operational acceptance are incomplete.

Verified code: `a078dd3bacfa7528d4e506c378680d18f3c0bfb0`. See [FEATURE_MATRIX.md](FEATURE_MATRIX.md) for current implementation and CI links, and [DEVELOPMENT_LOG.md](DEVELOPMENT_LOG.md) for historical checkpoints.

| Gate | Current evidence | Outstanding work |
|---|---|---|
| Reproducible installation/build | Backend pins, frozen Yarn, Python 3.11/3.12, 98 frontend tests and production build | Dependency/secret review and release reproducibility policy |
| Startup/configuration/health/body limits | Unit and Compose startup/smoke checks | Monitored deployment and degraded-service operations |
| Identity and tenant boundaries | 245 backend tests with Mongo; cookie/origin/CSRF, MFA, disable/reactivate, membership, invitation, email-proof, linked OIDC and token tests | Live OIDC provider acceptance, custom roles and service identities |
| Core workflow | Chromium against actual non-root Nginx/API/Mongo; synthetic imports/evidence/remediation/PDF/retest | More large datasets, error/accessibility review and upstream schema variants |
| Scanner safety | Exact scope/window/profile, pinned transport, timeout/cancel regression and training target | Broader sandboxing and durable worker ownership |
| Reports/evidence | Checksums, ready-state guards, versioned source snapshots, PDF visual review | Complete-set and size limits still apply; retention/quotas/malware controls |
| Deployment topology | Explicit one-API-worker contract | Distributed assessment ownership and membership mutation coordination are blocking before multiple workers |
| Data operations | Integration/MFA encryption and operator dry-run/CAS secret rewrapping | Retention, backup/restore drills and tamper-proof audit storage |
| Integrations | Mocked safe webhook delivery and optional provider contracts | No live AI/webhook/mail-provider acceptance; native ticket/chat adapters and durable mail delivery remain |
| Release operations | CI, images and synthetic acceptance | Upgrade/restore/rollback drills, monitoring/alerting and release/version policy |

Account disable and membership removal block subsequent authenticated operations; requests and organization jobs already in progress may finish. Archive is project metadata and does not revoke scope. Accepted risk remains open in overview counts. Imported assertions and AI interpretation are not verified findings; absence on retest is not proof of resolution.

No production deployment, merge or release has been performed. Use synthetic data for demonstrations and retain the supported single-worker topology. Readiness requires evidence for the remaining operational gates, not merely a successful build.

Latest code acceptance includes operator-only dry-run/apply secret rewrapping, explicitly linked OIDC/local-MFA sign-in and unlink/cancellation, open/invitation-only/closed registration, optional mandatory email proof, strict stored-session expiry, matching-account invitations, and complete evidence/report/scope/member/scan-job/task/audit navigation beyond 1,000 records, UTC overdue/date behavior, independent execution records, event detail inspection and explicit two-organization browser audit isolation. All four workflows passed for `a078dd3bacfa7528d4e506c378680d18f3c0bfb0`; published CI links are in the feature matrix.
