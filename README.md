# VAPT-X

An organization-scoped workspace for authorized security assessments, scanner-report imports, evidence, remediation and versioned reporting. The existing React, FastAPI, MongoDB and Docker application is retained.

Start with the [local development guide](docs/WINDOWS_LOCAL_DEV.md) and [testing guide](docs/TESTING.md). Scan jobs and short membership/service-identity mutation sections now use Mongo leases, but the supported deployment still requires one API worker while scan admission, cancellation/result atomicity and full multiworker failure acceptance remain incomplete.

- [Current implementation and acceptance evidence](docs/FEATURE_MATRIX.md)
- [Architecture](docs/ARCHITECTURE.md) and [security model](docs/SECURITY_MODEL.md)
- [Optional integrations](docs/INTEGRATIONS.md)
- [Optional password recovery](docs/PASSWORD_RECOVERY.md): disabled by default; configured TLS mail delivery is required and existing MFA remains required, as described in the guide
- [Membership project access](docs/PROJECT_ACCESS.md): administrator grants, live browser/token enforcement and scoped files/counts
- [Stored secret key rewrapping](docs/KEY_ROTATION.md): operator dry-run/apply tooling for MFA, webhooks and OIDC
- [Optional linked OIDC sign-in](docs/OIDC.md): explicit linking, PKCE and preserved local MFA/admission policy
- [Registration and required verification policy](docs/IDENTITY_POLICY.md): explicit open, invitation-only or closed registration; optional workspace admission gate
- [Registered-email verification](docs/EMAIL_VERIFICATION.md) and [organization invitations](docs/INVITATIONS.md): independently opt-in; matching-account checks and explicit confirmation/acceptance
- [Engineering roadmap](docs/MASTER_ROADMAP.md) and [development history](docs/DEVELOPMENT_LOG.md)
- [Release readiness](docs/RELEASE_READINESS.md): production acceptance remains incomplete

Synthetic tests exercise the controlled training target and mocked integrations. Passing them does not establish exhaustive scanner coverage or production readiness. No live mail, AI or notification destination is enabled by the example configuration.
