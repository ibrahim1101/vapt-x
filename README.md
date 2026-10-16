# VAPT-X

An organization-scoped workspace for authorized security assessments, scanner-report imports, evidence, remediation and versioned reporting. The existing React, FastAPI, MongoDB and Docker application is retained.

Start with the [local development guide](docs/WINDOWS_LOCAL_DEV.md) and [testing guide](docs/TESTING.md). The supported deployment currently requires one API worker; scanner ownership and membership coordination are process-local.

- [Current implementation and acceptance evidence](docs/FEATURE_MATRIX.md)
- [Architecture](docs/ARCHITECTURE.md) and [security model](docs/SECURITY_MODEL.md)
- [Optional integrations](docs/INTEGRATIONS.md)
- [Optional password recovery](docs/PASSWORD_RECOVERY.md): disabled by default; configured TLS mail delivery is required and existing MFA remains required, as described in the guide
- [Registered-email verification](docs/EMAIL_VERIFICATION.md) and [organization invitations](docs/INVITATIONS.md): independently opt-in; matching-account checks and explicit confirmation/acceptance
- [Engineering roadmap](docs/MASTER_ROADMAP.md) and [development history](docs/DEVELOPMENT_LOG.md)
- [Release readiness](docs/RELEASE_READINESS.md): production acceptance remains incomplete

Synthetic tests exercise the controlled training target and mocked integrations. Passing them does not establish exhaustive scanner coverage or production readiness. No live mail, AI or notification destination is enabled by the example configuration.
