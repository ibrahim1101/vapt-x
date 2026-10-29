# vapt-x

VAPT-X is an experimental workspace for authorized security assessments, evidence, remediation and reporting.

## Branch and validation status

The default branch is an earlier snapshot. Current development is on [`dev/vapt-x-foundation-hardening`](https://github.com/ibrahim1101/vapt-x/tree/dev/vapt-x-foundation-hardening). Updating this README does not merge that implementation into `main`.

The development branch retains React, FastAPI and MongoDB with organization-scoped workflows, identity controls, scan/report paths and regression suites. Optional integrations have their own limitations. The supported deployment remains one API worker until failure/recovery acceptance is complete. No production certification is claimed.

- [Development README](https://github.com/ibrahim1101/vapt-x/blob/dev/vapt-x-foundation-hardening/README.md)
- [Implementation matrix](https://github.com/ibrahim1101/vapt-x/blob/dev/vapt-x-foundation-hardening/docs/FEATURE_MATRIX.md)
- [Local setup](https://github.com/ibrahim1101/vapt-x/blob/dev/vapt-x-foundation-hardening/docs/WINDOWS_LOCAL_DEV.md)
- [Release readiness](https://github.com/ibrahim1101/vapt-x/blob/dev/vapt-x-foundation-hardening/docs/RELEASE_READINESS.md)

Review CI evidence at its exact commit. Source presence, hosted tests, physical-device acceptance and production readiness are separate evidence levels. No fresh runtime, deployment or installer acceptance was performed for this documentation update.

Earlier documentation remains in [README_VAPTX.md](README_VAPTX.md). Use scanners only against explicitly authorized targets.
