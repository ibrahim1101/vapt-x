# Acceptance checkpoint — 2026-10-22

Verified code: `1be6804abd578f2cd6f85de0abedc10ddf59cebf`.

- Backend: 320 tests passed on Python 3.11 and 3.12 ([run 39743939878](https://github.com/ibrahim1101/vapt-x/actions/runs/39743939878)).
- Frontend: 112 tests across 36 suites and production build ([run 39743939916](https://github.com/ibrahim1101/vapt-x/actions/runs/39743939916)).
- Docker smoke ([run 39743939840](https://github.com/ibrahim1101/vapt-x/actions/runs/39743939840)).
- Chromium against the Nginx/Compose application ([run 39743939913](https://github.com/ibrahim1101/vapt-x/actions/runs/39743939913)).

The acceptance suite includes concurrent scan-admission requests and an assessment cancellation request through two live API processes, plus recovery of an expired scan lease during API startup. Deployment remains limited to one API worker. Further multiworker failure testing and the release-readiness work listed in `RELEASE_READINESS.md` remain outstanding. This checkpoint is test evidence, not production approval.
