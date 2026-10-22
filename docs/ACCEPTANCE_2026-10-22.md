# Acceptance checkpoint — 2026-10-22

Verified code: `2098a592ba568081ed56313d7acbe9f3562534c5`.

- Backend: 320 tests passed on Python 3.11 and 3.12 ([run 39743217365](https://github.com/ibrahim1101/vapt-x/actions/runs/39743217365)).
- Frontend: 112 tests across 36 suites and production build ([run 39743217304](https://github.com/ibrahim1101/vapt-x/actions/runs/39743217304)).
- Docker smoke ([run 39743217316](https://github.com/ibrahim1101/vapt-x/actions/runs/39743217316)).
- Chromium against the Nginx/Compose application ([run 39743217326](https://github.com/ibrahim1101/vapt-x/actions/runs/39743217326)).

The acceptance suite includes concurrent scan-admission requests through two live API processes and recovery of an expired scan lease during API startup. Deployment remains limited to one API worker. Further multiworker failure testing and the release-readiness work listed in `RELEASE_READINESS.md` remain outstanding. This checkpoint is test evidence, not production approval.
