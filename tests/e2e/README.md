# Browser integration gate

This separate, lockfile-pinned Playwright package tests the production React build
against the actual API and MongoDB. It registers a disposable synthetic user and
organization, creates an exact `training://local` scope, imports explicitly
synthetic Semgrep data, triages a finding, verifies uploaded evidence bytes,
downloads PDF/JSON/CSV reports, checks cross-session revocation and persisted
login state, and revokes scope authorization to verify further imports are denied.
It does not run a scanner or contact external targets.

The `Browser integration` Actions workflow installs dependencies, builds the
frontend, starts Compose services, runs Chromium, retains failure traces and
screenshots, and destroys its containers and database volume. The test static
server binds loopback port 3000 and proxies `/api` only to loopback port 8001,
preserving browser cookies, Origin, and CSRF headers. Do not use it for hosting.

To run locally, use Node 22 or newer, build `frontend/build` with an empty
`REACT_APP_BACKEND_URL`, and start a disposable API/database configured with
`FRONTEND_URL=http://localhost:3000`, `VAPTX_LOCAL_HTTP=1`, and API port 8001.
Then, from this directory:

```sh
npm ci
npx playwright install --with-deps chromium
npm test
```

Ports 3000 and 8001 must be available for the static server and API respectively.
The suite creates synthetic persistent test records, so use a disposable database.
Reports and browser artifacts are ignored by git. The suite can be enumerated
without backend services using `npm test -- --list`.
