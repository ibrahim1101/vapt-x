# VAPT-X local Windows development

Use Docker Desktop (Linux containers), Git, Python 3.11+ and Node.js/Yarn compatible with `frontend/package.json` (Yarn 1.22.22). These instructions reflect the current source; this session has not verified Windows or Docker execution.

## Database and configuration

From the repository root in PowerShell:

```powershell
Copy-Item backend/.env.example backend/.env
docker compose -f compose.local.yml up -d mongodb
docker compose -f compose.local.yml ps
```

Edit `backend/.env` before starting the API. Keep `MONGO_URL=mongodb://127.0.0.1:27018` and `DB_NAME=vaptx_local` for a host-run backend. Set a fresh JWT secret of at least 32 characters, your admin email, and a unique admin password (10+ characters and at most 72 UTF-8 bytes). Placeholder secrets are rejected. Do not commit `.env` or credentials.

Local settings:

```dotenv
FRONTEND_URL=http://localhost:3000
INTERNAL_API_URL=http://127.0.0.1:8001
NMAP_BINARY=nmap
VAPTX_LOCAL_HTTP=1
MONGO_TIMEOUT_MS=5000
```

The local HTTP flag is permitted only for a loopback frontend. Production needs HTTPS and `VAPTX_LOCAL_HTTP=0`. `FRONTEND_URL` must exactly match the browser origin. MongoDB host port **27018** maps to container port 27017 and is bound to loopback. Its named volume preserves data; do not use `down -v` unless you intentionally mean to delete that volume.

## Host-run API

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend/requirements-dev.txt
Set-Location backend
python -m uvicorn server:app --host 127.0.0.1 --port 8001 --workers 1
```

Use a single API worker until distributed membership/service coordination and multiworker scan cancellation/result acceptance are complete. Scan jobs use durable Mongo claims and leases: queued work is picked up after restart, while running work with an expired lease is marked interrupted instead of replayed. Configuration and database connectivity are checked on startup. `/api/live` is liveness; `/api/health` checks database readiness and returns 503 on database failure. If startup fails, check Docker health, port, credentials and required configuration; do not weaken production controls.

## Optional containerized API

With `backend/.env` configured, from the repository root:

```powershell
docker compose -f compose.local.yml --profile api up -d --build
docker compose -f compose.local.yml --profile api logs api
```

The Compose API profile overrides the database URI to `mongodb://mongodb:27017` and uses the container's own loopback for its managed training endpoint. The non-root image does not include Nmap; safe checks and report imports remain available. This profile has not been built in the current Work environment because Docker is unavailable.

## Frontend

Create `frontend/.env.local`:

```dotenv
REACT_APP_BACKEND_URL=http://localhost:8001
```

Use `localhost` consistently in the browser/backend URL so cookies behave as expected. In another PowerShell window:

```powershell
Set-Location frontend
yarn install
yarn start
```

Open `http://localhost:3000`. For same-origin deployment the API client can use `/api`; configure a reverse proxy and exact CORS origin. Variables are embedded during build; restart/rebuild after changes. See `frontend/README.md` for build and test commands.

## Optional AI and scanners

The application does not require Emergent services. Claude is optional: install `backend/requirements-ai.txt`, set `ANTHROPIC_API_KEY` and `CLAUDE_MODEL`, and restart the API. For a container AI build, set `VAPTX_INSTALL_AI=true` before building. No real provider call is part of default tests. A configured key is not proof of provider availability.

Nmap execution requires a separately installed Nmap executable and authorized scope. Without it, use supported report imports. Start with the owned `training://local` target, an explicit authorization reference, permitted scanner and valid time window. Never scan unrelated systems to test installation.

## Verification and limitations

Run `python -m pytest` from `backend` after installing test requirements. Database integration tests require the explicit test database environment documented in `docs/TESTING.md`; never point them at valuable data. Verify login, refresh/logout, organization creation, project persistence after restart and selected assessment workflows before calling setup complete.

Frontend dependency/build checks, backend unit results and unavailable runtime checks are recorded in `docs/DEVELOPMENT_LOG.md`. Local bootstrap is not production deployment; database authentication, backups, retention and full workflow/tenant-isolation testing remain release gates.
