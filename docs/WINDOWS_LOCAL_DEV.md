# VAPT-X local Windows development (first bootstrap)

This first bootstrap runs MongoDB in Docker and runs the existing FastAPI and React code locally. It does not require Emergent credits. The full app has **not yet been validated on Windows**.

## Prerequisites
- Docker Desktop running in Linux-container mode
- Git, Python 3.11+ and Node.js 20+
- Yarn 1.x (the frontend package declares Yarn 1.22)

## Database
From the repository root:
```powershell
docker compose -f compose.local.yml up -d
docker compose -f compose.local.yml ps
```
MongoDB is exposed **only on localhost** and its files persist in the `vaptx_mongo_data` named volume. Never run `docker compose down -v` unless you intentionally want to delete the database.

## Backend environment
Create `backend/.env` locally (do not commit it):
```dotenv
MONGO_URL=mongodb://127.0.0.1:27017
DB_NAME=vaptx_local
JWT_SECRET=REPLACE_WITH_A_LONG_RANDOM_SECRET
ADMIN_EMAIL=REPLACE_WITH_YOUR_EMAIL
ADMIN_PASSWORD=REPLACE_WITH_A_STRONG_UNIQUE_PASSWORD
FRONTEND_URL=http://localhost:3000
INTERNAL_API_URL=http://127.0.0.1:8001
NMAP_BINARY=nmap
EMERGENT_LLM_KEY=
CLAUDE_MODEL=
```
Use a freshly generated secret and password; do not copy real credentials into chats, issues, or commits.

**Known integration blocker:** Existing auth code sets `Secure` cookies and therefore requires HTTPS in browsers. Do not weaken production cookie security just to make localhost work. The next sprint will add a strictly development-scoped localhost cookie mode or HTTPS local reverse proxy.

**Known dependency blocker:** `backend/requirements.txt` references an Emergent-hosted wheel; its availability outside Emergent must be verified before a reproducible local backend install can be claimed. The next sprint will replace provider-specific dependencies or make them optional.

## Frontend
The frontend currently uses Create React App + CRACO. Create `frontend/.env.local` locally:
```dotenv
REACT_APP_BACKEND_URL=http://localhost:8001
```
The frontend also has Emergent-specific development packages; installation outside Emergent has not yet been verified.

## Current milestone
The database bootstrap is reproducible. Full backend/frontend startup, authentication, and scanner execution remain to be validated on a local Windows workstation.
