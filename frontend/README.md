# VAPT-X frontend

The React workspace uses Create React App with CRACO, Tailwind CSS, and an Axios API client. Development and production builds do not require Emergent services, visual editing packages, or external session recording.

## Local development

Use Yarn 1.22.22 (the version pinned in `package.json`). From this directory:

```sh
yarn install
yarn start
```

For a separate local backend, create `frontend/.env.local` with:

```dotenv
REACT_APP_BACKEND_URL=http://localhost:8000
```

The client appends `/api` to this origin. If the variable is absent or blank, it uses `/api` on the frontend's own origin; configure your reverse proxy to forward that path to FastAPI. Trailing slashes are normalized. Environment variables are embedded at build time, so restart development or rebuild after changing them.

Authentication uses cookies. Configure backend CORS for the exact frontend origin and use matching hostnames (for example, `localhost` on both services).

## Verification

```sh
yarn test --watchAll=false --runInBand
yarn build
```

The API configuration regression tests cover same-origin fallback and explicit backend URL normalization. The production bundle is written to `build/` and should be served by a static web server with SPA fallback. The development server is not a production server.

Optional development compiler health endpoints are enabled with `ENABLE_HEALTH_CHECK=true`; these are independent of the backend's health checks.
