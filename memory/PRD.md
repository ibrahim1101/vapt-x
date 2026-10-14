# VAPT-X

## Product and original requirements
Enterprise AI-powered vulnerability assessment and penetration testing platform. A genuine full-stack workflow, never fabricated findings or mock controls. Authorized scope only.

User selections: email/password JWT with roles and organizations; Claude initially via Emergent Universal Key; extensible provider architecture; safe HTTP headers/TLS/DNS/security.txt/cookie checks, real Nmap where available; genuine Nmap XML, Nuclei JSONL, Semgrep JSON, Trivy JSON and ZAP JSON imports. Full lifecycle: registration → organization → project → authorized scope → assets → assessment → scan → findings → evidence → PDF → remediation → retest → comparison → dashboard/audit → persistence. Owner seeded from ADMIN_EMAIL (real signed-in email) and ADMIN_PASSWORD, never publish values.

## Architecture
React/shadcn frontend, FastAPI /api backend, MongoDB via existing MONGO_URL/DB_NAME. HttpOnly cookie JWT with persisted sessions, CSRF checks, memberships rechecked per request. Tenant-scoped repository and role permissions. UUID logical IDs with BaseDocument serialization. Private chunked evidence in MongoDB to survive process/container restarts. Scanner subprocess argument arrays, no shell; explicit scope, approved time window and allowed scanner checks; public IP restrictions and pinned DNS. Controlled server-owned training target is the only loopback exception. Background scan state persisted; interrupted work marked interrupted on process startup (no false completion).

## Plan (implementation in progress)
1. Identity + tenant data layer. Test login, registration, session revocation and cross-tenant/role denial.
2. Project/scope/asset/assessment APIs, checks and imports. Test out-of-scope denial, genuine training checks, Nmap and five parser formats.
3. Triage, evidence, reports, remediation, retest/comparison, AI sessions and audit. Test chunk hashes/download authorization, rendered PDF, stored state and AI grounding.
4. Build connected dark workspace from design_guidelines.json. Test desktop/mobile end-to-end and restart persistence.

## Current state
2026-02: Resumed paused initial work. Existing core.py/webhooks.py were helpers only; server/frontend stock template. Protected env keys present, Nmap installed, dependencies recorded. No workflow verified yet.

## Prioritized backlog
P0: Complete/test above core workflow, real results only.
P1: MFA/TOTP, email verification/recovery, richer session management, granular project membership and enterprise platform administration.
P2: Scheduled scans, notifications/webhooks, additional AI providers, advanced modules and integrations, attack surface visualization, richer report templates.
No broad cleanup planned; split new implementation into focused modules as required. No production-readiness claim until tested; production scanner binary availability is environment-dependent.
