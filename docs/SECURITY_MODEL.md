# Security model and outstanding risks

This is an implementation audit, not a security certification. Source inspected 2026-10-14 UTC. Test evidence belongs in [TESTING.md](TESTING.md).

## Trust boundaries

Users and uploaded reports/evidence are untrusted. Organization identifiers supplied by the browser are selectors, not authority. The server checks membership, role and organization-scoped resource lookup. Scanner output is an observation; imports remain `imported-unverified`; AI is interpretation and never authorizes a scan or changes finding severity.

| Boundary | Existing control | Remaining validation or work |
| --- | --- | --- |
| User authentication | bcrypt passwords, expiring access/refresh JWTs, DB session revocation | Refresh races/rotation replay tests, session expiry enforcement/cleanup, MFA, reset, verification, account disable |
| Browser writes | Exact Origin check, CSRF cookie/header comparison, credentialed single-origin CORS | Cross-origin negative tests and production deployment validation |
| Cookies | HttpOnly access/refresh, SameSite=Lax, Secure by default; explicit loopback HTTP development mode | Test logout deletion, expired session and production config rejection |
| Tenant isolation | Membership lookup and forced `org_id` repository filters | Every endpoint/download/background job needs regression coverage; project permissions absent |
| Scanning | Scope reference, exact host, time window, scanner allowlist, membership recheck at execution | Authorization expiry during long execution; cancellation; per-process concurrency limitations |
| Network access | Public-IP validation, IP-pinned requests, original Host/SNI, no redirects/proxies for safe checks | DNS/IPv6/error-path fixtures and controlled real transport verification |
| Nmap | Fixed TCP-connect profile, argument list, restricted ports, timeout/kill | Worker sandboxing, bounded stdout/stderr and process cleanup on cancellation |
| Imports | Payload/model bounds, supported formats, XML DOCTYPE/entity rejection, 2,000 findings cap | Deep/nested or malformed input fixtures, parser CPU bounds, import-to-asset attribution remains uploader-declared |
| Evidence | Extension allowlist, binary signatures, chunk length, owner-only writes, SHA-256 on download | Completion/write concurrency, quotas, retention, malware handling and abandoned upload cleanup |
| Reporting | HTML escaping, stored snapshot bytes, organization-scoped download | SHA-256 verification on download, missing PDF handling, complete pagination and large-document limits |
| AI | Role/owner/project checks, context cap, raw evidence excluded, defensive system instruction | Redaction of secrets in finding text, prompt injection tests, provider retention/consent settings, history limits |
| Audit | Application writes events; no public mutation route | Authentication events incomplete; no cryptographic integrity/external ledger, retention policy or guaranteed denied-event delivery |

## Authorization semantics

Roles are `org_admin`, `security_lead`, `analyst`, `auditor`, `viewer`. Administrators have all permissions. Leads can authorize scope; analysts can write, scan, triage, remediate, report, use AI and manage evidence. Auditors/viewers have read access; current generic read routes also return organization audit records. There are no custom roles, project memberships, API-token authentication routes or service-account workflows despite helper names for tokens.

A scope authorizes an exact normalized host rather than a wildcard/subdomain range. Only HTTP(S) target syntax and ports 80, 443, 8080 and 8443 are accepted. Repository/container asset labels do not create specialized scanning authorization. Local/private destinations are rejected except the application's explicit `training://local` target. Training routes intentionally omit some security headers and contain only non-sensitive fixtures.

## Known security work before release

1. Verify tenant isolation and authorization on every route, not only repository methods.
2. Test bounded input handling including malformed Content-Length and streamed request bodies.
3. Add distributed job ownership/concurrency and cancellation before multi-worker deployment.
4. Keep the webhook helper inactive: it validates DNS then connects by hostname, leaving rebinding exposure, and defaults to environment proxy trust. Add pinned transport and encrypted secrets before exposing it.
5. Add account lifecycle and authentication auditing; restrict registration/bootstrap according to deployment policy.
6. Define database authentication, encryption at rest/in transit, backup access and recovery procedures. Base64 is encoding, not encryption.
7. Add retention and per-tenant storage quotas for evidence, reports, jobs and conversations.
8. Resolve report/comparison pagination so incomplete data cannot mislead security decisions.

Do not use real customer evidence in tests or commit `.env` credentials. Active testing is restricted to owned fixtures or explicitly approved targets and windows. No exploit, persistence, stealth, credential-attack or destructive scanner functionality is part of this design.
