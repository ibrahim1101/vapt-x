# Security model and outstanding risks

Updated 2026-10-16. This describes implemented boundaries, not security certification or production approval. Current synthetic acceptance evidence is in [FEATURE_MATRIX.md](FEATURE_MATRIX.md); release gates are in [RELEASE_READINESS.md](RELEASE_READINESS.md).

Users, imported scanner reports, evidence and AI text are untrusted. Browser-supplied organization/project IDs select resources; membership, role and organization-scoped queries determine authority. Uploaded assertions and AI interpretation do not authorize scanning or establish exploitability.

| Boundary | Implemented control | Remaining limit |
|---|---|---|
| Authentication | bcrypt byte limits, cookie sessions, atomic refresh and attempt budgets, password/credential-epoch changes, account disable/reactivate | Registration policy, mandatory email-verification policy and OIDC remain deployment/identity work |
| Browser writes | Exact trusted Origin, CSRF cookie/header checks and credentialed single-origin CORS | Production-origin/cookie/deployment acceptance remains |
| Cookies | HttpOnly access/refresh cookies, SameSite=Lax, Secure by default; explicit loopback-only development HTTP | Supported browser/deployment combinations still require operational acceptance |
| MFA | Encrypted TOTP, atomic replay checks, hash-only one-use recovery codes and step-up for credential administration | Optional operator key; no automatic key rewrapping |
| Mail identity flows | Opt-in TLS SMTP; hash-only expiring reset/verification/invitation links, purpose-specific collections and account/address/epoch binding | No durable mail queue, delivery retry guarantee or live provider acceptance |
| Email proof | Explicit one-use confirmation records a verified registered address; changed address invalidates displayed status | Does not automatically sign in, grant access or enforce a new sign-in policy |
| Invitations | Administrator issuance/revocation, private recipient preview, signed-in matching email, explicit acceptance and fresh issuer authority | Single-worker coordination; claim, membership and audit writes are not a transaction |
| Organizations/tokens | Forced organization scope, fixed roles, fresh membership checks, anti-orphan removal and membership-bound API tokens | No project ACL, custom roles or service identities |
| Scanning | Exact host/time window/scanner permission, fresh pre-execution checks, bounded pinned transport and managed cancellation | Process-local ownership; no durable scheduler, broad sandbox or exhaustive scanner coverage |
| Imports/inventory | Bounded parsers, supported-format fixtures and secret/code omission in relevant adapters | Uploader-declared asset association; not every upstream schema; inventory is not vulnerability execution |
| Evidence/reports | Private chunked uploads, signatures, SHA-256 downloads, versioned integrity-checked snapshots and explicit complete-set caps | Retention, quotas, malware handling and abandoned-data cleanup remain |
| AI | Optional configured providers/models, bounded findings context, heuristic redaction, no tool invocation or raw evidence files | Redaction is not guaranteed; no live provider retention/consent acceptance |
| Webhooks | Opt-in encrypted secrets, fixed public HTTPS destinations, DNS-pinned Host/SNI transport, HMAC and leased bounded retries | No exactly-once delivery or atomic domain-write/outbox enqueue; no live destination activated |
| Audit | Organization events and private account history with metadata attribution and tenant checks | Application records are not a tamper-proof external ledger; account history is best effort |
| Data operations | Non-root containers, optional integration/MFA encryption keys, explicit configuration | Key rewrapping, monitored deployment, backup/restore/rollback drills and release policy remain |

Roles are `org_admin`, `security_lead`, `analyst`, `auditor` and `viewer`. Organization administrators manage membership and invitations. Read roles can inspect organization audit records under the existing organization-wide read policy. API tokens intersect their explicit scopes with the owner's current role, credential epoch and membership lifetime; they cannot enter account/session/organization-administration routes or mint credentials. Owner labels are metadata, not permissions.

Scopes authorize exact normalized hosts rather than wildcard/subdomain ranges. Remote private networks are blocked except the explicit managed `training://local` target. Nmap uses a constrained TCP-connect profile; no exploit scripts are enabled. Scope withdrawal blocks new scans/imports and queued pre-execution checks; an already-running check may finish within its timeout. Assessment cancellation is available but ownership/cancellation coordination remains process-local. Archive does not withdraw scope.

Credential changes invalidate previous sessions/API tokens through database-checked epochs, including credentials inserted late by an old request. Disabling an account or removing membership blocks subsequent authenticated operations; requests and jobs already in progress may finish. Rejoining creates a new membership identity, and retained revocation markers prevent old unbound tokens from reviving. Password recovery preserves enabled MFA and never automatically signs in. Email proof and invitation acceptance do not change passwords, disable MFA or independently grant a session.

Invitation acceptance rechecks the recipient account and issuing administrator's active membership identity and credential epoch. Existing roles and other-organization memberships are preserved. Interrupted or ambiguous membership writes can require administrator review; consumed links cannot be replayed to overwrite a role. Retain the one-API-worker contract until distributed membership and scan ownership are implemented.

Use only disposable identities, owned training fixtures and mocked mail/AI/webhook delivery for default acceptance. Do not commit real secrets or customer evidence. Production readiness requires the outstanding operational gates and broader authorization/error-path review, not merely passing synthetic workflows.
