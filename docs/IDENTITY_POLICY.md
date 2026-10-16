# Registration and verified email policy

Defaults preserve existing behavior: `REGISTRATION_MODE=open` and `REQUIRE_VERIFIED_EMAIL=0`. GET `/api/auth/policy` exposes these public deployment choices. No mail or admission policy is enabled by this change.

| Setting | Behavior |
| --- | --- |
| `REGISTRATION_MODE=open` | Anyone can create an account; organization access remains separately authorized. |
| `REGISTRATION_MODE=invite_only` | Account creation requires a pending, unexpired invitation for the submitted email and its current issuing administrator/membership/credential epoch. Requires `ORG_INVITATIONS_ENABLED=1` and valid TLS SMTP configuration. |
| `REGISTRATION_MODE=closed` | Self-registration is denied; existing accounts can sign in. Operator bootstrap remains available. |
| `REQUIRE_VERIFIED_EMAIL=1` | Requires `EMAIL_VERIFICATION_ENABLED=1` and valid TLS SMTP configuration. Every authenticated workspace request checks proof bound to the current registered address. |

Invitation-backed registration creates an account only. It neither consumes the invitation nor grants membership. Explicit acceptance rechecks authority and preserves existing roles. The signup UI keeps the invitation token in memory, clears the fragment and sends it only in the registration body.

Unverified users can authenticate with their normal password/MFA into a limited browser session. They can inspect their identity, request email proof, change their password, inspect/revoke their own sessions, view account security history, preview invitations, or sign out. They cannot access workspace/platform data, enroll MFA, create/join organizations, or mint API tokens. Existing bearer tokens are denied until their owner is verified. The browser shows a verification gate and refreshes account state if policy is enabled during an existing session.

Confirm the email link explicitly, then return to the original tab and refresh verification status. If opening a proof link replaces an invitation in the same tab, reopen the original invitation after confirmation. Email proof does not sign the user in or grant a role.

Before enabling mandatory verification, configure and validate delivery, verify the operator owner's registered address, and communicate the change to existing users. There is no privileged account bypass: existing owners and tokens are subject to the policy. The startup checks validate configuration, not actual relay delivery. If delivery fails, the operator must repair mail or deliberately restore the previous policy. Keep mail credentials outside source control.

Optional [linked OIDC sign-in](OIDC.md) preserves this policy and does not provision or verify accounts. Durable cross-worker membership coordination remains separate work. Invitation authority can change between registration validation and account insertion; that creates no organization access, and acceptance performs fresh checks. Mail tests are mocked against disposable accounts and MongoDB.
