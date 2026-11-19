# Step-up session reauthentication

Step-up records **recent authentication within an existing server-side session**, not a new JWT or a global user flag. The timestamp is persisted in `auth_sessions.last_step_up_at`, and checked against the session state on each protected action.

## API

Both endpoints require a valid bearer access JWT and an active PostgreSQL session:

- `GET /sessions/step-up` returns `{ "elevated": true|false, "validUntil": "..."|null }`.
- `POST /sessions/step-up` takes `{ "password": "...", "code": "123456" }` and returns `{ "validUntil": "..." }`. The code is **required only when MFA is enabled**. For MFA accounts, only a current TOTP is accepted for step-up, not an emergency recovery code. A valid password is required in all cases.

With `APP_STEP_UP_TTL_SECONDS=300` (default), recent authentication lasts five minutes. The configurable limit is 60–3600 seconds.

All new password-login and MFA-verified login sessions start with a recent authentication timestamp. Older sessions migrated from V7 start with `last_step_up_at = NULL` and must explicitly reauthenticate. Password login, session step-up and TOTP validation are serialized through the user's PostgreSQL row lock. TOTP counters are replay-protected across concurrent sessions.

The following operations require a currently valid step-up **inside their service transaction**:

- `DELETE /sessions/{id}` — revoke a selected session
- `DELETE /sessions/others` — revoke all other sessions

If the recent proof expired, the API returns HTTP 403 `STEP_UP_REQUIRED` and the client should prompt for `POST /sessions/step-up`, then retry the original action. Invalid step-up credentials return HTTP 401 `INVALID_STEP_UP`; failed attempts contribute to existing account failure-rate limits.

MFA enrollment/disable/regeneration already require explicit password and/or authenticator proof, so they keep their dedicated flows rather than requiring an extra redundant elevation. Logout using a refresh token remains usable without step-up to allow a user to end a compromised session.

**Important:** refresh-token rotation does **not** update `last_step_up_at`. No `elevated` claim is added to JWTs: a valid signed token alone cannot extend session elevation. Revocation of a session invalidates its step-up timestamp immediately.

See [TOTP MFA](totp-mfa.md) for authenticator configuration and recovery-code semantics.
