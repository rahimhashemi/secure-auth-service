# TOTP MFA and one-time recovery codes

The default password login flow is unchanged for accounts without MFA. Once MFA is enabled, a correct password returns **only a five-minute challenge**, not an access or refresh token. The challenge is a 256-bit random opaque token, stored only as SHA-256 and bound to the password hash that authenticated the login.

## Configuration

Set these two **independent** secrets in the application environment before starting the application:

- `APP_MFA_ENCRYPTION_KEY`: `openssl rand -hex 32` (64 hex characters, AES-256-GCM).
- `APP_MFA_RECOVERY_PEPPER`: `openssl rand -hex 32` (HMAC-SHA256 recovery-code hashing).

Do not substitute the JWT key, refresh pepper or mail outbox key. Keep both values stable and backed up securely. Losing the encryption key makes enrolled authenticator seeds unreadable; losing the recovery pepper invalidates the stored recovery codes. Neither value belongs in source control, logs or API responses.

## Endpoints

Authenticated endpoints require a valid access token belonging to an active session:

| Method | Endpoint | Request | Behavior |
| --- | --- | --- | --- |
| GET | `/auth/mfa/status` | Bearer access token | `{ "enabled": boolean, "pending": boolean }` |
| POST | `/auth/mfa/totp/setup` | Bearer + `{ "password": "..." }` | Returns the base32 secret and `otpauth://` URI; does **not** enable MFA |
| POST | `/auth/mfa/totp/confirm` | Bearer + `{ "code": "123456" }` | Enables MFA, returns 10 one-time recovery codes, revokes all existing sessions |
| POST | `/auth/mfa/recovery/regenerate` | Bearer + `{ "password": "...", "code": "123456" }` | Requires password and a fresh **TOTP** code; invalidates all previous recovery codes and sessions |
| POST | `/auth/mfa/disable` | Bearer + `{ "password": "...", "code": "..." }` | Requires password and fresh TOTP or unused recovery code; revokes all sessions |

The public second-factor endpoint, after a successful password login:

`POST /auth/mfa/challenge/verify` with `{ "challengeToken": "...", "code": "123456" }`. The code can also be one of the recovery codes. When valid, this endpoint returns the **usual** `AuthResponse` (signed access JWT + opaque refresh token) and consumes the challenge.

Once MFA is enabled, `POST /auth/login` returns:

```json
{
  "accessToken": null,
  "accessExpiresInSeconds": 0,
  "refreshToken": null,
  "refreshExpiresInSeconds": 0,
  "mfaRequired": true,
  "mfaChallengeToken": "opaque-high-entropy-value"
}
```

Clients must never treat a challenge as a session. Do not attempt to refresh until `/auth/mfa/challenge/verify` succeeds. Failed second-factor verification returns a generic 401 `INVALID_MFA`. The rate-limit filter uses the same IP-bound login budget for challenge verification. Five incorrect factors consume an individual challenge. Account-wide failed login budgeting includes incorrect MFA responses, with Redis failing closed when enabled.

## Enrollment and security

1. Sign in with password; call `/auth/mfa/totp/setup` with the current password.
2. Scan the returned `otpauth://` URI in an authenticator app. Store the seed only as an encrypted database value, protected using the user UUID as AES-GCM additional authenticated data.
3. Confirm a six-digit code. The server accepts SHA-1 TOTP with 30-second steps and at most one step of clock skew on either side. It records the last accepted counter so a code cannot be replayed.
4. Save the recovery codes **immediately** in a password manager or other secure location. They are displayed only on creation/regeneration; only HMAC hashes remain in PostgreSQL. Each code contains 128 random bits and can only be used once.
5. All earlier sessions become invalid after enrollment, disablement, or recovery-code regeneration. Sign in again with MFA after enrollment. A TOTP just used to enroll cannot be reused to sign in during the same time step; wait for the next code.

An email password-reset **does not disable MFA**. Challenges created before a password change cannot authenticate later because the password hash snapshot no longer matches. New MFA challenges are minted only after valid password authentication. Sessions use existing PostgreSQL-backed refresh families and revocation, not a separate MFA token format.

**Operational limits:** setup seeds remain pending until confirmed and are overwritten by a new password-authorized setup. Challenge rows are pruned by the existing bounded token-cleanup worker after the configured retention period. Protect the system clock with NTP. Never log authenticator seeds, codes, provisioning URIs or challenge tokens.

## Local testing

```bash
DOCKER_HOST="unix://$HOME/.docker/desktop/docker.sock" \
TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock \
./mvnw -B verify
```

Test suites include RFC 6238 vectors, encrypted-seed isolation, authenticated enrollment, challenge-only password responses, one-time recovery consumption, lockout after five failures, session revocation and migration checks.
