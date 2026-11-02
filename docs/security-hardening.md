# Authentication hardening

## API behavior

- Register requires a passphrase of at least 12 Unicode code points and at most
  72 UTF-8 bytes (BCrypt's input limit). No forced character-class composition.
  Previously registered short passwords can still log in. Overlong login input
  never authenticates and performs a dummy BCrypt comparison.
- Valid new and duplicate registration requests both return HTTP 200 with no body.
  Both hash the supplied password. The existing account/password is never overwritten.
  PostgreSQL `ON CONFLICT(email) DO NOTHING` handles concurrent duplicates atomically.
  Clients should present a generic outcome. This is not email ownership verification.
- Missing users perform a comparison against a startup-generated dummy cost-12 hash.
  Disabled and known users also perform password comparison before rejection.
  This reduces the dominant timing discrepancy, not all timing side channels.
- Invalid login credentials now return 401 / `INVALID_CREDENTIALS` (previously 400).
  Refresh errors have generic public text. Malformed JSON/validation errors remain 400.
- Stale Bearer headers on register/login/refresh are ignored so recovery works.
  Protected endpoints continue validating JWTs. Logout does not immediately invalidate
  existing access JWTs, and disabled users' existing JWTs still expire naturally.
- Unexpected errors, including internal IllegalArgumentException, return generic 500
  with `X-Error-Id`; the ID, method/path and stack trace are logged server-side.
  No request body or Authorization header is logged by the handler. Restrict log access.

## Rate limits

The existing per-IP login and refresh limits remain. Add:

| Variable | Default | Scope |
| --- | --- | --- |
| `APP_RATE_LIMIT_REGISTER_LIMIT` | 5 | registrations / IP / existing 60-second window |
| `APP_RATE_LIMIT_ACCOUNT_LIMIT` | 10 | login attempts / normalized account |
| `APP_RATE_LIMIT_ACCOUNT_WINDOW_SECONDS` | 300 | account window duration |

The account bucket is independent of client IP and applies to both existing and
unknown accounts, successes and failures. Keys use HMAC-SHA256 with the configured
refresh pepper; no email or password appears in a Redis key. Rotating that secret
also resets account buckets. Rejections do not prolong the bucket's TTL. There is
no persistent account lock flag; an attacker can nevertheless consume the budget
again in subsequent windows. This is a throttling/availability tradeoff, not complete
credential-stuffing or account-lockout-DoS prevention. Redis failures fail closed with
503. All instances must share Redis and configuration.

`APP_TRUSTED_PROXIES` is empty by default. It accepts a comma-separated list of
literal proxy socket IPs (no CIDR or hostnames). Only a request whose actual peer is
on that list can use a **single** literal `X-Forwarded-For` address. Invalid/multiple
addresses fall back to the proxy IP. The ingress MUST overwrite incoming XFF, never
append untrusted values; network access to the app must be limited to that ingress.
Do not list general client networks or enable arbitrary forwarded-header processing.
`server.forward-headers-strategy` remains `none`. NAT clients still share an IP budget.

## Token storage and cleanup

V2 adds `uq_refresh_token_hash` and `idx_refresh_expiry`. A duplicate hash stops the
migration: inspect and resolve existing duplicates explicitly; no session rows are
silently deleted. Before upgrade, check:

```sql
SELECT token_hash, COUNT(*)
FROM refresh_tokens
GROUP BY token_hash
HAVING COUNT(*) > 1;
```

An hourly application scheduler deletes at most 1000 rows expired more than 30 days
ago per instance. Configure `APP_TOKEN_CLEANUP_ENABLED`, `APP_TOKEN_CLEANUP_RETENTION_DAYS`
and `APP_TOKEN_CLEANUP_BATCH_SIZE` (1..10000); `app.token-cleanup.cron` controls scheduling.
The retention period is at least one day. Deletes are bounded and transactional,
with an expiry index. Multiple instances can delete in overlapping batches safely,
but throughput/locking and retention backlog should be monitored.

Old rotated tokens are retained for the grace period to support reuse detection.
After a row is purged it is unknown and rejected, but cannot trigger family-wide
reuse revocation. Active tokens and more recent history remain.

## Deployment defaults

Database username/password are required outside tests; Compose requires
`POSTGRES_PASSWORD` instead of embedding it. Existing initialized Postgres databases
keep their password: changing the environment alone does NOT change stored credentials.
The app HTTP port binds only to localhost. Configure TLS at a controlled ingress.
Swagger/OpenAPI are disabled unless `APP_API_DOCS_ENABLED=true`; enable deliberately
for local use. SQL logging is off, Docker runtime UID/GID is 10001, and one SecretKey
bean is shared by JWT signing and parsing. Database/container volumes are not reset.

## Remaining work

Spring Boot is still 3.3.2. A framework upgrade must be handled in a separate migration
with compatible Spring Security, springdoc and tests; these authentication changes
must not be taken as resolving framework support or all dependency vulnerabilities.
Immediate access-token invalidation, verified-email enrollment, recovery/MFA, breach
password checks and comprehensive abuse protection remain outside this PR.
