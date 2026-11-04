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
| `APP_RATE_LIMIT_ACCOUNT_LIMIT` | 10 | failed logins / normalized account |
| `APP_RATE_LIMIT_ACCOUNT_WINDOW_SECONDS` | 300 | account window duration |

The account bucket is independent of client IP and applies to both existing and
unknown accounts. Admission checks the failure count before BCrypt; only completed
credential failures consume it. Successful login neither consumes nor resets failures.
Concurrent requests admitted before the failure threshold is reached can exceed that
threshold; this is not a strict bound on in-flight BCrypt work. The IP limiter still
counts every request. Keys use HMAC-SHA256 with the independent
`APP_RATE_LIMIT_ACCOUNT_KEY`; no email or password appears in a Redis key. Rotating that account secret
resets account buckets without affecting refresh tokens. Rejections do not prolong the bucket's TTL. There is
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

An hourly scheduler drains up to 10 batches of 1000 rows expired more than 30 days
ago per instance. Every batch commits in its own `REQUIRES_NEW` transaction through
a separate service. It stops on a partial batch, a database failure, the batch cap,
or when the five-second runtime budget is reached between batches. The runtime
budget does not cancel a running database statement; monitor database statement
latency and configure database timeouts as appropriate for the deployment.

Configure `APP_TOKEN_CLEANUP_ENABLED`, `APP_TOKEN_CLEANUP_RETENTION_DAYS` (at least 1),
`APP_TOKEN_CLEANUP_BATCH_SIZE` (1..10000), `APP_TOKEN_CLEANUP_MAX_BATCHES` (1..1000), and
`APP_TOKEN_CLEANUP_MAX_RUNTIME_SECONDS` (1..300). `app.token-cleanup.cron` controls scheduling.
Multiple instances can delete overlapping batches safely, but lock contention and
retention backlog still need monitoring. The caps intentionally bound work per run;
raise capacity or scheduling frequency if expiration exceeds cleanup throughput.

Expired history is rejected before reuse detection, so it cannot invalidate live
sessions. An unexpired reused token revokes only its family, including the rotated
successor. Other families remain valid. Retention is for audit/history, not a retry
grace period. There is no idempotent refresh retry: clients must serialize refresh
and must not retry a consumed token blindly. After purge, a token is unknown and
rejected without revocation. Already-issued access JWTs remain valid until expiry.

## Deployment defaults

Database username/password are required outside tests; Compose requires
`POSTGRES_PASSWORD` instead of embedding it. Existing initialized Postgres databases
keep their password: changing the environment alone does NOT change stored credentials.
The app HTTP port binds only to localhost. Configure TLS at a controlled ingress.
Swagger/OpenAPI are disabled unless `APP_API_DOCS_ENABLED=true`; enable deliberately
for local use. SQL logging is off, Docker runtime UID/GID is 10001, and one SecretKey
bean is shared by JWT signing and parsing. Database/container volumes are not reset.

## Remaining work

Spring Boot is upgraded to 4.1.2 with compatible springdoc and managed Security
dependencies; see [the platform migration notes](spring-boot-upgrade.md). This does
not establish that all dependencies are vulnerability-free.
Immediate access-token invalidation, verified-email enrollment, recovery/MFA, breach
password checks and comprehensive abuse protection remain outside this PR.


