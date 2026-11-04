# Secure Auth Service

A Java 17 / Spring Boot 4.1.2 authentication sample with PostgreSQL-backed sessions.
This is a portfolio project, not a production-ready identity provider.

## Implemented

- BCrypt password hashing and signed, short-lived JWT access tokens.
- Random 384-bit opaque refresh tokens; only peppered hashes are stored.
- Refresh token expiration checks and rotation within a session family.
- Reuse detection that revokes the affected refresh session family.
- Database user-row locks serialize session mutations across application instances.
- Disabled users cannot obtain new tokens through refresh.
- Logout of a refresh token and logout of all refresh sessions using an active refresh token.
- Audit events in independent transactions, including failed login and refresh reuse.
- Swagger UI and a protected `/me` endpoint.
- Shared Redis rate limits for login and refresh, with HTTP 429 and Retry-After.
- Versioned PostgreSQL migrations with Flyway and Hibernate schema validation.

Latest routing/security corrections: [routing and audit repair](docs/auth-routing-and-audit.md).

Platform dependencies and migration notes: [Spring Boot upgrade](docs/spring-boot-upgrade.md).

## Run locally

Requires Docker Engine / Docker Desktop and Docker Compose v2. Generate local secrets
and keep them outside source control:

```bash
export POSTGRES_PASSWORD="$(openssl rand -hex 24)"
export APP_JWT_SECRET="$(openssl rand -hex 32)"
export APP_REFRESH_PEPPER="$(openssl rand -hex 32)"
export APP_RATE_LIMIT_ACCOUNT_KEY="$(openssl rand -hex 32)"
docker compose up --build
```

The Dockerfile builds the JAR; no prebuilt `target` directory is required.
PostgreSQL and Redis ports are bound to localhost. Redis is required for login
and refresh rate limiting and Compose waits for its health check.

- API: http://localhost:8081
- Swagger (opt-in with `APP_API_DOCS_ENABLED=true`): http://localhost:8081/swagger-ui.html
- Health: http://localhost:8081/actuator/health

JWT secret and refresh pepper are required configuration. The JWT secret must have
at least 32 UTF-8 bytes. Database credentials must be configured explicitly; Compose requires
`POSTGRES_PASSWORD`. Changing the pepper invalidates existing refresh tokens; changing the JWT
key invalidates existing access tokens. Key rotation is not implemented.

## API examples

```bash
curl -X POST localhost:8081/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@example.com","password":"Correct-Horse-123!"}'

curl -X POST localhost:8081/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@example.com","password":"Correct-Horse-123!"}'

curl localhost:8081/me -H 'Authorization: Bearer <ACCESS_TOKEN>'

curl -X POST localhost:8081/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refreshToken":"<REFRESH_TOKEN>"}'

curl -X POST localhost:8081/auth/logout \
  -H 'Content-Type: application/json' \
  -d '{"refreshToken":"<REFRESH_TOKEN>"}'
```

`POST /auth/logout-all` accepts the same request body and requires an active,
unexpired refresh token.

## Token and transaction behavior

Access tokens expire after 15 minutes by default. Refresh tokens expire 14 days
after issuance; rotation renews that lifetime. There is no absolute session lifetime.

A reused, unexpired refresh token revokes **its session family**. Other devices remain
active. Expired history is rejected without revocation. Family revocation commits even
though the request returns 401. Clients must serialize refresh requests:
two concurrent requests using the same token cause one rotation and then reuse
revocation, so the returned successor is also revoked.

Access JWTs carry a required `sid`. Every authenticated request checks the session
and the user's enabled state in PostgreSQL. Logout, family reuse revocation and
logout-all invalidate the corresponding access tokens on the next request. A request
already authorized and running may finish. See [session management](docs/session-management.md).

Audit entries use independent transactions. Success entries describe an attempted
operation and can remain if the surrounding transaction subsequently fails.

## Login and refresh rate limits

By default each socket peer IP gets separate budgets of **10 login attempts** and
**30 refresh attempts** in a **60-second fixed window**, starting at the first request.
All POST attempts count, including successful, invalid, and malformed requests.
Registration has a separate default limit of 5 requests per IP/window. Other endpoints are not covered. Redis executes the check, increment, and expiry
atomically so multiple application instances share the same budget. Redis keys use
SHA-256 of the address and never include passwords, email addresses, or tokens.
An address hash is pseudonymous, not anonymous.

- Exhausted budget: `429`, JSON code `RATE_LIMIT_EXCEEDED`, and `Retry-After` in seconds.
- Redis failure: `503`, JSON code `RATE_LIMIT_UNAVAILABLE`; login and refresh fail closed.
- Rejected attempts do not extend the window. Budget resets when the Redis key expires.
- Fixed windows allow bursts near window boundaries; this is not a sliding-window limiter.
- Redis command and connect timeouts default to one second each.

Configuration (also forwarded by Compose):

| Environment variable | Default |
| --- | --- |
| `APP_RATE_LIMIT_ENABLED` | `true` |
| `APP_RATE_LIMIT_LOGIN_LIMIT` | `10` |
| `APP_RATE_LIMIT_REFRESH_LIMIT` | `30` |
| `APP_RATE_LIMIT_WINDOW_SECONDS` | `60` |

Limits must be positive and window size must be 1..86400 seconds. Disabling the
limiter explicitly bypasses Redis checks. All instances must use the same Redis
database and settings. Redis restarts, eviction, or data loss can reset budgets.

Automatic forwarded-header processing is disabled. `X-Forwarded-For` is ignored unless
the peer is explicitly listed in `APP_TRUSTED_PROXIES` and supplies one literal client IP. Behind a reverse proxy, requests share the proxy address budget until
trusted-ingress address handling is deliberately configured. Clients sharing a NAT
also share a budget. IP rotation/distributed attacks can bypass IP-only limits; an additional normalized-account
login budget now limits failed attempts across IPs; successful logins do not consume or reset it. Edge protection remains necessary. No account lockout is
implemented. Do not enable arbitrary forwarded-header trust on an internet-facing app.

## Database migrations

On an empty database, Flyway creates the three auth tables from the versioned SQL
under `src/main/resources/db/migration`; Hibernate then validates the schema instead
of changing it. Applied migration checksums are checked on startup. Automatic baseline
and Flyway clean are disabled.

**Existing databases created by Hibernate need a deliberate adoption step.** Startup
will refuse an unmanaged nonempty schema. Follow [the migration guide](docs/database-migrations.md)
to compare the schema, preserve data and explicitly baseline a verified version 1.
A baseline records history; it does not repair schema differences.

## Tests

```bash
# Full suite: Docker required for PostgreSQL and Redis Testcontainers
bash mvnw -B verify

# Filter regression tests without Docker
bash mvnw -B -Dtest=JwtAuthFilterTest,RateLimitFilterTest test
```

See [authentication hardening](docs/security-hardening.md) for account throttling, trusted
proxy configuration, generic registration responses, password policy, cleanup and deployment defaults.

The PostgreSQL integration suite covers expired refresh rejection, rotation and
persisted reuse revocation, concurrent refresh attempts, disabled users, failed-login
audit persistence, and rejection of stale tokens for logout-all. Filter tests check
invalid-token rejection and propagation of downstream failures. CI runs the full suite;
it does not silently skip database tests when Docker is absent.

Rate-limit tests cover real Redis expiry, exact thresholds, separate IP/operation
buckets, 40 concurrent attempts through two independent Redis clients, HTTP filter
wiring, malformed request counting, forwarded-header spoofing, 429 headers, and
fail-closed behavior when Redis is unavailable.

Migration tests also check empty schema initialization, data retention on repeat
migration, refusal of unmanaged schemas and checksum mismatch rejection. The auth
suite runs with Flyway and production Hibernate validation, without `create-drop`.

## Remaining limitations

- No MFA, email verification, password reset, or OAuth2/OIDC support.
- Existing Hibernate databases require verified, manual Flyway adoption; separate migration/runtime DB roles are not configured.
- No immediate access-token revocation. Expired refresh history is cleaned in bounded batches after a retention period.
- Database locks serialize session operations per user, with no custom lock timeout policy.
- Registration normalization/concurrency behavior and broader HTTP endpoint coverage need work.
- Deployment hardening, TLS, browser credential storage and CSRF policy require a deployment-specific review.






## Manage sessions

`GET /sessions?page=0&size=20` lists your active sessions (maximum size 100), including
creation/last activity times, initial IP/user agent, expiry and a `current` flag.
`DELETE /sessions/{id}` revokes one of your sessions; `DELETE /sessions/others` keeps
only the calling session. Both return 204. Supply an access token in the Bearer header.
Unknown or another user's session id returns the same 204 without changing that user.

**V4 deployment cutover:** stop old instances before migrating and start only the
new version afterwards. V4 revokes legacy refresh tokens; JWTs without `sid` are
rejected. All existing users must sign in again. Do not run old and new versions
concurrently or roll back the binary: old binaries do not enforce session revocation.
