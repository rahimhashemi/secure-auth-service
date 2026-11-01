# Secure Auth Service

A Java 17 / Spring Boot authentication sample with PostgreSQL-backed sessions.
This is a portfolio project, not a production-ready identity provider.

## Implemented

- BCrypt password hashing and signed, short-lived JWT access tokens.
- Random 384-bit opaque refresh tokens; only peppered hashes are stored.
- Refresh token expiration checks and rotation within a session family.
- Reuse detection that revokes all refresh sessions for the user.
- Database user-row locks serialize session mutations across application instances.
- Disabled users cannot obtain new tokens through refresh.
- Logout of a refresh token and logout of all refresh sessions using an active refresh token.
- Audit events in independent transactions, including failed login and refresh reuse.
- Swagger UI and a protected `/me` endpoint.

## Run locally

Requires Docker Engine / Docker Desktop and Docker Compose v2. Generate local secrets
and keep them outside source control:

```bash
export APP_JWT_SECRET="$(openssl rand -hex 32)"
export APP_REFRESH_PEPPER="$(openssl rand -hex 32)"
docker compose up --build
```

The Dockerfile builds the JAR; no prebuilt `target` directory is required.
PostgreSQL and Redis ports are bound to localhost. Redis is included for future
experiments and is not currently used for rate limiting.

- API: http://localhost:8080
- Swagger: http://localhost:8080/swagger-ui.html
- Health: http://localhost:8080/actuator/health

JWT secret and refresh pepper are required configuration. The JWT secret must have
at least 32 UTF-8 bytes. The development database credentials in Compose are local
examples. Changing the pepper invalidates existing refresh tokens; changing the JWT
key invalidates existing access tokens. Key rotation is not implemented.

## API examples

```bash
curl -X POST localhost:8080/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@example.com","password":"Passw0rd!"}'

curl -X POST localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@example.com","password":"Passw0rd!"}'

curl localhost:8080/me -H 'Authorization: Bearer <ACCESS_TOKEN>'

curl -X POST localhost:8080/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refreshToken":"<REFRESH_TOKEN>"}'

curl -X POST localhost:8080/auth/logout \
  -H 'Content-Type: application/json' \
  -d '{"refreshToken":"<REFRESH_TOKEN>"}'
```

`POST /auth/logout-all` accepts the same request body and requires an active,
unexpired refresh token.

## Token and transaction behavior

Access tokens expire after 15 minutes by default. Refresh tokens expire 14 days
after issuance; rotation renews that lifetime. There is no absolute session lifetime.

A reused refresh token revokes **all refresh sessions** for its user. This change
commits even though the request returns 401. Clients must serialize refresh requests:
two concurrent requests using the same token cause one rotation and then reuse
revocation, so the returned successor is also revoked.

Logout, reuse revocation, and account disablement do not immediately invalidate
already issued access tokens. They remain usable until JWT expiry.

Audit entries use independent transactions. Success entries describe an attempted
operation and can remain if the surrounding transaction subsequently fails.

## Tests

```bash
# Full suite: Docker required for PostgreSQL Testcontainers
bash mvnw -B verify

# JWT filter regression tests without Docker
bash mvnw -B -Dtest=JwtAuthFilterTest test
```

The PostgreSQL integration suite covers expired refresh rejection, rotation and
persisted reuse revocation, concurrent refresh attempts, disabled users, failed-login
audit persistence, and rejection of stale tokens for logout-all. Filter tests check
invalid-token rejection and propagation of downstream failures. CI runs the full suite;
it does not silently skip database tests when Docker is absent.

## Remaining limitations

- No rate limiting, MFA, email verification, password reset, or OAuth2/OIDC support.
- Hibernate `ddl-auto: update` is used for development; versioned migrations are needed.
- No immediate access-token revocation or automatic expired-token cleanup.
- Database locks serialize session operations per user, with no custom lock timeout policy.
- Registration normalization/concurrency behavior and broader HTTP endpoint coverage need work.
- Deployment hardening, TLS, browser credential storage and CSRF policy require a deployment-specific review.
