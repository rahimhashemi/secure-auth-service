
# Secure Auth Service (Spring Boot)

Production-style authentication service built with **Spring Boot 3 / Java 17**, implementing:

* Stateless JWT access tokens
* Refresh token rotation
* Reuse detection
* Server-side revocation
* Audit logging
* Integration tests with Testcontainers

Designed as a foundation for secure, distributed backend systems (FinTech-ready).

---

# 🚀 Features

### 🔐 Authentication

* Email/password authentication
* BCrypt password hashing
* Stateless JWT access tokens (short-lived)

### 🔄 Refresh Token Strategy

* Opaque refresh tokens (not JWT)
* **Hashed storage (SHA-256 + server-side pepper)**
* Rotation on every refresh
* Reuse detection
* Session family tracking
* Logout / Logout-all support

### 🛡 Security Controls

* Token reuse detection triggers session revocation
* Refresh tokens never stored in plaintext
* Stateless access tokens
* CSRF-safe (API-first design)
* Audit trail for auth-related events

### 📜 Audit Logging

Tracks:

* LOGIN_SUCCESS / LOGIN_FAIL
* REFRESH_SUCCESS / REFRESH_FAIL
* REFRESH_REUSE
* LOGOUT
* LOGOUT_ALL

### 🧪 Integration Testing

* Postgres via Testcontainers
* Full login → refresh → reuse detection flow covered

---

# 🏗 Architecture

```
Client
   |
   |  (1) Login
   v
AuthController
   |
   v
AuthService
   |
   |----> UserRepository (Postgres)
   |----> RefreshTokenService
               |
               |----> RefreshTokenRepository (Postgres)
               |----> RefreshTokenHasher (SHA-256 + pepper)
   |
   |----> JwtService (HS256)
   |
   |----> AuditService
```

### Token Model

Access Token:

* JWT (15 min default)
* Stateless
* Contains userId + email

Refresh Token:

* 384-bit secure random opaque token
* Hashed before storage
* Stored with:

    * familyId (session group)
    * revokedAt
    * replacedBy
    * expiresAt

---

# 🔄 Refresh Token Rotation Logic

1. Client sends refresh token
2. Server hashes token
3. Lookup in DB
4. If:

    * Not found → invalid
    * Already revoked or replaced → **reuse detected**
5. On valid refresh:

    * Current token revoked
    * New refresh token issued
    * Access token re-issued

If reuse detected:

* All user sessions revoked (configurable)
* Event logged

---

# 🔎 Threat Model (Simplified)

| Threat                     | Mitigation                 |
| -------------------------- | -------------------------- |
| Stolen refresh token reuse | Rotation + reuse detection |
| DB leak                    | Refresh tokens hashed      |
| Access token replay        | Short TTL                  |
| Session fixation           | Rotation strategy          |
| Horizontal scaling issues  | Stateless access tokens    |

---

# ▶ Running Locally

```bash
docker compose up --build
```

Service:

```
http://localhost:8080
```

---

# 📡 API Examples

### Register

```bash
curl -X POST localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Passw0rd!"}'
```

### Login

```bash
curl -X POST localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Passw0rd!"}'
```

### Call Protected Endpoint

```bash
curl localhost:8080/me \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

### Refresh

```bash
curl -X POST localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<REFRESH_TOKEN>"}'
```

### Logout

```bash
curl -X POST localhost:8080/auth/logout \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<REFRESH_TOKEN>"}'
```

---

# 🧪 Tests

Run:

```bash
mvn test
```

Covers:

* Login flow
* Refresh rotation
* Reuse detection
* Protected endpoint access

Uses:

* Testcontainers (Postgres)
* Spring Boot integration testing

---

# 🧠 Design Decisions

Why opaque refresh tokens instead of JWT refresh?

* Server-side control
* Revocation support
* Reuse detection
* Reduced attack surface

Why hash refresh tokens?

* Prevent plaintext token exposure in case of DB leak
* Similar principle to password storage

Why stateless access tokens?

* Horizontal scalability
* No server memory dependency
* Works well in distributed systems

---

# 📈 Possible Extensions (Roadmap)

* TOTP-based MFA
* Device fingerprinting
* OAuth2 / OpenID Connect support
* Redis-based rate limiting
* Prometheus metrics
* Key rotation support
* JWK endpoint

---

# 👤 About the Author

Senior Java Backend Engineer with 10+ years of experience building secure, scalable banking systems.

Specialized in:

* Distributed architecture
* JWT & secure authentication
* PKI / digital signatures
* Enterprise modernization

---
