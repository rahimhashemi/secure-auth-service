# Session management and access-token revocation

## Storage and invariants

`auth_sessions.id` is the refresh family's UUID, also carried in the access JWT's
required `sid` claim. The session owns userId, creation time, last activity, rolling
expiry, revocation time, initial user agent and IP. PostgreSQL is the authoritative
store. The user foreign key cascades on deletion. Refresh family_id remains a logical
reference: historical pre-V4 token rows are retained without synthetic session rows.
The server creates a session before issuing its first refresh token.

Every authenticated request verifies signature, issuer, expiration and UUID claims,
then joins the session to the enabled user by session primary key and matching userId.
Database unavailability fails closed with 503 SESSION_STORE_UNAVAILABLE; invalid or
revoked session returns 401 INVALID_TOKEN. Public register/login/refresh routes retain
their existing filter bypass and own validation. There is no session cache.

The service records last activity at most once per minute using a conditional update.
This means a usual request costs one indexed read; stale activity adds a write and
lastSeenAt is approximate. IP/user agent describe login metadata, not verified device
identity. They are truncated to the column limit and are never trusted for authorization.

Session mutation follows the existing user-row lock. Login creates a new family;
refresh checks session activity and renews its expiry in the same transaction as
rotation. Logout revokes the entire family. Reuse revokes that family and commits on
the typed failure. Logout-all revokes all sessions. Session-management writes recheck
the calling session after acquiring the user lock. Revocation and refresh cannot
resurrect a closed session. Requests already authorized may finish; revocation is
observed by subsequent requests after commit. User disablement is checked on every
request; re-enabling a user can make still-unexpired non-revoked sessions usable again.

## API

All endpoints require Bearer access authentication and return the common ApiError
shape on errors. Responses contain no access token, refresh token or token hash.

| Endpoint | Behavior |
| --- | --- |
| GET /sessions?page=0&size=20 | Active sessions owned by caller, newest first; size 1..100, page 0..10000 |
| DELETE /sessions/{id} | Revoke caller-owned session and all its refresh tokens; idempotent 204 for unknown/foreign ids |
| DELETE /sessions/others | Revoke all caller's sessions except current one; 204 |

Deleting the current session is allowed and causes the next request to return 401.
Success audit events include userId and session id, never credentials. Lists are
paginated and may change between pages during concurrent logins.

## Migration and deployment

V4 creates the table/indexes and marks all existing refresh tokens revoked while
preserving history. No legacy JWT has a sid, so all existing users must log in again.
Stop/drain old instances before migration, then start the new version. A mixed-version
rolling deployment is unsafe: old binaries accept JWTs without consulting sessions.
Do not downgrade to an old binary as a rollback strategy for this security change.
Plan a maintenance window and recovery using the new code/schema.

The existing bounded cleanup coordinator deletes up to batch-size rows from each of
refresh_tokens and auth_sessions per batch in one independent transaction. Session
expiry has its own index. Retention, batch count and runtime caps still apply. A full
batch in either table causes the coordinator to continue up to its caps.

## Validation

PostgreSQL/Redis integration tests cover logout and logout-all access invalidation,
disabled users, same-sid rotation, family reuse, expired sessions, legacy and mismatched
claims, ownership, pagination, self/other revocation, activity-write throttling, cleanup,
and concurrent refresh/revocation. Filter tests cover fail-closed database outages.
Flyway tests exercise V3-to-V4 cutover and retention of revoked legacy token history.
