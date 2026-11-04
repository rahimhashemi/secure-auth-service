# Email verification and transactional mail delivery

## Registration and verification

Registration atomically inserts an unverified user, a random 256-bit verification
token's SHA-256 hash and an encrypted outbox row. Duplicate registration performs the
same password hash but neither overwrites credentials nor queues mail. A registered
but unverified user cannot log in, refresh or authenticate an existing access token.
Login still compares BCrypt and returns the same generic credential error.

Confirmation uses POST with the token in JSON. A user-row lock serializes confirmation,
including two different valid links: only the first confirmation succeeds. Every token
expires after 30 minutes. A resend leaves earlier links valid until the first success;
all other links then become unusable because the owner is already verified. Success
is audited with user id, never the token. Confirmation does not create a session.

The minimal confirmation page receives the token in a URL fragment, removes it from
the address bar and requires an explicit button click. No automatic GET consumes it,
no third-party assets are loaded, and links use a configured origin rather than Host.
The origin must be HTTPS except for loopback development. Email scanners executing
only GET requests do not consume tokens. A compromised mailbox or client remains
outside the protection of email verification. Never confirm an unexpected registration.
A pre-registered account's password is not reset by verification; password recovery is
a separate future feature. Existing users retain their existing password.

## Abuse limits and responses

Request returns the same 202 body for unknown, disabled, verified and pending accounts.
Responses are generic, not a constant-time protocol. Per-IP request budget uses the
registration limit (default 5/min); confirmation uses the refresh limit (30/min).
Both use MVC-aligned encoded-path matching. Normalized-account HMAC buckets allow
3 requests/hour across IPs, including unknown accounts. The account secret is the
independent rate-limit key, and the namespace is separate from login failures.
A per-user database cooldown prevents issuing mail more than once/minute, including
across instances. Rate-limit exhaustion returns 429, Redis failure 503. Edge protection
is still needed against distributed email bombing and large-scale registration.

## Outbox security and concurrency

Recipient and plaintext token exist only inside AES-256-GCM ciphertext in mail_outbox.
Verification table stores only SHA-256. Each encryption has a random 96-bit nonce and
binds the outbox id as additional authenticated data. `APP_MAIL_OUTBOX_KEY` is an
independent 32-byte key represented as exactly 64 hex characters. Keep it in a secret
manager/environment, shared across instances. Never log bodies, links, payloads or
SMTP exceptions; exception messages can include credentials or mail content.

A worker claims one due row with FOR UPDATE SKIP LOCKED in its own transaction and
holds that row lock during SMTP. No user lock is acquired by the worker. Normal mail
volume and configured SMTP timeouts make this simpler than a lease protocol; high
throughput may justify leasing later. SMTP connect/read/write timeouts are two seconds
each. A poll handles at most five items, every ten seconds after the prior poll ends.
Failures retry after 30/60/120/240 seconds, at most five attempts, without extending
token expiry. Success, exhaustion and invalid/expired tokens erase the payload.
Pending ciphertext for consumed, verified, disabled or expired records is scrubbed
in bounded groups of 100 per poll. Ciphertext may briefly remain until that poll.

Delivery is at-least-once: a crash after SMTP acceptance but before DB commit can
send a duplicate. Confirmation is single-use. The worker rechecks token/owner state
before sending; a concurrent confirmation can still leave an in-flight obsolete email.
An obsolete link cannot verify twice. A database failure stops that poll for scheduler
retry. A dead worker releases its row lock when the connection closes.

Bounded history cleanup deletes expired verification tokens after the existing
retention period, cascading outbox rows. The coordinator's batch size applies per
table, so total deleted rows may exceed batch-size. Pending payloads are scrubbed
without waiting for that history-retention period.

## Deployment and local operation

V5 defaults all users to unverified and revokes existing sessions and refresh tokens.
Stop/drain old binaries before migration; mixed-version operation or downgrade can
bypass the new policy. The migration does not send emails. Existing users invoke
request, verify their mailbox and then sign in. A maintenance notice is appropriate.

Compose includes a Mailpit SMTP sink with UI bound to localhost:8025. Application SMTP
points to mailpit:1025 by default. Production: set SMTP_HOST/PORT/USERNAME/PASSWORD,
SMTP_AUTH=true, SMTP_STARTTLS=true as required by your provider, APP_MAIL_FROM and
APP_VERIFICATION_PUBLIC_URL. Do not expose Mailpit or use it for production delivery.
APP_MAIL_WORKER_ENABLED=false pauses processing for maintenance outside Compose.

Drain pending mail before rotating the outbox key. There is no key ring; replacing the
key makes pending payloads unreadable. Failures eventually erase them; users must
request another email subject to the normal limits. A delivered token is independent
of the encryption key. Backups containing ciphertext remain sensitive.

## Verification

CI uses PostgreSQL, Redis and real SMTP delivery to a Mailpit Testcontainer. Tests
cover atomic registration/outbox rollback, hashed/encrypted storage, duplicate sign-up,
single-use concurrent confirmation, concurrent worker claims, expiry, disabled users,
resend cooldown/budgets, generic responses, SMTP failure/recovery and bounded retries,
GCM tampering/id binding and V4-to-V5 legacy cutover. Existing auth/session tests use
explicitly verified fixtures; no production bypass or test profile disables verification.
