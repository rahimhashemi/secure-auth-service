ALTER TABLE users ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN verification_sent_at TIMESTAMP(6) WITH TIME ZONE;
-- Require existing accounts to prove mailbox ownership too; never send a migration email blast.
UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE revoked_at IS NULL;
UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE revoked_at IS NULL;
CREATE TABLE email_verification_tokens (
 id UUID PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 token_hash VARCHAR(64) NOT NULL UNIQUE,
 created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
 expires_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
 used_at TIMESTAMP(6) WITH TIME ZONE
);
CREATE INDEX idx_verification_user ON email_verification_tokens(user_id);
CREATE INDEX idx_verification_expiry ON email_verification_tokens(expires_at);
CREATE TABLE mail_outbox (
 id UUID PRIMARY KEY,
 token_id UUID NOT NULL REFERENCES email_verification_tokens(id) ON DELETE CASCADE,
 payload TEXT,
 attempts INTEGER NOT NULL DEFAULT 0,
 next_attempt_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
 expires_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
 finished_at TIMESTAMP(6) WITH TIME ZONE
);
CREATE INDEX idx_outbox_pending ON mail_outbox(next_attempt_at, id) WHERE finished_at IS NULL;
CREATE INDEX idx_outbox_expiry ON mail_outbox(expires_at);
