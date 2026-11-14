CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP(6) WITH TIME ZONE
);
CREATE INDEX idx_password_reset_user ON password_reset_tokens(user_id);
CREATE INDEX idx_password_reset_expiry ON password_reset_tokens(expires_at);

ALTER TABLE mail_outbox ALTER COLUMN token_id DROP NOT NULL;
ALTER TABLE mail_outbox ADD COLUMN reset_token_id UUID REFERENCES password_reset_tokens(id) ON DELETE CASCADE;
ALTER TABLE mail_outbox ADD COLUMN reset_notice BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE mail_outbox ADD CONSTRAINT chk_mail_outbox_source CHECK (
    (token_id IS NOT NULL AND reset_token_id IS NULL AND NOT reset_notice)
    OR (token_id IS NULL AND reset_token_id IS NOT NULL)
);
CREATE INDEX idx_mail_outbox_reset_token ON mail_outbox(reset_token_id);
