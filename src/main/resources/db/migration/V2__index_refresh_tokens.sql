-- Fail on duplicate hashes rather than silently deleting or selecting session data.
CREATE UNIQUE INDEX uq_refresh_token_hash ON refresh_tokens (token_hash);
CREATE INDEX idx_refresh_expiry ON refresh_tokens (expires_at);
