CREATE TABLE auth_sessions (
    id UUID NOT NULL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    last_seen_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP(6) WITH TIME ZONE,
    user_agent VARCHAR(255),
    ip VARCHAR(255)
);
CREATE INDEX idx_session_user_active ON auth_sessions (user_id, created_at DESC, id DESC) WHERE revoked_at IS NULL;
CREATE INDEX idx_session_expiry ON auth_sessions (expires_at);
-- Coordinated cutover: legacy JWTs have no sid and legacy refresh tokens cannot mint new session JWTs.
-- Preserve token history. New refresh family_id values logically reference auth_sessions.id.
UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE revoked_at IS NULL;
