-- Pending and enabled TOTP configurations share one row per user.
-- The authenticator seed is AES-256-GCM ciphertext, with the user UUID as AAD.
CREATE TABLE user_mfa (
    user_id UUID NOT NULL PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_ciphertext VARCHAR(512) NOT NULL,
    enabled_at TIMESTAMP(6) WITH TIME ZONE,
    last_used_counter BIGINT NOT NULL DEFAULT -1
);

-- 128-bit random recovery codes are never stored in plaintext, only keyed HMAC-SHA256 digests.
CREATE TABLE mfa_recovery_codes (
    id UUID NOT NULL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(64) NOT NULL,
    used_at TIMESTAMP(6) WITH TIME ZONE,
    CONSTRAINT uq_mfa_recovery_code UNIQUE (user_id, code_hash)
);
CREATE INDEX idx_mfa_recovery_user ON mfa_recovery_codes (user_id);

-- Password-authenticated pre-MFA state is NOT a JWT or refresh session.
CREATE TABLE mfa_login_challenges (
    token_hash VARCHAR(64) NOT NULL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash VARCHAR(120) NOT NULL,
    expires_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    consumed_at TIMESTAMP(6) WITH TIME ZONE,
    failed_attempts INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_mfa_challenge_expiry ON mfa_login_challenges (expires_at);
CREATE INDEX idx_mfa_challenge_user ON mfa_login_challenges (user_id);
