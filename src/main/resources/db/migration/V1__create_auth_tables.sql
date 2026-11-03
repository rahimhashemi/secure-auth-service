-- Preserve the column types and nullability of the existing Hibernate model.
-- UUIDs and timestamps are assigned by application code, not database defaults.
CREATE TABLE users (
    id UUID NOT NULL,
    email VARCHAR(190) NOT NULL,
    password_hash VARCHAR(120) NOT NULL,
    enabled BOOLEAN NOT NULL,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_users PRIMARY KEY (id)
);
CREATE UNIQUE INDEX idx_users_email ON users (email);

CREATE TABLE refresh_tokens (
    id UUID NOT NULL,
    user_id UUID NOT NULL,
    token_hash VARCHAR(128) NOT NULL,
    family_id UUID NOT NULL,
    issued_at TIMESTAMP(6) WITH TIME ZONE,
    expires_at TIMESTAMP(6) WITH TIME ZONE,
    revoked_at TIMESTAMP(6) WITH TIME ZONE,
    replaced_by UUID,
    user_agent VARCHAR(255),
    ip VARCHAR(255),
    CONSTRAINT pk_refresh_tokens PRIMARY KEY (id)
);
CREATE INDEX idx_refresh_user ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_family ON refresh_tokens (family_id);

-- No user FK: failed authentication can have no user, and independent audit
-- transactions must not depend on locks held by the authentication transaction.
CREATE TABLE audit_events (
    id UUID NOT NULL,
    at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    user_id UUID,
    type VARCHAR(60) NOT NULL,
    detail VARCHAR(500),
    ip VARCHAR(255),
    user_agent VARCHAR(255),
    CONSTRAINT pk_audit_events PRIMARY KEY (id)
);
CREATE INDEX idx_audit_user ON audit_events (user_id);
CREATE INDEX idx_audit_type ON audit_events (type);
