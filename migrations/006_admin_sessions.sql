BEGIN;
CREATE TABLE admin_sessions (
    token_hash CHAR(64) PRIMARY KEY,
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    mfa_verified BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY (user_id, tenant_id) REFERENCES users(id, tenant_id)
);
CREATE INDEX admin_session_expiry ON admin_sessions(expires_at);
COMMIT;
