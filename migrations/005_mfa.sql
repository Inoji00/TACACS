BEGIN;
CREATE TABLE mfa_factors (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    secret_reference TEXT NOT NULL CHECK (secret_reference LIKE 'secret://%'),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    last_accepted_step BIGINT NOT NULL DEFAULT -1,
    FOREIGN KEY (user_id, tenant_id) REFERENCES users(id, tenant_id)
);
COMMIT;
