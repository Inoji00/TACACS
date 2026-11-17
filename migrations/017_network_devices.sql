BEGIN;
CREATE TABLE network_devices (
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    address INET NOT NULL CHECK (family(address)=4 AND masklen(address)=32),
    name TEXT NOT NULL,
    enabled BOOLEAN NOT NULL,
    secret_cipher BYTEA NOT NULL,
    secret_fingerprint BYTEA NOT NULL,
    shell_group TEXT NOT NULL,
    privilege INTEGER NOT NULL CHECK (privilege BETWEEN 0 AND 15),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id,address),
    UNIQUE (tenant_id,secret_fingerprint)
);
COMMIT;
