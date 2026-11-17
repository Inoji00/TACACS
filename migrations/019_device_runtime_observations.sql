BEGIN;
ALTER TABLE network_devices ADD COLUMN revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0);
CREATE TABLE device_runtime_observations (
    tenant_id UUID NOT NULL,
    address INET NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id,address),
    FOREIGN KEY (tenant_id,address) REFERENCES network_devices(tenant_id,address)
);
COMMIT;
