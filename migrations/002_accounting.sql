BEGIN;
CREATE TABLE accounting_records (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    session_id TEXT NOT NULL,
    username TEXT NOT NULL,
    device_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('start', 'stop', 'watchdog')),
    arguments JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX accounting_tenant_session ON accounting_records(tenant_id, session_id);
COMMIT;
