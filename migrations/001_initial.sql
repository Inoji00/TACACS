BEGIN;
CREATE TABLE tenants (id UUID PRIMARY KEY, name TEXT NOT NULL UNIQUE);
CREATE TABLE users (id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id), username TEXT NOT NULL, password_hash TEXT NOT NULL, enabled BOOLEAN NOT NULL DEFAULT TRUE, failed_logins INTEGER NOT NULL DEFAULT 0, locked BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(tenant_id, username));
CREATE TABLE policy_versions (id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id), revision INTEGER NOT NULL, state TEXT NOT NULL CHECK (state IN ('draft','test','approval','active','archived')), author_id UUID NOT NULL REFERENCES users(id), approver_id UUID REFERENCES users(id), rules JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(tenant_id, revision));
CREATE UNIQUE INDEX one_active_policy_per_tenant ON policy_versions(tenant_id) WHERE state='active';
CREATE TABLE audit_events (id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id), occurred_at TIMESTAMPTZ NOT NULL, actor TEXT NOT NULL, source TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, result TEXT NOT NULL, policy_version TEXT, session_id TEXT, correlation_id TEXT NOT NULL, security_context JSONB NOT NULL, previous_hash CHAR(64) NOT NULL, event_hash CHAR(64) NOT NULL);
CREATE INDEX audit_events_tenant_time ON audit_events(tenant_id, occurred_at DESC);
COMMIT;
