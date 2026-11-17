BEGIN;
CREATE TABLE identity_groups (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    UNIQUE (tenant_id, name),
    UNIQUE (id, tenant_id)
);
ALTER TABLE users ADD CONSTRAINT users_id_tenant_unique UNIQUE (id, tenant_id);
CREATE TABLE user_groups (
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    user_id UUID NOT NULL,
    group_id UUID NOT NULL,
    PRIMARY KEY (tenant_id, user_id, group_id),
    FOREIGN KEY (user_id, tenant_id) REFERENCES users(id, tenant_id),
    FOREIGN KEY (group_id, tenant_id) REFERENCES identity_groups(id, tenant_id)
);
COMMIT;
