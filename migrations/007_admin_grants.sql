BEGIN;
CREATE TABLE admin_grants (
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    permission TEXT NOT NULL CHECK (permission IN (
        'console.read', 'users.manage', 'devices.manage', 'policy.draft',
        'policy.approve', 'policy.activate', 'audit.read', 'backup.manage')),
    PRIMARY KEY (tenant_id, user_id, permission),
    FOREIGN KEY (user_id, tenant_id) REFERENCES users(id, tenant_id)
);
COMMIT;
