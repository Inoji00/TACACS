BEGIN;
ALTER TABLE admin_grants DROP CONSTRAINT admin_grants_permission_check;
ALTER TABLE admin_grants ADD CONSTRAINT admin_grants_permission_check CHECK (permission IN (
    'console.read', 'users.manage', 'devices.manage', 'policy.draft',
    'policy.approve', 'policy.activate', 'audit.read', 'backup.manage',
    'global.audit.read', 'global.tenants.create', 'global.devices.manage', 'global.users.manage'));
COMMIT;
