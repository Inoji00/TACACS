BEGIN;
INSERT INTO identity_groups (id, tenant_id, name)
SELECT gen_random_uuid(), tenants.id, defaults.name
FROM tenants
CROSS JOIN (VALUES ('super-admin'), ('read-only')) AS defaults(name)
ON CONFLICT (tenant_id, name) DO NOTHING;
COMMIT;
