ALTER TABLE admin_grants ADD COLUMN generation UUID NOT NULL DEFAULT gen_random_uuid();

CREATE FUNCTION set_device_console_access(
    tenant UUID, actor UUID, subject UUID, allow_access BOOLEAN
) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    affected INTEGER;
BEGIN
    IF actor IS NULL OR subject IS NULL OR actor = subject OR allow_access IS NULL THEN
        RETURN NULL;
    END IF;

    PERFORM id FROM tenants WHERE id = tenant FOR UPDATE;
    IF NOT EXISTS (
        SELECT 1 FROM users u JOIN admin_grants g
            ON g.tenant_id = u.tenant_id AND g.user_id = u.id
        WHERE u.tenant_id = tenant AND u.id = actor
            AND u.enabled AND NOT u.locked AND NOT u.deleted
            AND g.permission = 'users.manage'
    ) THEN
        RETURN NULL;
    END IF;

    PERFORM id FROM users
        WHERE tenant_id = tenant AND id = subject AND NOT deleted FOR UPDATE;
    IF NOT FOUND OR EXISTS (
        SELECT 1 FROM admin_grants
        WHERE tenant_id = tenant AND user_id = subject
            AND permission NOT IN ('console.read', 'devices.manage')
    ) THEN
        RETURN NULL;
    END IF;

    IF allow_access THEN
        INSERT INTO admin_grants(tenant_id, user_id, permission)
        VALUES (tenant, subject, 'console.read'), (tenant, subject, 'devices.manage')
        ON CONFLICT DO NOTHING;
    ELSE
        DELETE FROM admin_grants
        WHERE tenant_id = tenant AND user_id = subject
            AND permission IN ('console.read', 'devices.manage');
    END IF;
    GET DIAGNOSTICS affected = ROW_COUNT;
    RETURN affected > 0;
END;
$$;

DO $$
BEGIN
    EXECUTE format(
        'ALTER FUNCTION %I.set_device_console_access(uuid, uuid, uuid, boolean) SET search_path TO pg_catalog, %I, pg_temp',
        current_schema(), current_schema()
    );
END;
$$;
REVOKE ALL ON FUNCTION set_device_console_access(uuid, uuid, uuid, boolean) FROM PUBLIC;
