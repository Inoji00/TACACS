BEGIN;
-- Preserve migration checksums; replace functions with schema-qualified targets.
CREATE OR REPLACE FUNCTION invalidate_user_admin_sessions() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.password_hash IS DISTINCT FROM OLD.password_hash
        OR NEW.enabled IS DISTINCT FROM OLD.enabled OR NEW.locked IS DISTINCT FROM OLD.locked THEN
        EXECUTE pg_catalog.format('DELETE FROM %I.admin_sessions WHERE user_id=$1 AND tenant_id=$2', TG_TABLE_SCHEMA)
            USING OLD.id, OLD.tenant_id;
    END IF;
    RETURN NEW;
END;
$$;
CREATE OR REPLACE FUNCTION invalidate_grant_admin_sessions() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    EXECUTE pg_catalog.format('DELETE FROM %I.admin_sessions WHERE user_id=$1 AND tenant_id=$2', TG_TABLE_SCHEMA)
        USING OLD.user_id, OLD.tenant_id;
    RETURN OLD;
END;
$$;
CREATE OR REPLACE FUNCTION invalidate_factor_admin_sessions() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        EXECUTE pg_catalog.format('DELETE FROM %I.admin_sessions WHERE user_id=$1 AND tenant_id=$2', TG_TABLE_SCHEMA)
            USING OLD.user_id, OLD.tenant_id;
        RETURN OLD;
    END IF;
    IF NEW.enabled IS DISTINCT FROM OLD.enabled OR NEW.secret_reference IS DISTINCT FROM OLD.secret_reference
        OR NEW.user_id IS DISTINCT FROM OLD.user_id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
        EXECUTE pg_catalog.format('DELETE FROM %I.admin_sessions WHERE user_id=$1 AND tenant_id=$2', TG_TABLE_SCHEMA)
            USING OLD.user_id, OLD.tenant_id;
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION invalidate_user_admin_sessions() FROM PUBLIC;
REVOKE ALL ON FUNCTION invalidate_grant_admin_sessions() FROM PUBLIC;
REVOKE ALL ON FUNCTION invalidate_factor_admin_sessions() FROM PUBLIC;
COMMIT;
