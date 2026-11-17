BEGIN;
-- Run migrations with a search_path containing only trusted application schemas.
-- Runtime password/lockout updates need this narrowly scoped owner execution.
CREATE FUNCTION invalidate_user_admin_sessions() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path FROM CURRENT AS $$
BEGIN
    IF NEW.password_hash IS DISTINCT FROM OLD.password_hash
        OR NEW.enabled IS DISTINCT FROM OLD.enabled OR NEW.locked IS DISTINCT FROM OLD.locked THEN
        DELETE FROM admin_sessions WHERE user_id = OLD.id AND tenant_id = OLD.tenant_id;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER user_security_session_invalidation AFTER UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION invalidate_user_admin_sessions();
CREATE FUNCTION invalidate_grant_admin_sessions() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path FROM CURRENT AS $$
BEGIN
    DELETE FROM admin_sessions WHERE user_id = OLD.user_id AND tenant_id = OLD.tenant_id;
    RETURN OLD;
END;
$$;
CREATE TRIGGER grant_session_invalidation AFTER UPDATE OR DELETE ON admin_grants
    FOR EACH ROW EXECUTE FUNCTION invalidate_grant_admin_sessions();
CREATE FUNCTION invalidate_factor_admin_sessions() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM admin_sessions WHERE user_id = OLD.user_id AND tenant_id = OLD.tenant_id;
        RETURN OLD;
    END IF;
    IF NEW.enabled IS DISTINCT FROM OLD.enabled OR NEW.secret_reference IS DISTINCT FROM OLD.secret_reference
        OR NEW.user_id IS DISTINCT FROM OLD.user_id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
        DELETE FROM admin_sessions WHERE user_id = OLD.user_id AND tenant_id = OLD.tenant_id;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER factor_session_invalidation AFTER UPDATE OR DELETE ON mfa_factors
    FOR EACH ROW EXECUTE FUNCTION invalidate_factor_admin_sessions();
REVOKE ALL ON FUNCTION invalidate_user_admin_sessions() FROM PUBLIC;
REVOKE ALL ON FUNCTION invalidate_grant_admin_sessions() FROM PUBLIC;
REVOKE ALL ON FUNCTION invalidate_factor_admin_sessions() FROM PUBLIC;
COMMIT;
