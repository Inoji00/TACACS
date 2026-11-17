ALTER TABLE device_console_scopes
    DROP CONSTRAINT device_console_scopes_actions_check,
    ADD CONSTRAINT device_console_scopes_actions_check CHECK (
        actions <@ ARRAY['create','edit','set_enabled','delete','reveal_secret',
                         'rotate_secret','edit_mappings','view_aaa_logs']::TEXT[]
    );

ALTER TABLE network_devices
    ADD COLUMN aaa_log_scope_since TIMESTAMPTZ NOT NULL DEFAULT now();

CREATE FUNCTION reset_aaa_log_scope_since() RETURNS trigger LANGUAGE plpgsql
SET search_path TO pg_catalog AS $$
BEGIN
    IF (OLD.location_id, OLD.device_type_id, OLD.deleted)
        IS DISTINCT FROM (NEW.location_id, NEW.device_type_id, NEW.deleted) THEN
        NEW.aaa_log_scope_since := clock_timestamp();
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER reset_aaa_log_scope_since
    BEFORE UPDATE OF location_id, device_type_id, deleted ON network_devices
    FOR EACH ROW EXECUTE FUNCTION reset_aaa_log_scope_since();
