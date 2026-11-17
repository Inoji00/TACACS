BEGIN;
CREATE TABLE policy_retirements (
    version_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    retired_by UUID NOT NULL REFERENCES users(id),
    retired_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (version_id,tenant_id) REFERENCES policy_versions(id,tenant_id)
);
CREATE FUNCTION protect_policy_retirement() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE policy_state text; approved uuid;
BEGIN
    IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'policy retirements are immutable'; END IF;
    EXECUTE format('SELECT state,approver_id FROM %I.policy_versions WHERE id=$1 AND tenant_id=$2 FOR UPDATE',TG_TABLE_SCHEMA)
        INTO policy_state,approved USING NEW.version_id,NEW.tenant_id;
    IF policy_state IS NULL OR policy_state NOT IN ('draft','test','approval') OR approved IS NOT NULL THEN
        RAISE EXCEPTION 'only unapproved inactive versions can be retired';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER policy_retirement_guard BEFORE INSERT OR UPDATE OR DELETE ON policy_retirements FOR EACH ROW EXECUTE FUNCTION protect_policy_retirement();
CREATE TRIGGER policy_retirement_no_truncate BEFORE TRUNCATE ON policy_retirements FOR EACH STATEMENT EXECUTE FUNCTION protect_policy_retirement();
CREATE FUNCTION block_retired_policy_updates() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE retired boolean;
BEGIN
    EXECUTE format('SELECT EXISTS(SELECT 1 FROM %I.policy_retirements WHERE version_id=$1 AND tenant_id=$2)',TG_TABLE_SCHEMA)
        INTO retired USING OLD.id,OLD.tenant_id;
    IF retired THEN RAISE EXCEPTION 'retired policy cannot change'; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER policy_retired_no_update BEFORE UPDATE ON policy_versions FOR EACH ROW EXECUTE FUNCTION block_retired_policy_updates();
COMMIT;
