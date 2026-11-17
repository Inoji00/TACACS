BEGIN;
-- A NULL override means the actor belongs to the policy tenant.
ALTER TABLE policy_versions
    ADD COLUMN author_home_override UUID,
    ADD COLUMN approver_home_override UUID,
    ADD COLUMN author_home UUID GENERATED ALWAYS AS (COALESCE(author_home_override, tenant_id)) STORED,
    ADD COLUMN approver_home UUID GENERATED ALWAYS AS (COALESCE(approver_home_override, tenant_id)) STORED,
    DROP CONSTRAINT policy_author_tenant,
    DROP CONSTRAINT policy_approver_tenant,
    ADD CONSTRAINT policy_author_home_fk FOREIGN KEY (author_id, author_home) REFERENCES users(id, tenant_id),
    ADD CONSTRAINT policy_approver_home_fk FOREIGN KEY (approver_id, approver_home) REFERENCES users(id, tenant_id),
    ADD CONSTRAINT policy_approver_override_requires_actor CHECK (approver_id IS NOT NULL OR approver_home_override IS NULL);

ALTER TABLE policy_test_reports
    ADD COLUMN tester_home_override UUID,
    ADD COLUMN tester_home UUID GENERATED ALWAYS AS (COALESCE(tester_home_override, tenant_id)) STORED,
    DROP CONSTRAINT policy_test_reports_tested_by_tenant_id_fkey,
    ADD CONSTRAINT policy_tester_home_fk FOREIGN KEY (tested_by, tester_home) REFERENCES users(id, tenant_id);

ALTER TABLE policy_retirements
    ADD COLUMN retiree_home_override UUID,
    ADD COLUMN retiree_home UUID GENERATED ALWAYS AS (COALESCE(retiree_home_override, tenant_id)) STORED,
    ADD CONSTRAINT policy_retirement_actor_home_fk FOREIGN KEY (retired_by, retiree_home) REFERENCES users(id, tenant_id);

CREATE FUNCTION protect_policy_actor_tenants() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.author_home_override IS DISTINCT FROM OLD.author_home_override THEN
        RAISE EXCEPTION 'policy author tenant is immutable';
    END IF;
    IF NEW.approver_home_override IS DISTINCT FROM OLD.approver_home_override AND
        (OLD.approver_id IS NOT NULL OR NEW.approver_id IS NULL) THEN
        RAISE EXCEPTION 'policy approver tenant may only be set on approval';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER policy_actor_tenants_immutable BEFORE UPDATE ON policy_versions
    FOR EACH ROW EXECUTE FUNCTION protect_policy_actor_tenants();

CREATE OR REPLACE FUNCTION require_policy_test_report() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE has_evidence boolean;
BEGIN
    IF NEW.state IN ('test','approval','active') AND NEW.state IS DISTINCT FROM OLD.state THEN
        EXECUTE format('SELECT EXISTS (
            SELECT 1 FROM %I.policy_test_reports
            WHERE version_id = $1 AND tenant_id = $2 AND cases IS NOT NULL
              AND tested_by = $3 AND tester_home = $4
        )', TG_TABLE_SCHEMA)
        INTO has_evidence USING NEW.id, NEW.tenant_id, NEW.author_id,
            COALESCE(NEW.author_home_override, NEW.tenant_id);
        IF NOT has_evidence THEN
            RAISE EXCEPTION 'replayable policy test evidence required';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION protect_policy_retirement() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE policy_state text; approved uuid; author uuid; author_tenant uuid;
BEGIN
    IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'policy retirements are immutable'; END IF;
    EXECUTE format('SELECT state, approver_id, author_id, author_home
        FROM %I.policy_versions WHERE id = $1 AND tenant_id = $2 FOR UPDATE', TG_TABLE_SCHEMA)
        INTO policy_state, approved, author, author_tenant USING NEW.version_id, NEW.tenant_id;
    IF policy_state IS NULL OR policy_state NOT IN ('draft','test','approval') OR approved IS NOT NULL THEN
        RAISE EXCEPTION 'only unapproved inactive versions can be retired';
    END IF;
    IF NEW.retired_by IS DISTINCT FROM author OR
        COALESCE(NEW.retiree_home_override, NEW.tenant_id) IS DISTINCT FROM author_tenant THEN
        RAISE EXCEPTION 'policy author required';
    END IF;
    RETURN NEW;
END;
$$;
ALTER TABLE admin_grants DROP CONSTRAINT admin_grants_permission_check;
ALTER TABLE admin_grants ADD CONSTRAINT admin_grants_permission_check CHECK (permission IN (
    'console.read', 'users.manage', 'devices.manage', 'policy.draft',
    'policy.approve', 'policy.activate', 'audit.read', 'backup.manage',
    'global.audit.read', 'global.tenants.create', 'global.devices.manage', 'global.users.manage', 'global.policy.read',
    'global.policy.draft', 'global.policy.approve', 'global.policy.activate'));
COMMIT;
