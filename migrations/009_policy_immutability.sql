BEGIN;
ALTER TABLE policy_versions ADD CONSTRAINT policy_id_tenant_unique UNIQUE(id,tenant_id);
ALTER TABLE policy_versions ADD COLUMN rollback_source_id UUID;
ALTER TABLE policy_versions ADD CONSTRAINT policy_rollback_tenant
    FOREIGN KEY (rollback_source_id,tenant_id) REFERENCES policy_versions(id,tenant_id);
CREATE FUNCTION protect_policy_version() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'policy versions cannot be deleted';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.revision IS DISTINCT FROM OLD.revision OR NEW.author_id IS DISTINCT FROM OLD.author_id
        OR NEW.rules IS DISTINCT FROM OLD.rules OR NEW.created_at IS DISTINCT FROM OLD.created_at
        OR NEW.rollback_source_id IS DISTINCT FROM OLD.rollback_source_id THEN
        RAISE EXCEPTION 'policy version content is immutable';
    END IF;
    IF OLD.approver_id IS NOT NULL AND NEW.approver_id IS DISTINCT FROM OLD.approver_id THEN
        RAISE EXCEPTION 'policy approval is immutable';
    END IF;
    IF NEW.approver_id IS DISTINCT FROM OLD.approver_id AND
        NOT (OLD.state = 'approval' AND NEW.state = 'approval' AND OLD.approver_id IS NULL) THEN
        RAISE EXCEPTION 'approval requires approval state';
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
        (OLD.state = 'draft' AND NEW.state = 'test') OR
        (OLD.state = 'test' AND NEW.state = 'approval') OR
        (OLD.state = 'approval' AND NEW.state = 'active' AND OLD.approver_id IS NOT NULL) OR
        (OLD.state = 'active' AND NEW.state = 'archived')) THEN
        RAISE EXCEPTION 'invalid policy state transition';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER policy_version_immutable BEFORE UPDATE OR DELETE ON policy_versions
    FOR EACH ROW EXECUTE FUNCTION protect_policy_version();
COMMIT;
