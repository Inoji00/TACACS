BEGIN;
CREATE FUNCTION protect_audit_events() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit events are append-only';
END;
$$;
CREATE TRIGGER audit_events_no_mutation BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION protect_audit_events();
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION protect_audit_events();
-- NOT VALID preserves legacy rows but checks all subsequent inserts.
ALTER TABLE audit_events ADD CONSTRAINT audit_valid_hashes
    CHECK (previous_hash ~ '^[0-9a-f]{64}$' AND event_hash ~ '^[0-9a-f]{64}$') NOT VALID;
ALTER TABLE audit_events ADD CONSTRAINT audit_canonical_required
    CHECK (canonical_data IS NOT NULL) NOT VALID;
COMMIT;
