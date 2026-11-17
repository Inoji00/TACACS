BEGIN;
-- Old reports have no replayable evidence and cannot be used for new approval.
ALTER TABLE policy_test_reports ADD COLUMN cases JSONB;
ALTER TABLE policy_test_reports ADD CONSTRAINT policy_cases_array
    CHECK (cases IS NULL OR (jsonb_typeof(cases) = 'array' AND jsonb_array_length(cases) = total));
CREATE FUNCTION protect_policy_test_report() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'policy test evidence is immutable';
END;
$$;
CREATE TRIGGER policy_test_report_immutable BEFORE UPDATE OR DELETE ON policy_test_reports
    FOR EACH ROW EXECUTE FUNCTION protect_policy_test_report();
CREATE FUNCTION require_policy_test_report() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.state IN ('test','approval','active') AND NEW.state IS DISTINCT FROM OLD.state THEN
        IF NOT EXISTS (SELECT 1 FROM policy_test_reports r WHERE r.version_id = NEW.id
            AND r.tenant_id = NEW.tenant_id AND r.cases IS NOT NULL AND r.tested_by = NEW.author_id) THEN
            RAISE EXCEPTION 'replayable policy test evidence required';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER policy_test_evidence_required BEFORE UPDATE ON policy_versions
    FOR EACH ROW EXECUTE FUNCTION require_policy_test_report();
COMMIT;
