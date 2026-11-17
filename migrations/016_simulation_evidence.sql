BEGIN;
CREATE TABLE policy_simulation_reports (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    simulated_by UUID NOT NULL,
    candidate_id UUID NOT NULL,
    baseline_id UUID,
    baseline_rules_digest CHAR(64) NOT NULL CHECK(baseline_rules_digest ~ '^[0-9a-f]{64}$'),
    candidate_rules_digest CHAR(64) NOT NULL CHECK(candidate_rules_digest ~ '^[0-9a-f]{64}$'),
    samples_digest CHAR(64) NOT NULL CHECK(samples_digest ~ '^[0-9a-f]{64}$'),
    sample_count INTEGER NOT NULL CHECK(sample_count BETWEEN 1 AND 1024),
    report JSONB NOT NULL CHECK(jsonb_typeof(report)='object' AND octet_length(report::text)<=2097152),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY(simulated_by,tenant_id) REFERENCES users(id,tenant_id),
    FOREIGN KEY(candidate_id,tenant_id) REFERENCES policy_versions(id,tenant_id),
    FOREIGN KEY(baseline_id,tenant_id) REFERENCES policy_versions(id,tenant_id),
    CHECK(COALESCE(report->>'coverage'='provided-samples-only',FALSE)),
    CHECK(COALESCE(jsonb_typeof(report->'total')='number' AND (report->>'total')::integer=sample_count,FALSE))
);
CREATE INDEX policy_simulation_tenant_candidate ON policy_simulation_reports(tenant_id,candidate_id,created_at DESC);
CREATE FUNCTION protect_policy_simulation_report() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'policy simulation evidence is immutable';
END;
$$;
CREATE TRIGGER simulation_report_no_mutation BEFORE UPDATE OR DELETE ON policy_simulation_reports
    FOR EACH ROW EXECUTE FUNCTION protect_policy_simulation_report();
CREATE TRIGGER simulation_report_no_truncate BEFORE TRUNCATE ON policy_simulation_reports
    FOR EACH STATEMENT EXECUTE FUNCTION protect_policy_simulation_report();
REVOKE ALL ON FUNCTION protect_policy_simulation_report() FROM PUBLIC;
COMMIT;
