BEGIN;
CREATE TABLE policy_test_reports (
    version_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    tested_by UUID NOT NULL,
    rules_digest CHAR(64) NOT NULL,
    cases_digest CHAR(64) NOT NULL,
    total INTEGER NOT NULL CHECK(total BETWEEN 2 AND 1024),
    tested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY(version_id,tenant_id) REFERENCES policy_versions(id,tenant_id),
    FOREIGN KEY(tested_by,tenant_id) REFERENCES users(id,tenant_id)
);
COMMIT;
