BEGIN;
-- Refuse existing cross-tenant data rather than silently reassign ownership.
ALTER TABLE policy_versions ADD CONSTRAINT policy_author_tenant
    FOREIGN KEY (author_id, tenant_id) REFERENCES users(id, tenant_id);
ALTER TABLE policy_versions ADD CONSTRAINT policy_approver_tenant
    FOREIGN KEY (approver_id, tenant_id) REFERENCES users(id, tenant_id);
ALTER TABLE policy_versions ADD CONSTRAINT policy_distinct_approver
    CHECK (approver_id IS NULL OR approver_id <> author_id);
ALTER TABLE policy_versions ADD CONSTRAINT policy_positive_revision
    CHECK (revision > 0);
ALTER TABLE users ADD CONSTRAINT user_nonnegative_failures
    CHECK (failed_logins >= 0);
COMMIT;
