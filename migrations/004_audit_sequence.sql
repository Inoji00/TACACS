BEGIN;
ALTER TABLE audit_events ADD COLUMN chain_sequence BIGINT GENERATED ALWAYS AS IDENTITY;
ALTER TABLE audit_events ADD COLUMN canonical_data TEXT;
CREATE UNIQUE INDEX audit_chain_order ON audit_events(tenant_id,chain_sequence);
COMMIT;
