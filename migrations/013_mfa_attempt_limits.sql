BEGIN;
ALTER TABLE mfa_factors ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK(failed_attempts >= 0);
ALTER TABLE mfa_factors ADD COLUMN locked_until TIMESTAMPTZ;
COMMIT;
