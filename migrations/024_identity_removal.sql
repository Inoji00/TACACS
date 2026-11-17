BEGIN;
ALTER TABLE users ADD COLUMN deleted BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD CONSTRAINT removed_identity_disabled CHECK (NOT deleted OR NOT enabled);
COMMIT;
