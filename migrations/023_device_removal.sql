BEGIN;
ALTER TABLE network_devices ADD COLUMN deleted BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE network_devices ADD CONSTRAINT deleted_device_disabled CHECK (NOT deleted OR NOT enabled);
COMMIT;
