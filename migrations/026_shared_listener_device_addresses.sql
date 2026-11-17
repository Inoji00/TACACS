BEGIN;
ALTER TABLE network_devices
    ADD CONSTRAINT network_devices_shared_listener_address_unique UNIQUE (address);
COMMIT;
