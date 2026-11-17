BEGIN;
CREATE TABLE network_device_groups (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    kind TEXT NOT NULL CHECK (kind IN ('location','device_type')),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    description TEXT NOT NULL DEFAULT '' CHECK (length(description)<=256),
    parent_id UUID,
    UNIQUE (tenant_id,kind,id),
    UNIQUE NULLS NOT DISTINCT (tenant_id,kind,parent_id,name),
    FOREIGN KEY (tenant_id,kind,parent_id) REFERENCES network_device_groups(tenant_id,kind,id),
    CHECK (parent_id IS DISTINCT FROM id)
);
ALTER TABLE network_devices ADD COLUMN description TEXT NOT NULL DEFAULT '' CHECK (length(description)<=256);
ALTER TABLE network_devices ADD COLUMN location_id UUID;
ALTER TABLE network_devices ADD COLUMN device_type_id UUID;
ALTER TABLE network_devices ADD COLUMN location_kind TEXT GENERATED ALWAYS AS ('location'::text) STORED;
ALTER TABLE network_devices ADD COLUMN device_type_kind TEXT GENERATED ALWAYS AS ('device_type'::text) STORED;
ALTER TABLE network_devices ADD FOREIGN KEY (tenant_id,location_kind,location_id) REFERENCES network_device_groups(tenant_id,kind,id);
ALTER TABLE network_devices ADD FOREIGN KEY (tenant_id,device_type_kind,device_type_id) REFERENCES network_device_groups(tenant_id,kind,id);
COMMIT;
