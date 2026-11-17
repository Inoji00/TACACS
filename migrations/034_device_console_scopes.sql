CREATE TABLE device_console_scopes (
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    location_id UUID,
    device_type_id UUID,
    actions TEXT[] NOT NULL,
    location_kind TEXT GENERATED ALWAYS AS ('location'::text) STORED,
    device_type_kind TEXT GENERATED ALWAYS AS ('device_type'::text) STORED,
    PRIMARY KEY (tenant_id,user_id),
    FOREIGN KEY (user_id,tenant_id) REFERENCES users(id,tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id,location_kind,location_id) REFERENCES network_device_groups(tenant_id,kind,id),
    FOREIGN KEY (tenant_id,device_type_kind,device_type_id) REFERENCES network_device_groups(tenant_id,kind,id),
    CHECK (actions <@ ARRAY['create','edit','set_enabled','delete','reveal_secret','rotate_secret','edit_mappings']::TEXT[])
);
