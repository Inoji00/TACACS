BEGIN;
ALTER TABLE network_devices ADD COLUMN access_mappings JSONB NOT NULL DEFAULT '[]'::jsonb
    CHECK (jsonb_typeof(access_mappings)='array' AND jsonb_array_length(access_mappings)<=64);
UPDATE network_devices SET access_mappings=jsonb_build_array(jsonb_build_object('group',shell_group,'privilege',privilege,'mode','policy')) WHERE shell_group<>'';
COMMIT;
