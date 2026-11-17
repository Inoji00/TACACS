ALTER TABLE device_console_scopes
    ADD COLUMN creation_addresses TEXT[] NOT NULL DEFAULT '{}',
    ADD CONSTRAINT scoped_device_creation_requires_addresses CHECK (
        NOT ('create' = ANY(actions))
        OR (location_id IS NULL AND device_type_id IS NULL)
        OR cardinality(creation_addresses) BETWEEN 1 AND 64
    );
