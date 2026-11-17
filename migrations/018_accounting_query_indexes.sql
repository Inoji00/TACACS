BEGIN;
CREATE INDEX accounting_tenant_time ON accounting_records(tenant_id,occurred_at DESC,id DESC);
CREATE INDEX accounting_tenant_user_time ON accounting_records(tenant_id,username,occurred_at DESC,id DESC);
CREATE INDEX accounting_tenant_device_time ON accounting_records(tenant_id,device_id,occurred_at DESC,id DESC);
COMMIT;
