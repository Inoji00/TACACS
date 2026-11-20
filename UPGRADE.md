# Upgrade to v1.1.3

**English** · [Tiếng Việt](UPGRADE.vi.md)

v1.1.3 preserves the 37 migrations. Back up PostgreSQL, verify restore in a separate container, and retain the active Compose configuration and exact running image IDs for rollback. If an old image is missing, retain a restorable full VM backup.

Build and scan both images from a separate v1.1.3 checkout using [the testing guide](TESTING.md). During maintenance, update the image references for app/admin/proxy and PostgreSQL in the existing Compose project. Recreate all four services because Web Admin and its proxy share PostgreSQL's network namespace. Keep the existing volumes. Verify service health, HTTPS sign-in, and device authentication, authorization and accounting.

- [Device Syslog deployment and rollback](DEVICE-SYSLOG.md)
