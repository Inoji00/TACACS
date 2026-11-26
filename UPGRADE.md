# Upgrade to v1.1.6

**English** · [Tiếng Việt](UPGRADE.vi.md)

v1.1.6 preserves the 37 migrations. Back up PostgreSQL, verify restore in a separate container, and retain the active Compose configuration and exact running image IDs for rollback. If an old image is missing, retain a restorable full VM backup.

Build and scan both images from a separate v1.1.6 checkout using [the testing guide](TESTING.md). During maintenance, update the image references for app/admin/proxy and PostgreSQL in the existing Compose project. Recreate all four services because Web Admin and its proxy share PostgreSQL's network namespace. Keep the existing volumes. Verify service health, HTTPS sign-in, and device authentication, authorization and accounting.

- [Device Syslog deployment and rollback](DEVICE-SYSLOG.md)

If Slack monitoring is installed, update the host worker after upgrading the Web Admin image. Run this from the verified v1.1.6 checkout.

```bash
monitor=/usr/local/lib/tnac-monitoring
sudo test -f "$monitor/slack_monitor.py"
sudo cp -p "$monitor/slack_monitor.py" "$monitor/slack_monitor.py.v1.1.6-backup"
sudo install -m 0644 scripts/slack_monitor.py "$monitor/slack_monitor.py.new"
sudo cp -p "$monitor/alert_storage.py" "$monitor/alert_storage.py.v1.1.6-backup"
sudo install -m 0644 src/tacacs_appliance/alert_storage.py "$monitor/alert_storage.py.new"
sudo mv "$monitor/slack_monitor.py.new" "$monitor/slack_monitor.py"
sudo mv "$monitor/alert_storage.py.new" "$monitor/alert_storage.py"
sudo systemctl restart tnac-alerts.service
sudo systemctl is-active tnac-alerts.service
```
