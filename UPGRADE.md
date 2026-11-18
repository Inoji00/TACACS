# Upgrade to v1.1.0

**English** · [Tiếng Việt](UPGRADE.vi.md)

This procedure targets the default single-appliance v1.0 installation in ~/TNAC+ with containers tnac-app, tnac-admin, tnac-proxy and tnac-db. Schedule a maintenance window because AAA and Web containers are recreated. Keep an independent device administration session available while validating the result.

v1.0 already includes migration 037. v1.1.0 uses the same 37-migration manifest and requires no new database migration. Older or customized schemas need a separate upgrade assessment. Run the fresh installer only for a new deployment.

Download TNAC-v1.1.0.zip and TNAC-v1.1.0.zip.sha256 from the [release page](https://github.com/Inoji00/TACACS/releases/tag/v1.1.0), then transfer both to the Ubuntu user's home directory. Private repositories require authenticated access when downloading.

## Back up the existing installation

```bash
(
set -euo pipefail
umask 077
cd "$HOME/TNAC+"
backup=$(mktemp -d "$HOME/tnac-pre-v1.1.0.XXXXXX")
sudo docker exec tnac-db sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > "$backup/tnac.dump"
sudo tar -czf "$backup/deployment-state.tar.gz" data/vm-appliance
sudo chmod 600 "$backup/deployment-state.tar.gz"
sudo docker image tag "$(sudo docker inspect --format '{{.Image}}' tnac-app)" tnac:pre-v1.1.0-app
sudo docker image tag "$(sudo docker inspect --format '{{.Image}}' tnac-admin)" tnac:pre-v1.1.0-web
sha256sum "$backup/tnac.dump" > "$backup/tnac.dump.sha256"
printf 'Private backup directory: %s\n' "$backup"
)
```

Also retain protected backups of configuration/secret volumes, including the alerts volume if Slack is already configured. The archive below overlays installation source files; its contents exclude deployment state and generated secrets. Preserve custom source edits before applying it.

## Apply the release

```bash
(
set -euo pipefail
cd "$HOME"
sha256sum -c TNAC-v1.1.0.zip.sha256
unzip -o TNAC-v1.1.0.zip -d "$HOME"
cd "$HOME/TNAC+"
WEB_IMAGE=$(sudo python3 -c 'import json; print(json.load(open("data/vm-appliance/compose.json"))["services"]["admin"]["image"])')
AAA_IMAGE=$(sudo python3 -c 'import json; print(json.load(open("data/vm-appliance/compose.json"))["services"]["app"]["image"])')
sudo docker build -t "$WEB_IMAGE" .
if [ "$AAA_IMAGE" != "$WEB_IMAGE" ]; then
  sudo docker tag "$WEB_IMAGE" "$AAA_IMAGE"
fi
sudo .venv/bin/python scripts/repair_external_volumes.py
sudo .venv/bin/python scripts/prepare_slack_alerts.py
sudo env PYTHONPATH="$PWD/src" .venv/bin/python scripts/vm_appliance.py update-audit
sudo bash tnac enable-monitoring
sudo bash tnac status
sudo systemctl status tnac-alerts.service --no-pager
)
```

## Validate and retain rollback material

Refresh the browser assets and sign in again. Check Dashboard version 1.1.0 and service health. Verify existing devices, users, mappings and logs. With a disposable account, verify the intended authentication result and lock/unlock behavior. For Slack, check the selected event groups, send a test, then compare event timestamps with delivery. Device command notifications require command accounting configured on the device.

The worker retains an existing configuration and cursor. A settings save establishes a new monitoring baseline and clears pending messages on the next cycle. Avoid saving unchanged settings during acceptance testing.

Compose repair helpers keep dated backups beside compose.json. Retain these files and the pre-upgrade image tags until acceptance is complete. An image-only rollback can use the prior Compose configuration and saved image tags while retaining the database. Stop tnac-alerts.service when rolling back to an image without the activity collector. Restore a database backup only as an explicitly chosen recovery action, since it replaces subsequent data.
