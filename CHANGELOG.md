# Changelog

**English** · [Tiếng Việt](CHANGELOG.vi.md)

## Unreleased

- Export retained Device Syslog into daily text files by source IPv4 and UTC+07 receive date. Use a short collector name and preserve the full Compose status table. Fresh installs use the `tnac-syslog` volume; upgrades retain existing logs.

## v1.1.2 — 2026-11-19

- Add Device Syslog for operational messages over UDP/514, including devices without a TACACS+ registration. Administrators can filter by source IP, receive time, severity and message.
- Keep logs in a separate volume for 30 days. Prune expired rows in batches and limit each page to 100 entries.
- Add offline English and Vietnamese Cisco connection guidance with copyable example CLI on the Devices page.
- Package operational files and documentation in the installer ZIP. The full Git checkout retains tests and workflows.

## v1.1.1 — 2026-11-19

- Run TNAC on Python 3.12 with Alpine 3.23.
- Remove the superseded Go `gosu` binary from published PostgreSQL layers and retain `su-exec` with UID 70.
- Add reproducible PostgreSQL regression, Compose smoke, dump/restore, Trivy, and release privacy checks to CI.
- Preserve the 37 migrations. A default clone tracks `main`; the versioned ZIP pins the release.

## v1.1.0 — 2026-11-18

- Add Slack Incoming Webhook configuration, queued test messages, delivery status and selectable notification groups in Web Admin.
- Forward successful device authentication, failed authentication and other recorded AAA outcomes, recorded commands, and audited Web actions.
- Add the three-second host activity worker. Account lock/unlock notifications use the same fast worker and take priority over routine activity. Normal delivery targets about 3–5 seconds, subject to network availability, backlog and Slack limits.
- Keep Docker health, endpoint checks, resource thresholds and aggregate authentication-burst monitoring on the one-minute snapshot schedule.
- Persist a bounded notification queue and committed audit cursor. Retry failed delivery, honor webhook-wide cooldowns and preserve unread activity when the queue is full.
- Correlate new accounting audit entries with their exact accounting record ID in the same transaction. Apply command redaction before sending notifications.
- Lock device accounts at the fourth consecutive wrong password. Counters persist across SSH connections. The Web authentication provider retains its existing threshold and shares the account lock state.
- Declare launcher-created configuration and secret volumes external. Add backup-and-validate helpers for upgrading existing Compose configuration.
- Make Inventory tiles navigable, preserve the complete Users list and its Status column, and align Dashboard update timestamps.
- Separate fast activity processing from health observations, preventing false recovery/unlock messages from uncollected data.
- Minify the packaged UI without identifier renaming. Keep temporary patch archives, local deployment state, credentials and test-site data outside the installation package.

### Validation scope

Local automated validation covers repository/API authorization, CSRF, command redaction, queue recovery, cursor backpressure, cooldowns, fast worker scheduling and English/Vietnamese UI rendering. The release validation summary is recorded in SECURITY.md.

Operator-provided acceptance confirmed Slack test delivery, device authentication PASS/FAIL, EXEC authorization allow, accounting start and account-lock notifications. The operator accepted the final fast activity and lock updates. These observations do not certify every device/firmware or every command-accounting configuration. No fresh CVE scan of the v1.1.0 images was performed during publication.

## v1.0

Initial online installation package, bilingual installation/operations/security documentation, account unlock, delegated AAA log scopes, and management API rate-limit adjustments.
