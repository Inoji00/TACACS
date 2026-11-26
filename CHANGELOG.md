# Changelog

**English** · [Tiếng Việt](CHANGELOG.vi.md)

## v1.2.1 — 2026-11-26

- Split Admin API request dispatch into dedicated handlers for login, devices, identities, policies, logs, Syslog and alerts.
- Centralize duplicate-key rejection for six JSON request handlers while retaining their body limits and the existing session, CSRF and authorization checks.
- Local verification: 33 Admin API tests passed, including duplicate keys and incomplete bodies. Ruff and frontend source tests passed.

## v1.1.9 — 2026-11-26

- Add the original React source and dependency lockfile. GitHub Actions type-checks, tests and builds it separately while the installer continues to use the currently shipped console.
- Apply Ruff lint and formatting checks to all Python files in src/ and scripts/.
- Lab verification on a disposable stack: React build and source tests, Compose TLS and mount isolation, PostgreSQL backup/restore and migration checks, and 534 regression tests passed with no skips.

## v1.1.8 — 2026-11-26

- Apply Web login rate limits to each verified HTTPS relay source IP. Direct connections use the socket peer.
- Skip PostgreSQL device admission lookups when an existing TCP/49 source has exhausted its rate limit. Unknown sources still require ACL approval before obtaining a bucket.
- Name the CI source archive TNAC-source-<tag>.zip to distinguish it from the installer and its checksum.

## v1.1.7 — 2026-11-26

- Move PostgreSQL-backed device admission into bounded listener workers and deny unauthorized sources before allocating rate-limit buckets.
- Require device-group membership for TACACS+ password authentication. Web-only users are excluded from device lockout updates. Dual-use users still share their counters.
- Wait up to 1.5 seconds for a password-work slot. Saturation returns TACACS+ ERROR or HTTP 503 without updating credential counters.
- Simplify Admin API body handling, name TACACS+ challenge fields and lint maintained modules with Ruff.
- Reject browser profile databases in the release privacy check and create versioned ZIPs from tracked Git content.
- VM lab evidence for the runtime patch: 531 Python and PostgreSQL integration tests passed, including TCP/49 with the restricted database role. Switch fallback remains site-dependent.

## v1.1.6 — 2026-11-26

- Reuse the Docker dependency layer when rebuilding after source or console changes.
- Skip incremental SQLite vacuum when the Device Syslog database has no free pages.
- Preserve the published console, service layout and all database migrations.

## v1.1.5 — 2026-11-20

- Add Mattermost as an alternative webhook destination to Slack. The Linux worker sends Mattermost alerts only to an administrator-approved DNS hostname.

- Simplify Device Syslog to four columns. Expand a log message in place to read the original text without a per-row scrollbar.
- Validate Mattermost destinations, reject redirects and neutralize mentions from log content.

## v1.1.4 — 2026-11-20

- Add inline icons by event type. Limit TACACS+ activity queued for Slack to five events per device IP and event type per rolling 60 seconds. Audit records remain available.
- Shorten the default Syslog update image tag to `tnac:syslog`.
- Update PostgreSQL regression fixtures for the stronger password policy.

- Format Slack notifications as concise English lines. Send login, logout, account lock and operational alerts separately. Group other TACACS+ activity for the same user and device within one poll.

- Recover the installation administrator from a private root terminal with `tnac reset-admin`. Password reset invalidates existing Web sessions and preserves MFA.

- Require new account passwords to have at least 12 characters, including an uppercase letter, a lowercase letter, a digit and an ASCII punctuation symbol. Existing passwords remain valid until changed.
- Apply the policy to device-user creation and password resets, Web password changes, and administrator bootstrap. Show the requirements in both console languages.
- Align Syslog filters in a responsive grid while retaining single-line log rows.
- Document runtime boundaries, deployment impact and the frontend source and bundle alignment gap. See the [architecture review](ARCHITECTURE-REVIEW.md).

## v1.1.3 — 2026-11-20

- Enable Device Syslog automatically on fresh VM installations after checking UDP/514.
- Label Syslog sources by IPv4 as Switch, Router or Firewall, with separate admin-managed profiles and filters for retained events.
- Keep each Syslog record on one line, with horizontal scrolling for long messages.
- Add a bilingual CLI guide for inspecting and filtering daily files.

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
