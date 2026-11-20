# TNAC+ operations

**English** · [Tiếng Việt](OPERATIONS.vi.md)

Run these commands from the directory containing `tnac` on the server where TNAC+ is installed.

| Command | Purpose |
| --- | --- |
| `sudo bash tnac status` | Show container status and published ports. |
| `sudo bash tnac start` | Start the existing stack. |
| `sudo bash tnac stop` | Stop the stack and retain the PostgreSQL volume. |
| `sudo bash tnac snapshot` | Refresh the service and endpoint status snapshot. |
| `sudo bash tnac credentials` | Show the initial credentials and TOTP setup data. Run it in a private terminal and keep the output confidential. |
| `sudo bash tnac rebind` | Apply a new IP address or domain and HTTPS certificate. Use a maintenance window because services may be recreated. |

## Troubleshoot services

```bash
sudo docker ps -a --filter name=tnac- \
  --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
sudo docker logs --tail 50 tnac-admin
sudo docker logs --tail 50 tnac-proxy
sudo docker logs --tail 50 tnac-app
sudo docker exec tnac-db pg_isready -h 127.0.0.1 -U tacacs_app -d tacacs
sudo docker stats --no-stream tnac-app tnac-admin tnac-proxy tnac-db
```

Read the logs for the service you are investigating and redact internal information before sharing them. For HTTPS issues, check `tnac-db`, `tnac-admin`, and `tnac-proxy` together because they share a network namespace. For TACACS+ issues, check TCP/49 and compare the device's source IP with its registered entry.

## Use a trusted CA certificate for Web Admin

Point DNS to the VM's management IPv4 address. Prepare a PEM file containing the leaf certificate and intermediates, a private key with mode `0600`, and a CA bundle to verify the certificate. Replace the example hostname and paths with values from your deployment.

```bash
sudo bash tnac rebind --admin-domain tnac.example.net \
  --cert-file /path/to/fullchain.pem \
  --key-file /path/to/privkey.pem \
  --ca-file /path/to/ca-bundle.pem
sudo bash tnac status
```

Once the services are ready, open `https://tnac.example.net:8443/`.

## Dashboard monitoring

Fresh installations enable periodic monitoring automatically. To enable it on an existing installation after updating the source:

```bash
sudo bash tnac enable-monitoring
systemctl list-timers --all tnac-snapshot.timer
sudo journalctl -u tnac-snapshot.service -n 20 --no-pager
```

The timer samples container status, VM resources, and the configured HTTPS endpoint about once a minute. If the dashboard still shows **Not currently verified**, check `sudo bash tnac status` and the service journal. If you remove this deployment, disable the timer with `sudo systemctl disable --now tnac-snapshot.timer`.

## Delegate AAA logs

In **Users → Edit Web access**, select **View AAA logs**. The user can read authentication, authorization and accounting for registered devices matching both their Location and Device Type. An unfiltered scope covers all registered devices in the tenant. Activity Log and Reports require separate administration access.

Delegated users can see events recorded within the current device assignment, starting at migration 037 for existing devices. A change to Location or Device Type, deletion, or re-registration starts a new log window. Grant changes invalidate the target user's current Web sessions.

## Reset the Web Admin password

On the Ubuntu VM, open a private terminal with sudo access while PostgreSQL is running.

```bash
cd "$HOME/TNAC+"
sudo bash tnac reset-admin
```

Type `RESET` to confirm and enter the new password twice. The command targets the administrator recorded at installation. It clears failed password attempts, unlocks an enabled account, invalidates its Web sessions and records `admin.password.reset` in Audit Logs. Sign in with the new password and your existing TOTP if MFA is enabled.

For a separate checkout containing the recovery command, pass `--deploy-dir "$HOME/TNAC+"` to target the running installation. The command reuses the existing initializer image and database connection, then removes its temporary container.

## Unlock a user account

In **Users**, select **Unlock** for the locked account and confirm the action. The action is recorded in the Activity Log. Sign in again after unlocking.

## Schema compatibility

v1.1.4 uses the same 37 migrations as the published v1.0 release. See UPGRADE.md for the existing-deployment procedure. Back up PostgreSQL and keep the previous service images before upgrading.


## Device login lockout

TACACS+ password authentication locks an account on its fourth consecutive wrong password. The counter belongs to the account and persists across SSH connections and devices in the tenant. A successful password authentication resets the counter. Account lockout also prevents Web sign-in for that identity. An authorized administrator can unlock it in Users. Confirm four rejected password attempts and the Locked status on the target switch during acceptance testing.


## Webhook alerts

Configure one Slack or Mattermost Incoming Webhook in Alerts. Before selecting Mattermost, set `TNAC_MATTERMOST_HOST` to the trusted DNS name in systemd drop-ins for both `tnac-alerts.service` and `tnac-snapshot.service`. Reload systemd and restart the alert worker. The Ubuntu worker verifies HTTPS certificates and sends Mattermost alerts only to the approved host. Enter the webhook URL in Web Admin and use the test alert to verify delivery.

Open System Administration → Alerts as an administrator with users.manage. Create a Slack app, enable Incoming Webhooks, authorize the channel, and enter the webhook in TNAC+. Save before selecting Send test alert. Tests are queued and normally sent within a few seconds when the fast activity service is enabled. Refresh to check delivery status.

The webhook is a secret in a dedicated external alerts volume. Files are mode 0600 and its directory is mode 0700, owned by Web Admin UID 10001. GET responses omit the secret. Keep it out of chat, screenshots, Git and shell command lines. The Ubuntu host needs DNS and outbound HTTPS to hooks.slack.com. No additional inbound port is required.

Defaults are two consecutive failed service/endpoint checks, CPU or RAM at least 90% or Docker filesystem usage at least 85% for 300 seconds, and 10 stored failed TACACS+ authentications in five minutes. Event groups can be enabled separately. Reminders default to 1800 seconds. A readiness check does not certify successful switch AAA.

Account alerts compare successive database snapshots, up to 512 locked accounts. The first successful snapshot establishes the baseline. Messages include usernames. A missing account is reported as no longer locked or removed. Brief transitions between samples can be missed. Authentication bursts count aggregate stored failures across this installation.

The host timer sends Slack messages independently of application container health. Web Admin and PostgreSQL must be available for account facts. Alerts shows stale monitor checks and unavailable account data. A powered-off VM, stopped timer, or loss of outbound network requires an external monitor.

Saving settings resets baselines and pending messages on the next cycle. A durable queue holds 100 grouped notifications, retries failures, respects Slack rate limits and sends recovery messages. A timeout after Slack accepts a message may cause a duplicate. Settings and the queue survive Web container recreation and live outside PostgreSQL. Include the private alerts volume in protected backups.

~~~bash
systemctl status tnac-snapshot.timer --no-pager
sudo journalctl -u tnac-snapshot.service -n 30 --no-pager
sudo bash tnac enable-monitoring
~~~

Re-enable monitoring after updating host monitoring source. Slack setup documentation is at https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/ .


### Forward recorded user activity

The Alerts page additionally offers Successful device authentication, Recorded device commands, Other recorded AAA activity, and Audited Web actions. These groups are opt-in. Save, wait for a new monitor check to establish the initial cursor, then generate test activity.

Authentication PASS is the device authentication result. EXEC and command authorization remain separate exchanges. Command text requires command accounting sent by the device. Accounting start and stop notifications are distinct records. The update adds an exact accounting record ID to newly appended audit metadata, in the same transaction. Existing history is preserved. Historical records without this reference are not matched by guessed session IDs or timestamps.

Only stored events are forwarded. This cannot observe terminal keystrokes, command output, all Web clicks, or switch-local activity absent from AAA. Web forwarding includes audited login/logout and management actions. Commands pass through the existing redaction function. Its heuristics cannot identify every possible vendor secret syntax.

Delivery is batched, normally up to eight queued events per monitoring cycle. A durable audit cursor advances only after events have entered the queue, so a full queue or Slack outage leaves remaining events in PostgreSQL for later reading. A busy system can accumulate backlog, shown in Alerts. Changing settings resets the baseline and pending alerts. Messages include the audit sequence for correlation.

Updating this feature restarts AAA and Web services to activate transactional accounting metadata. No database migration is required. Test using a disposable device account, a harmless command such as show clock on a compatible device, and a Web logout/login. Verify corresponding stored records before expecting Slack messages.


### Fast activity delivery

The tnac-alerts.service host worker polls recorded user activity every three seconds. Login results, commands and audited Web actions normally reach Slack within about 3–5 seconds when the network and queue are healthy. This is a target, not a delivery deadline. Slack throttling, backlog and network failures can extend it. Account lock/unlock transitions use the fast three-second worker. Health snapshots, resource thresholds and aggregate authentication-burst checks keep their one-minute cadence. Lock notifications take priority over queued routine activity.

The worker reuses the durable cursor and locked queue. Concurrent snapshot checks cannot clear active conditions through a missing fast-path observation. Inspect Last activity check in Alerts to verify the fast reader. Stop both tnac-alerts.service and tnac-snapshot.timer when removing a deployment.

~~~bash
systemctl status tnac-alerts.service --no-pager
sudo journalctl -u tnac-alerts.service -n 20 --no-pager
~~~

- [Device Syslog deployment and rollback](DEVICE-SYSLOG.md)
