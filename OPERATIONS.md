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
