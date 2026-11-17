# TNAC+ security

**English** · [Tiếng Việt](SECURITY.vi.md)

## Security controls

- Web Admin uses TLS 1.3, `Secure` and `HttpOnly` cookies with `SameSite=Strict`, Origin and CSRF checks, and login rate limiting. Each fresh installation generates its own initial credentials.
- Web Admin and TACACS+ use separate PostgreSQL roles. Installation generates secrets in Docker volumes. The application containers drop Linux capabilities and mount configuration and secret files read-only while serving traffic.
- PostgreSQL TCP/5432 stays internal. HTTPS/8443 and TACACS+/49 bind to the selected IPv4 address. Restrict these ports to management networks and device source IPs, respectively.
- TCP/49 uses legacy TACACS+. Its obfuscation lacks modern confidentiality and integrity protection. Run it on a protected management network. [RFC 8907 §10](https://www.rfc-editor.org/rfc/rfc8907.html#section-10)

## Patch status

| Component | Change in source | Candidate image test results |
| --- | --- | --- |
| Python and OS | Move the TNAC+ image to Python 3.12 on Debian Trixie. | Trivy reported 0 Critical and 47 High findings on the TNAC+ r2 candidate. |
| `zlib1g` | Upgrade to the Debian patched version or newer during build and enforce the minimum version. | Trivy no longer detected CVE-2026-85091 on the TNAC+ r2 candidate. [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-85091) |
| PostgreSQL and `gosu` | Upgrade to PostgreSQL 16.16 on Alpine 3.23, pin the base image digest, and drop to UID 70 through `su-exec` at startup. | Image-layer scanning still reported 1 Critical and 25 High findings at the old `gosu` path. A scan of the exported filesystem reported 0 Critical and 0 High after verifying that the symlink resolves to `su-exec`. [Go advisory](https://pkg.go.dev/vuln/GO-2026-4337) |

## Test coverage and open items

The candidate images passed PostgreSQL initialization, restart, and dump/restore checks, schema migrations, TCP/49 readiness, and direct HTTPS access to Web Admin. Login, logout, and rejection of the revoked session cookie were verified. AAA on physical switches and HTTPS through the proxy remain unverified for these candidates.

The scan counts above apply to the candidate images. A fresh online build can resolve newer Python base layers and dependencies. Scan the exact image IDs that you deploy and record remaining findings. CVE reports can include image names and environment details. Share a redacted report privately with the maintainer.
