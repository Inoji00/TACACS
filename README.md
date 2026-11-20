# TNAC+ v1.1.5

**English** · [Tiếng Việt](README.vi.md)

[MIT License](LICENSE) · [Responsible use and disclaimer](DISCLAIMER.md)

TNAC+ is a TACACS+ server for network device administration. Its web console manages devices, identity groups, EXEC access mappings, command policies, and AAA logs. Available capabilities depend on the device's TACACS+ client, configuration, and firmware.

TNAC+ integrates Slack activity and health alerts, fast account-lock notifications, fourth-failure device lockout, and the accepted Dashboard/Users layout. Recorded activity is polled every three seconds; normal Slack delivery targets about 3–5 seconds. Command notifications require device command accounting. See the [changes](CHANGELOG.md) and [upgrade procedure](UPGRADE.md).

> **[Security validation](SECURITY-VALIDATION.md)** · 66 focused security tests · 512 CI regression tests · 0 Critical / 0 High

> [!IMPORTANT]
> **Cisco switch integration verified.** TNAC+ has been tested on a Cisco Catalyst 2960X in the lab for TACACS+ sign-in, EXEC authorization, session and command accounting, and receipt of operational Syslog. Compatibility depends on the switch model, OS, firmware and configuration.
>
> **Need help integrating another vendor?** If you cannot get it working, email **[lehoangtuansang@gmail.com](mailto:lehoangtuansang@gmail.com)** with the vendor, model, OS/firmware, desired feature and a redacted error or log sample. These reports help resolve integration issues, broaden tested coverage and improve TNAC+ for everyone.

## Tests and security checks

[Workflow and artifacts](https://github.com/Inoji00/TACACS/actions/workflows/ci.yml) · [Reproduce tests and Trivy scans](TESTING.md). A default clone tracks `main`. Use the versioned ZIP for a fixed release.

## Fresh installation on Ubuntu

Download the [installer ZIP](https://github.com/Inoji00/TACACS/releases/download/v1.1.5/TNAC-v1.1.5.zip) and [SHA-256 checksum](https://github.com/Inoji00/TACACS/releases/download/v1.1.5/TNAC-v1.1.5.zip.sha256), or clone the default branch below.

Use an amd64 Ubuntu VM with Python 3.12 or later and venv, Docker Engine, Buildx, Compose v2, and a management IPv4 address. The VM needs Internet access to fetch base images and dependencies.

```bash
git clone https://github.com/Inoji00/TACACS.git 'TNAC+'
cd 'TNAC+'
sudo bash install.sh
sudo bash tnac status
```

When prompted, enter the CIDR containing the VM's IPv4 address. Open the HTTPS URL shown by the installer. Run `sudo bash tnac credentials` in a private terminal to retrieve the initial credentials, then change the password after signing in.

- [Installation and HTTPS verification](INSTALL.md)
- [Operations CLI and troubleshooting](OPERATIONS.md)
- [Security controls, CVE patch status, and test coverage](SECURITY.md)
- [Upgrade an existing v1.0 appliance](UPGRADE.md)
- [Release history](CHANGELOG.md)
- [Connect a Cisco switch to TNAC+ (English / Tiếng Việt)](CISCO-AAA.md)

- [Device Syslog deployment and rollback](DEVICE-SYSLOG.md)
