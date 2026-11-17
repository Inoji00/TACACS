# TNAC+

**English** · [Tiếng Việt](README.vi.md)

TNAC+ is a TACACS+ server for network device administration. Its web console manages devices, identity groups, EXEC access mappings, command policies, and AAA logs. Available capabilities depend on the device's TACACS+ client, configuration, and firmware.

## Fresh installation on Ubuntu

Use an amd64 Ubuntu VM with Python 3.12 or later and venv, Docker Engine, Buildx, Compose v2, and a management IPv4 address. The VM needs Internet access to fetch base images and dependencies.

```bash
git clone https://github.com/Inoji00/TNAC-.git 'TNAC+'
cd 'TNAC+'
sudo bash install.sh
sudo bash tnac status
```

When prompted, enter the CIDR containing the VM's IPv4 address. Open the HTTPS URL shown by the installer. Run `sudo bash tnac credentials` in a private terminal to retrieve the initial credentials, then change the password after signing in.

- [Installation and HTTPS verification](INSTALL.md)
- [Operations CLI and troubleshooting](OPERATIONS.md)
- [Security controls, CVE patch status, and test coverage](SECURITY.md)
