# Install TNAC+ on Ubuntu

**English** · [Tiếng Việt](INSTALL.vi.md)

The installer requires an amd64 Linux VM with Python 3.12 or later and venv, Docker Engine, Buildx, the Compose plugin, unzip, and iproute2. Assign an IPv4 address to the VM and allow Internet access for base images and Python dependencies. The `192.0.2.0/24` range in this guide is reserved for examples.

Check the prerequisites on the VM.

```bash
dpkg --print-architecture
python3 --version
docker --version
docker buildx version
docker compose version
ip -br -4 addr
```

If Docker Engine or its plugins are missing, follow the [Docker Engine installation guide for Ubuntu](https://docs.docker.com/engine/install/ubuntu/). Install `python3-venv`, `git`, `unzip`, and `iproute2` from the Ubuntu package repositories as needed.

## Download and install

```bash
git clone https://github.com/Inoji00/TNAC-.git 'TNAC+'
cd 'TNAC+'
sudo bash install.sh
```

If you have the installer ZIP and its checksum, use:

```bash
sha256sum -c TNAC-online-install.zip.sha256 && unzip TNAC-online-install.zip
cd 'TNAC+'
sudo bash install.sh
```

The installer checks the IP address, ports, Docker, and container names before downloading dependencies or building images. It selects the VM's IPv4 address when exactly one address matches the CIDR you enter. If several addresses match, enter the exact address with a `/32` prefix. Devices use TCP/49 and Web Admin uses HTTPS/8443. Docker shows the HTTPS port on `tnac-db` because the proxy shares its network namespace. PostgreSQL TCP/5432 stays internal.

The installer builds `tnac:current` and `tnac-postgres:16.16-r2` locally. The app image uses Python 3.12 on Debian Trixie and checks that `zlib1g` meets the minimum patched version. The PostgreSQL image stays on major version 16 and runs the database as UID 70 through `su-exec`.

```bash
sudo bash tnac status
sudo bash tnac credentials
```

Run `credentials` in a private terminal. Use the public CA file at `data/vm-appliance/localhost-ca.pem` to verify the certificate presented by the HTTPS URL printed by the installer before signing in. Change the initial password after signing in and register devices under **Network Resources → Devices**. Use each device's source IP and a unique shared secret.

This installer initializes a fresh deployment. For an existing deployment, run `sudo bash tnac status` to check its state. See [Operations](OPERATIONS.md) for service CLI and installation of a trusted CA certificate for your management domain.
