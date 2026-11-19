#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

if [[ $(uname -s) != Linux || $(uname -m) != x86_64 || $EUID != 0 ]]; then
    printf '%s\n' 'Run sudo bash install.sh on Linux x86_64.' >&2
    exit 1
fi
if [[ -e data/vm-appliance ]]; then
    printf '%s\n' 'Deployment state already exists. Use tnac status to inspect it.' >&2
    exit 1
fi
if [[ $# -gt 1 ]]; then
    printf '%s\n' 'Usage: sudo bash install.sh [IPv4 subnet CIDR]' >&2
    exit 1
fi

python3 -c 'import sys; sys.exit(sys.version_info < (3, 12))' || {
    printf '%s\n' 'Python 3.12 or newer with venv is required.' >&2
    exit 1
}
docker info --format '{{.OSType}}' | grep -qx linux
docker buildx version
ip -br -4 addr
subnet=${1:-}
if [[ -z $subnet ]]; then
    read -r -p 'VM subnet in CIDR (example 192.0.2.0/24): ' subnet
fi

export PYTHONPATH="$PWD/src"
python3 scripts/vm_preflight.py --host-only --subnet "$subnet"
python3 -m venv .venv
.venv/bin/python -m pip install 'cryptography>=46,<51'

docker build --pull -t tnac:current .
docker build -f Dockerfile.postgres -t tnac-postgres:16.16-r2 .
.venv/bin/python scripts/vm_preflight.py --subnet "$subnet"
.venv/bin/python scripts/vm_appliance.py init --subnet "$subnet"
syslog_ip=$(.venv/bin/python -c 'import json; from pathlib import Path; print(json.loads(Path("data/vm-appliance/vm-profile.json").read_text())["server_ip"])')
if ! bash scripts/enable_device_syslog.sh "$PWD" "$syslog_ip" tnac:current; then
    printf '%s\n' 'Device Syslog setup failed. Deployment state was retained. Check UDP/514 and retry:' >&2
    printf 'sudo bash scripts/enable_device_syslog.sh "$PWD" %q tnac:current\n' "$syslog_ip" >&2
    exit 1
fi
.venv/bin/python scripts/vm_appliance.py status
bash tnac enable-monitoring
printf '%s\n' 'Run sudo bash tnac credentials in a private terminal.'
