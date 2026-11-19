#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID != 0 || $# != 3 ]]; then
  echo 'Usage: sudo bash enable_device_syslog.sh DEPLOY_DIR LISTEN_IPV4 IMAGE' >&2
  exit 2
fi
deploy_dir=$(realpath -e -- "$1")
listen_ip=$2
image=$3
config="$deploy_dir/data/vm-appliance/compose.json"

test -f "$config" && test ! -L "$config"
test "$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project.config_files"}}' tnac-admin)" = "$config"
project=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' tnac-admin)
[[ $project =~ ^(tnac|tacacs-local)-[a-f0-9]{32}$ ]]
docker image inspect "$image" >/dev/null

compose=(docker compose --project-name "$project" -f "$config")
backup=$(mktemp "${config}.before-device-syslog.XXXXXXXX")
candidate=$(mktemp "${config}.candidate.XXXXXXXX")
trap 'rm -f -- "$candidate"' EXIT
cp -p -- "$config" "$backup"
printf 'Compose backup: %s\n' "$backup"
cp -p -- "$config" "$candidate"
volume=$(python3 - "$candidate" "$project" "$listen_ip" "$image" <<'PY'
import ipaddress
import json
import re
import sys
from pathlib import Path

path, project, address, image = sys.argv[1:]
ip = ipaddress.IPv4Address(address)
if ip.is_unspecified or ip.is_multicast or ip.is_loopback or ip.is_link_local:
    raise SystemExit('A dedicated management IPv4 address is required')
if not re.fullmatch(r"tnac:[a-zA-Z0-9_.-]+", image):
    raise SystemExit('Expected a local tnac image tag')
config = json.loads(Path(path).read_text())
services = config['services']
volumes = config.setdefault('volumes', {})
legacy_volume = project + '-device-syslog'
volume = 'tnac-syslog'
data_mount = 'device-syslog:/var/lib/tnac-syslog'
if 'device-syslog' in services or 'device-syslog' in volumes:
    existing = volumes.get('device-syslog', {})
    volume = existing.get('name')
    if (volume not in ('tnac-syslog', legacy_volume)
            or existing != {'external': True, 'name': volume}
            or services.get('device-syslog', {}).get('volumes') != [data_mount]):
        raise SystemExit('Existing Syslog configuration requires manual review')
volumes['device-syslog'] = {'external': True, 'name': volume}
services['device-syslog'] = {
    'container_name': 'tnac-syslog',
    'image': image, 'user': '10001:10001', 'restart': 'unless-stopped',
    'command': ['python', '-m', 'tacacs_appliance.device_syslog'],
    'ports': [f'{ip}:514:1514/udp'],
    'volumes': ['device-syslog:/var/lib/tnac-syslog'],
    'read_only': True, 'cap_drop': ['ALL'],
    'security_opt': ['no-new-privileges:true'],
    'healthcheck': {
        'test': ['CMD', 'python', '-c', 'from tacacs_appliance.device_syslog import ready; ready()'],
        'interval': '10s', 'timeout': '4s', 'retries': 5,
    },
}
if data_mount + ':ro' not in services['admin']['volumes']:
    services['admin']['volumes'].append(data_mount + ':ro')
for name in ('admin', 'proxy'):
    services[name]['image'] = image
Path(path).write_text(json.dumps(config, indent=2) + '\n')
print(volume)
PY
)

docker compose --project-name "$project" -f "$candidate" config --quiet
if docker container inspect tnac-syslog >/dev/null 2>&1; then
  owner=$(docker container inspect -f '{{index .Config.Labels "com.docker.compose.project"}}/{{index .Config.Labels "com.docker.compose.service"}}' tnac-syslog)
  if [[ $owner != "$project/device-syslog" ]]; then
    echo 'Container name tnac-syslog is already in use by another service.' >&2
    exit 1
  fi
fi
if [[ $volume == tnac-syslog ]]; then
  if ! docker volume inspect "$volume" >/dev/null 2>&1; then
    docker volume create --label "org.tnac.syslog.project=$project" "$volume" >/dev/null
  fi
  owner=$(docker volume inspect -f '{{index .Labels "org.tnac.syslog.project"}}' "$volume")
  if [[ $owner != "$project" ]]; then
    echo 'tnac-syslog belongs to another deployment or is unlabeled; refusing to share it.' >&2
    exit 1
  fi
else
  docker volume inspect "$volume" >/dev/null
fi
docker run --rm --network none --user 0:0 \
  --mount "type=volume,src=$volume,dst=/var/lib/tnac-syslog" \
  --entrypoint sh "$image" -ec 'chown 10001:10001 /var/lib/tnac-syslog; chmod 0700 /var/lib/tnac-syslog'
mv -f -- "$candidate" "$config"
"${compose[@]}" up -d --no-deps --no-build --pull never --wait --wait-timeout 90 device-syslog
"${compose[@]}" up -d --no-deps --no-build --pull never --force-recreate \
  --wait --wait-timeout 120 admin proxy
"${compose[@]}" ps
