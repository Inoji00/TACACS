#!/usr/bin/env bash
set -euo pipefail

image=${1:?Supply a locally built TNAC image}
fixture="tnac-syslog-test-$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
docker volume create "$fixture" >/dev/null
cleanup() {
  docker rm -f "$fixture" >/dev/null 2>&1 || true
  docker volume rm "$fixture" >/dev/null
}
trap cleanup EXIT
docker run --rm --network none --user 0:0 \
  --mount "type=volume,source=$fixture,target=/var/lib/tnac-syslog" \
  --entrypoint sh "$image" -ec 'chown 10001:10001 /var/lib/tnac-syslog; chmod 0700 /var/lib/tnac-syslog'
docker run -d --name "$fixture" --network none --read-only --cap-drop=ALL \
  --mount "type=volume,source=$fixture,target=/var/lib/tnac-syslog" \
  --entrypoint python "$image" -m tacacs_appliance.device_syslog >/dev/null
for attempt in {1..30}; do
  if docker exec "$fixture" python -c 'from tacacs_appliance.device_syslog import ready; ready()' 2>/dev/null; then
    break
  fi
  sleep 1
done
docker exec "$fixture" python -c '
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
    client.sendto(b"<189>%LINK-5-UPDOWN: example operational event", ("127.0.0.1", 1514))
'
docker run --rm --network none --read-only --cap-drop=ALL \
  --mount "type=volume,source=$fixture,target=/var/lib/tnac-syslog,readonly" \
  --entrypoint python "$image" -c '
import time
from tacacs_appliance.device_syslog import search
for _ in range(30):
    events = search("source=127.0.0.1&severity=5&q=operational")["items"]
    if events:
        assert events[0]["message"].endswith("example operational event")
        print("PASS: UDP collector and read-only Syslog volume query")
        break
    time.sleep(0.25)
else:
    raise SystemExit("Syslog event did not arrive")
'
