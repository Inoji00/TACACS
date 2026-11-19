#!/usr/bin/env sh
# Local on-prem bootstrap. Requires Linux, Docker Engine and Compose v2.
set -eu
initialize=false
case "${1:-}" in
  '') ;;
  --initialize) initialize=true ;;
  *) echo "Usage: scripts/install.sh [--initialize]" >&2; exit 1 ;;
esac
if [ "$#" -gt 1 ]; then echo "Unexpected arguments" >&2; exit 1; fi
if [ "$(uname -s)" != "Linux" ]; then echo "Linux is required" >&2; exit 1; fi
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo "Docker Engine with Compose v2 is required" >&2; exit 1
fi
umask 077
if [ ! -s config/service.toml ]; then
  echo "Missing config/service.toml. Provision database/schema/runtime role and operator configuration first." >&2
  exit 1
fi
if [ ! -d secrets ]; then
  echo "Missing secrets directory with protected runtime DSN/device files." >&2
  exit 1
fi
if [ ! -f secrets/postgres_password ] || [ -L secrets/postgres_password ] || [ ! -s secrets/postgres_password ]; then
  # A generated replacement could disagree with the prepared owner DSN or
  # an existing database volume. Never silently create/rotate this credential.
  echo "Missing protected secrets/postgres_password matching the database owner DSN." >&2
  exit 1
fi
if [ "$initialize" = true ]; then
  # Owner credentials are deliberately outside the runtime secrets mount.
  for input in owner_dsn aaa_password admin_password operator_password; do
    if [ ! -f "provisioning/$input" ] || [ -L "provisioning/$input" ] || [ ! -s "provisioning/$input" ]; then
      echo "Missing protected first-install input: provisioning/$input" >&2
      exit 1
    fi
  done
  docker compose -f docker-compose.yml -f docker-compose.initialize.yml config --quiet
  docker compose -f docker-compose.yml -f docker-compose.initialize.yml build initialize
  docker compose up -d --wait postgres
  docker compose -f docker-compose.yml -f docker-compose.initialize.yml run --rm --no-deps initialize
fi
docker compose config --quiet
docker compose up -d --build --wait app
echo "Stack launched; not yet verified ready. Check: docker compose ps and app health status."
