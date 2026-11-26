"""Read-only Linux installation checks. Never initializes or repairs a deployment."""

import argparse
import json
import socket
import subprocess
import sys
from pathlib import Path
from container_names import names
from local_appliance import IMAGE, POSTGRES_IMAGE
from vm_appliance import (
    SubnetSelectionError,
    select_vm_ip,
    validate_addresses,
    validate_admin_ip,
)

ROOT = Path(__file__).resolve().parents[1]


def run(command):
    return subprocess.run(
        command, check=True, capture_output=True, text=True, timeout=15
    ).stdout


def check(
    server,
    client=None,
    root=ROOT,
    runner=run,
    binder=socket.socket,
    *,
    admin_ip=None,
    check_images=True,
):
    server, client = validate_addresses(server, client)
    admin_ip = validate_admin_ip(admin_ip or server)
    results = []

    def record(name, action):
        try:
            if action() is False:
                raise ValueError("requirement unmet")
            results.append({"check": name, "status": "PASS"})
        except Exception as error:
            # Do not expose command output, network configuration or credentials.
            results.append(
                {"check": name, "status": "FAIL", "reason": type(error).__name__}
            )

    record(
        "native-linux-python312",
        lambda: sys.platform == "linux" and sys.version_info >= (3, 12),
    )
    record(
        "docker-engine",
        lambda: bool(
            runner(["docker", "version", "--format", "{{.Server.Version}}"]).strip()
        ),
    )
    record(
        "compose-plugin",
        lambda: int(
            runner(["docker", "compose", "version", "--short"])
            .strip()
            .lstrip("v")
            .split(".")[0]
        )
        >= 2,
    )
    if check_images:
        for image in (IMAGE, POSTGRES_IMAGE):
            record(
                "image:" + image,
                lambda image=image: bool(
                    runner(
                        ["docker", "image", "inspect", "--format", "{{.Id}}", image]
                    ).strip()
                ),
            )

    def names_available():
        existing = runner(["docker", "ps", "-a", "--format", "{{.Names}}"]).splitlines()
        return set(existing).isdisjoint(names("", primary=True).values())

    record("container-names-available", names_available)
    record("fresh-install-state", lambda: not (root / "data" / "vm-appliance").exists())

    def bind_ports():
        for address, port in ((server, 49), (admin_ip, 8443)):
            with binder(socket.AF_INET, socket.SOCK_STREAM) as endpoint:
                endpoint.bind((address, port))
        with binder(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
            endpoint.bind((server, 514))
        return True

    record("assigned-ip-and-free-ports", bind_ports)
    if client is not None:
        record(
            "switch-route",
            lambda: bool(
                runner(["ip", "-4", "route", "get", client, "from", server]).strip()
            ),
        )
    ready_key = "ready_for_init" if check_images else "host_ready"
    return {
        "checks": results,
        ready_key: all(item["status"] == "PASS" for item in results),
        "not_verified": [
            "firewall-source-restriction",
            "switch-reachability",
            "source-ip-preservation",
            "vendor-AAA-interoperability",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    server = parser.add_mutually_exclusive_group(required=True)
    server.add_argument("--server-ip")
    server.add_argument(
        "--subnet",
        nargs="?",
        const="",
        metavar="CIDR",
        help="Select the VM IPv4 address from this subnet, or prompt for CIDR",
    )
    parser.add_argument("--client-ip", help="Optional bootstrap TACACS+ device IPv4")
    parser.add_argument("--admin-ip")
    parser.add_argument(
        "--host-only",
        action="store_true",
        help="Check the host before building or loading Docker images",
    )
    args = parser.parse_args()
    try:
        server_ip = args.server_ip if args.subnet is None else select_vm_ip(args.subnet)
        admin_ip = args.admin_ip or server_ip
        report = check(
            server_ip,
            args.client_ip,
            admin_ip=admin_ip,
            check_images=not args.host_only,
        )
    except SubnetSelectionError as error:
        parser.error(str(error))
    except ValueError:
        parser.error(
            "valid IPv4 LAN addresses required; server and device must be distinct"
        )
    if args.subnet is not None:
        report["bindings"] = {"tacacs_ip": server_ip, "admin_ip": admin_ip}
    print(json.dumps(report, indent=2))
    return 0 if report["host_ready" if args.host_only else "ready_for_init"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
