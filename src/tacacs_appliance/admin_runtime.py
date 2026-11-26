"""Explicit local administration runtime with a separate least-privilege DSN."""

import argparse
import logging
from pathlib import Path
import signal
import sys
import threading
import tomllib
from uuid import UUID
from psycopg_pool import ConnectionPool
from .runtime import read_secret
from .admin_composition import build_admin_api
from .admin_tls import create_admin_tls_context
from .admin_server import AdminHttpsServer, ProxiedAdminHttpsServer
from .admin_console import AdminConsole
from .admin_api import lan_admin_origin


def load_config(path):
    with path.open("rb") as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError("configuration too large")
    data = tomllib.loads(raw.decode("utf-8"))
    required = {
        "tenant_id",
        "database_dsn_file",
        "origin",
        "csrf_key_file",
        "cert_file",
        "key_file",
        "mfa_references",
    }
    if not required <= set(data) or set(data) - required - {
        "port",
        "client_ca_file",
        "local_password_only",
        "device_registry_key_file",
        "lan_ip",
        "lan_domain",
        "shared_tenant_console",
    }:
        raise ValueError("invalid administration schema")
    data["tenant_id"] = str(UUID(data["tenant_id"]))
    port = data.get("port", 8443)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid port")
    data["port"] = port
    mode = data.get("local_password_only", False)
    lan_origin = lan_admin_origin(data.get("lan_ip"), data.get("lan_domain"))
    if lan_origin is not None and (data["origin"] != lan_origin or port != 8443):
        raise ValueError("LAN administration origin mismatch")
    if type(mode) is not bool or (
        mode
        and (
            data["origin"] not in ("https://localhost:8443", lan_origin) or port != 8443
        )
    ):
        raise ValueError("invalid local authentication mode")
    data["local_password_only"] = mode

    def local(value):
        if not isinstance(value, str) or not value:
            raise ValueError("path required")
        candidate = Path(value)
        return candidate if candidate.is_absolute() else path.parent / candidate

    for name in ("database_dsn_file", "csrf_key_file", "cert_file", "key_file"):
        data[name] = local(data[name])
    if "client_ca_file" in data:
        data["client_ca_file"] = local(data["client_ca_file"])
    if "device_registry_key_file" in data:
        data["device_registry_key_file"] = local(data["device_registry_key_file"])
    references = data["mfa_references"]
    if not isinstance(references, dict):
        raise ValueError("MFA mapping required")
    data["mfa_references"] = {name: local(value) for name, value in references.items()}
    return data


def main():
    parser = argparse.ArgumentParser(description="HTTPS administration service")
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args()
    logging.basicConfig(format="%(message)s", level=logging.INFO)
    logging.getLogger("psycopg.pool").disabled = True
    log = logging.getLogger(__name__)
    pool = None
    listeners = []
    threads = []
    stop = threading.Event()
    failed = threading.Event()
    previous = {}
    result = 1
    try:
        config = load_config(args.config)
        context = create_admin_tls_context(
            config["cert_file"],
            config["key_file"],
            client_ca=config.get("client_ca_file"),
        )
        pool = ConnectionPool(
            read_secret(config["database_dsn_file"]).decode("utf-8").strip(),
            min_size=1,
            max_size=8,
            max_idle=120,
            timeout=5,
            open=False,
            kwargs={
                "connect_timeout": 5,
                "options": "-c statement_timeout=5000 -c lock_timeout=3000",
            },
        )
        pool.open(wait=True, timeout=10)
        app = build_admin_api(
            pool,
            tenant_id=config["tenant_id"],
            origin=config["origin"],
            csrf_key_file=config["csrf_key_file"],
            mfa_references=config["mfa_references"],
            password_only=config["local_password_only"],
            lan_ip=config.get("lan_ip"),
            lan_domain=config.get("lan_domain"),
            **(
                {"device_registry_key_file": config["device_registry_key_file"]}
                if "device_registry_key_file" in config
                else {}
            ),
        )
        # The TLS proxy controls external access; this listener stays inside the shared namespace.
        console = AdminConsole(app)
        server = AdminHttpsServer(("127.0.0.1", config["port"]), console, context)
        listeners.append(server)
        if sys.platform == "linux" and config["port"] == 8443:
            listeners.append(ProxiedAdminHttpsServer(console, context, server))

        def serve(listener):
            try:
                listener.serve_forever()
                if not stop.is_set():
                    failed.set()
                    log.error('{"event":"ADMIN_LISTENER_STOPPED"}')
            except Exception:
                failed.set()
                log.error('{"event":"ADMIN_LISTENER_FAILED"}')
            finally:
                stop.set()

        for number in (signal.SIGINT, signal.SIGTERM):
            previous[number] = signal.signal(number, lambda *_: stop.set())
        for listener in listeners:
            thread = threading.Thread(
                target=serve, args=(listener,), name="tacacs-admin"
            )
            thread.start()
            threads.append(thread)
        log.info('{"event":"ADMIN_READY"}')
        stop.wait()
        result = 1 if failed.is_set() else 0
    except Exception:
        log.error('{"event":"ADMIN_SERVICE_FAILED"}')
    finally:

        def cleanup(action):
            nonlocal result
            try:
                action()
            except Exception:
                result = 1
                log.error('{"event":"ADMIN_CLEANUP_FAILED"}')

        for listener, thread in zip(listeners, threads):
            if thread.is_alive():
                cleanup(listener.shutdown)
        for listener in listeners:
            cleanup(listener.server_close)
        for thread in threads:
            cleanup(thread.join)
        if pool is not None:
            cleanup(pool.close)
        for number, handler in previous.items():
            cleanup(lambda n=number, h=handler: signal.signal(n, h))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
