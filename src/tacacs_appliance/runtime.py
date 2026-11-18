"""Explicit PostgreSQL-backed AAA composition; no automatic migrations."""
import ipaddress
import os
from pathlib import Path
import stat
import tomllib
from uuid import UUID
from dataclasses import dataclass
from psycopg_pool import ConnectionPool
from .accounting_handler import TacacsAccountingHandler
from .authentication_service import AuthenticationService
from .authorization_handler import TacacsAuthorizationHandler
from .postgres_accounting import PostgresAccountingStore
from .postgres_authorization import PostgresAuthorizationService
from .postgres_identity import PostgresLocalProvider
from .postgres_policy import load_active_policy
from .router import TacacsRouter
from .secrets import StaticDeviceSecretProvider
from .server import ListenerConfig, TacacsListener
from .tacacs_handler import TacacsAuthenticationHandler
from .database_security import validate_runtime_role
from .schema_manifest import validate_schema


def validate_secret_metadata(info, *, posix: bool, runtime_uid: int | None = None) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("secret must be a regular file")
    if posix:
        # Group read supports a dedicated runtime group. Group modification,
        # execute bits and all access by other users are forbidden.
        if info.st_mode & 0o137:
            raise ValueError("secret file access unsafe")
        if info.st_uid not in (0, runtime_uid):
            raise ValueError("secret owner must be root or runtime user")


def read_secret(path: Path) -> bytes:
    """Mounted secret file, not encryption at rest; Windows requires ACLs."""
    if path.is_symlink():
        raise ValueError("secret links unsupported")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        validate_secret_metadata(info, posix=os.name != "nt",
                                 runtime_uid=os.geteuid() if hasattr(os,"geteuid") else None)
        value = stream.read(4097)
    if not value or len(value) > 4096:
        raise ValueError("invalid secret size")
    return value


@dataclass(frozen=True)
class RuntimeConfig:
    tenant_id: str
    database_dsn_file: Path
    devices: tuple[tuple[str, Path], ...]
    listener: ListenerConfig
    shell_grants: tuple = ()
    device_registry_key_file: Path | None = None

    @classmethod
    def load(cls, path: Path):
        with path.open("rb") as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError("configuration too large")
        data = tomllib.loads(raw.decode("utf-8"))
        required={"tenant_id", "database_dsn_file", "listener", "devices"}
        if not required<=set(data) or set(data)-required-{'shell_grants','device_registry_key_file','shared_listener'}:
            raise ValueError("invalid configuration schema")
        tenant = str(UUID(data["tenant_id"]))
        def secret_path(value):
            if not isinstance(value, str) or not value:
                raise ValueError("secret path required")
            result = Path(value)
            return result if result.is_absolute() else path.parent / result
        devices = []
        if (not isinstance(data["devices"], list) or len(data["devices"]) > 4096
                or (not data["devices"] and 'device_registry_key_file' not in data)):
            raise ValueError("device inventory required")
        for device in data["devices"]:
            if not isinstance(device, dict) or set(device) != {"address", "secret_file"}:
                raise ValueError("invalid device schema")
            devices.append((str(ipaddress.IPv4Address(device["address"])), secret_path(device["secret_file"])))
        if len({a for a, _ in devices}) != len(devices):
            raise ValueError("duplicate device identity")
        settings = data["listener"]
        if not isinstance(settings, dict) or set(settings) - {"host", "port"}:
            raise ValueError("invalid listener schema")
        host, port = settings.get("host", "0.0.0.0"), settings.get("port", 49)
        if not isinstance(host, str) or type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("invalid listener address")
        ipaddress.IPv4Address(host)
        listener = ListenerConfig(host=host, port=port, allowed_sources=tuple(a + "/32" for a, _ in devices))
        listener.validate()
        from .shell_profiles import decode_shell_grants
        grants=decode_shell_grants(data.get('shell_grants',[]),{address for address,_ in devices})
        key=secret_path(data['device_registry_key_file']) if 'device_registry_key_file' in data else None
        return cls(tenant, secret_path(data["database_dsn_file"]), tuple(devices), listener,grants,key)


def build_listener(config: RuntimeConfig, pool, *, metrics=None):
    secrets = StaticDeviceSecretProvider({a: read_secret(p) for a, p in config.devices}) if config.devices else None
    registry=None
    if config.device_registry_key_file is not None:
        from .device_registry import DeviceRegistry
        registry=DeviceRegistry(pool,config.tenant_id,read_secret(config.device_registry_key_file),secrets,observe_runtime=True)
        secrets=registry
    elif secrets is None:
        raise ValueError("device inventory required")
    load_active_policy(pool, config.tenant_id)  # Validate initial persisted policy before binding.
    router = TacacsRouter(
        TacacsAuthenticationHandler(secrets, AuthenticationService(PostgresLocalProvider(pool, config.tenant_id, lockout_after=4))),
        TacacsAuthorizationHandler(secrets, service=PostgresAuthorizationService(pool, config.tenant_id,config.shell_grants)),
        TacacsAccountingHandler(secrets, PostgresAccountingStore(pool, config.tenant_id), config.tenant_id))
    from .aaa_events import AaaEvents, ObservedRouter
    router = ObservedRouter(router, secrets, AaaEvents(pool, config.tenant_id))
    return TacacsListener(config.listener, router, handler_factory=router.new_connection, metrics=metrics,
                          **({'source_state':registry.source_state} if registry else {}))


def open_pool(config: RuntimeConfig):
    dsn = read_secret(config.database_dsn_file).decode("utf-8").strip()
    pool = ConnectionPool(dsn, min_size=1, max_size=16, timeout=5, open=False,
                          kwargs={"connect_timeout": 5, "options": "-c statement_timeout=5000 -c lock_timeout=3000"})
    try:
        pool.open(wait=True, timeout=10)
        with pool.connection() as connection:
            validate_runtime_role(connection)
            validate_schema(connection)
            if connection.execute("SELECT id FROM tenants WHERE id=%s", (UUID(config.tenant_id),)).fetchone() is None:
                raise ValueError("configured tenant missing")
        return pool
    except BaseException:
        pool.close()
        raise
