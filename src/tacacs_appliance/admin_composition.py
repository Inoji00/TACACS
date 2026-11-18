"""Local WSGI administration composition; HTTPS serving is separate."""
from pathlib import Path
from uuid import UUID
from .admin_api import AdminApi
from .admin_login import AdminLoginService,PostgresAdminSubjectResolver
from .admin_rbac import PostgresAdminPermissions
from .admin_sessions import PostgresAdminSessions
from .postgres_identity import PostgresLocalProvider
from .postgres_mfa import PostgresTotpVerifier
from .postgres_audit import PostgresAuditWriter
from .postgres_policy_lifecycle import PostgresPolicyLifecycle
from .runtime import read_secret
from .schema_manifest import validate_schema
from .database_security import validate_admin_role
from .admin_audit import PostgresAdminAudit
from .postgres_simulation import PostgresPolicySimulation


class LocalReferenceResolver:
    """Only explicit operator mappings, never paths derived from DB references."""
    def __init__(self,references: dict[str,Path]):
        if not isinstance(references,dict) or not 1<=len(references)<=4096:
            raise ValueError("bounded secret reference mapping required")
        for reference,path in references.items():
            if (not isinstance(reference,str) or not reference.startswith("secret://")
                    or not 9<len(reference)<=1024 or not isinstance(path,Path)):
                raise ValueError("invalid local secret mapping")
        self._references=dict(references)

    def __call__(self,reference: str) -> bytes:
        path=self._references.get(reference)
        if path is None:raise ValueError("secret reference unavailable")
        return read_secret(path)


def build_admin_api(pool, *, tenant_id: str, origin: str, csrf_key_file: Path,
                    mfa_references: dict[str,Path],password_only=False,device_registry_key_file=None,lan_ip=None,lan_domain=None) -> AdminApi:
    from .admin_api import lan_admin_origin
    if type(password_only) is not bool or (password_only and origin not in ('https://localhost:8443',lan_admin_origin(lan_ip,lan_domain))):
        raise ValueError('configured administration origin required')
    tenant=str(UUID(tenant_id))
    resolver=LocalReferenceResolver(mfa_references)
    key=read_secret(csrf_key_file)
    with pool.connection() as connection:
        validate_admin_role(connection)
        validate_schema(connection)
        if connection.execute("SELECT id FROM tenants WHERE id=%s",(UUID(tenant),)).fetchone() is None:
            raise ValueError("administration tenant unavailable")
    sessions=PostgresAdminSessions(pool,tenant)
    if password_only:
        from .local_password_sessions import LocalPasswordSessions
        sessions=LocalPasswordSessions(pool,tenant)
    permissions=PostgresAdminPermissions(pool,tenant)
    login=AdminLoginService(PostgresLocalProvider(pool,tenant),PostgresAdminSubjectResolver(pool,tenant),
                            permissions,PostgresTotpVerifier(pool,tenant,resolver),sessions,password_only=password_only)
    audit=PostgresAuditWriter(pool,tenant)
    from .admin_password import AdminPasswordChange
    from .admin_inventory import AdminInventory
    from .admin_identities import AdminIdentities
    policies=PostgresPolicyLifecycle(pool,tenant,audit.policy_callback)
    from .admin_accounting import AdminAccounting
    from .deployment_status import DeploymentStatus
    from .admin_dashboard import AdminDashboard
    from .admin_logs import AdminLogs
    from .alert_storage import AlertStorage
    devices=None
    if device_registry_key_file is not None:
        from .device_registry import DeviceRegistry
        devices=DeviceRegistry(pool,tenant,read_secret(device_registry_key_file))
    return AdminApi(sessions,permissions,key,origin,login=login,policies=policies,audit=PostgresAdminAudit(pool,tenant),
                    simulation=PostgresPolicySimulation(pool,tenant,audit.append_in_transaction),password_only=password_only,
                    password_change=AdminPasswordChange(pool,tenant,audit.append_in_transaction),inventory=AdminInventory(pool,tenant),
                    identities=AdminIdentities(pool,tenant,audit.append_in_transaction),devices=devices,device_audit=audit.append_in_transaction,
                    accounting=AdminAccounting(pool,tenant),deployment=DeploymentStatus(),lan_ip=lan_ip,lan_domain=lan_domain,dashboard=AdminDashboard(pool,tenant),logs=AdminLogs(pool,tenant),
                    device_operator=permissions.device_operator,web_audit=audit.append,alerts=AlertStorage())
