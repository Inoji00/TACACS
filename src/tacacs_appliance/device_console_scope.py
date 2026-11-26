"""Web administration access to the device registry."""

from ipaddress import IPv4Address
from uuid import UUID


ACTIONS = frozenset(
    (
        "create",
        "edit",
        "set_enabled",
        "delete",
        "reveal_secret",
        "rotate_secret",
        "edit_mappings",
        "view_aaa_logs",
    )
)
SCOPE_JSON = (
    "jsonb_build_object('location_id',s.location_id,'device_type_id',s.device_type_id,"
    "'actions',s.actions,'creation_addresses',s.creation_addresses)"
)


def source_ipv4(value):
    ip = IPv4Address(value)
    if (
        ip.is_loopback
        or ip.is_unspecified
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_link_local
    ):
        raise ValueError("unicast source IP required")
    return str(ip)


def parse_scope(payload):
    from .device_groups import identifier

    fields = {"location_id", "device_type_id", "actions"}
    if not isinstance(payload, dict) or not fields <= set(payload) <= fields | {
        "creation_addresses"
    }:
        raise ValueError("invalid device access")
    actions = payload["actions"]
    if not isinstance(actions, list) or any(
        not isinstance(action, str) or action not in ACTIONS for action in actions
    ):
        raise ValueError("invalid device actions")
    if len(actions) != len(set(actions)):
        raise ValueError("duplicate device actions")
    scoped_creation = "create" in actions and (
        payload["location_id"] is not None or payload["device_type_id"] is not None
    )
    addresses = payload.get("creation_addresses", [])
    if (
        not isinstance(addresses, list)
        or len(addresses) > 64
        or any(not isinstance(value, str) for value in addresses)
    ):
        raise ValueError("invalid approved source IPv4 addresses")
    addresses = sorted({source_ipv4(value) for value in addresses}, key=IPv4Address)
    if scoped_creation != bool(addresses):
        raise ValueError(
            "approved source IPv4 addresses required for scoped device creation"
        )
    return (
        identifier(payload["location_id"])
        if payload["location_id"] is not None
        else None,
        identifier(payload["device_type_id"])
        if payload["device_type_id"] is not None
        else None,
        sorted(actions),
        addresses,
    )


def load_scope(connection, tenant, actor):
    row = connection.execute(
        f"SELECT CASE WHEN s.user_id IS NOT NULL THEN {SCOPE_JSON} END "
        "FROM admin_grants g JOIN users u ON u.id=g.user_id AND u.tenant_id=g.tenant_id "
        "LEFT JOIN device_console_scopes s ON s.tenant_id=g.tenant_id AND s.user_id=g.user_id "
        "WHERE g.tenant_id=%s AND g.user_id=%s AND g.permission='devices.manage' "
        "AND u.enabled AND NOT u.locked AND NOT u.deleted",
        (tenant, UUID(actor)),
    ).fetchone()
    if row is None:
        raise PermissionError("permission denied")
    return row[0]


def require_device_scope(scope, location, device_type):
    for field, actual in (("location_id", location), ("device_type_id", device_type)):
        if scope[field] is not None and scope[field] != str(actual):
            raise PermissionError("permission denied")


def require_action(scope, action):
    if scope is not None and action not in scope["actions"]:
        raise PermissionError("permission denied")


def require_aaa_log_scope(connection, tenant, actor):
    scope = load_scope(connection, tenant, actor)
    if scope is None or "view_aaa_logs" not in scope["actions"]:
        raise PermissionError("permission denied")
    return scope


def aaa_log_device_clause(scope, address_column, timestamp_column):
    """Match visible registry devices, excluding events from an earlier scope."""
    filters = [
        "d.tenant_id = %s",
        "NOT d.deleted",
        f"host(d.address) = {address_column}",
        f"{timestamp_column} >= d.aaa_log_scope_since",
    ]
    values = []
    for name in ("location_id", "device_type_id"):
        if scope[name] is not None:
            filters.append(f"d.{name} = %s")
            values.append(scope[name])
    return "EXISTS (SELECT 1 FROM network_devices d WHERE " + " AND ".join(
        filters
    ) + ")", values
