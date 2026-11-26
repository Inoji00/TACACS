"""Hierarchical inventory classifications, deliberately separate from authorization."""

import re
from uuid import UUID, uuid4
from .device_console_scope import load_scope


def description(value):
    if (
        not isinstance(value, str)
        or len(value) > 256
        or any((ord(c) < 32 and c not in "\n\r\t") or ord(c) == 127 for c in value)
    ):
        raise ValueError("invalid description")
    return value


def identifier(value):
    if not isinstance(value, str):
        raise ValueError("invalid identifier")
    return UUID(value)


def validate_tree(rows):
    graph = {str(row[0]): str(row[4]) if row[4] else None for row in rows}
    for node in graph:
        seen = set()
        while node is not None:
            if node in seen or node not in graph or len(seen) >= 8:
                raise ValueError("invalid hierarchy")
            seen.add(node)
            node = graph[node]


class DeviceGroups:
    def __init__(self, pool, tenant):
        self.pool, self.tenant = pool, UUID(str(tenant))

    def list(self, actor=None):
        with self.pool.connection() as connection:
            restricted = (
                actor is not None
                and load_scope(connection, self.tenant, actor) is not None
            )
            rows = connection.execute(
                "SELECT id,kind,name,description,parent_id FROM network_device_groups WHERE tenant_id=%s ORDER BY kind,name,id",
                (self.tenant,),
            ).fetchall()
        return {
            "read_only": restricted,
            "groups": [
                dict(
                    id=str(r[0]),
                    kind=r[1],
                    name=r[2],
                    description=r[3],
                    parent_id=str(r[4]) if r[4] else None,
                )
                for r in rows
            ],
        }

    def save(self, actor, payload, audit):
        if not isinstance(payload, dict):
            raise ValueError("invalid group")
        operation = payload.get("operation")
        if operation == "delete":
            if set(payload) != {"operation", "id"}:
                raise ValueError("invalid group")
            group_id = identifier(payload["id"])
        elif operation == "save":
            if set(payload) != {
                "operation",
                "id",
                "kind",
                "name",
                "description",
                "parent_id",
            }:
                raise ValueError("invalid group")
            group_id = (
                identifier(payload["id"]) if payload["id"] is not None else uuid4()
            )
            kind, name = payload["kind"], payload["name"]
            text = description(payload["description"])
            parent = (
                identifier(payload["parent_id"])
                if payload["parent_id"] is not None
                else None
            )
            if (
                kind not in ("location", "device_type")
                or not isinstance(name, str)
                or not re.fullmatch(r"[A-Za-z0-9_. -]{1,64}", name)
                or name != name.strip()
            ):
                raise ValueError("invalid group")
        else:
            raise ValueError("invalid operation")
        with self.pool.connection() as connection:
            with connection.transaction():
                connection.execute(
                    "SELECT id FROM tenants WHERE id=%s FOR UPDATE", (self.tenant,)
                )
                if load_scope(connection, self.tenant, actor) is not None:
                    raise PermissionError("permission denied")
                rows = connection.execute(
                    "SELECT id,kind,name,description,parent_id FROM network_device_groups WHERE tenant_id=%s",
                    (self.tenant,),
                ).fetchall()
                previous = next((r for r in rows if r[0] == group_id), None)
                if operation == "delete":
                    if previous is None:
                        raise ValueError("group unavailable")
                    if any(r[4] == group_id for r in rows):
                        raise ValueError("group has children")
                    if connection.execute(
                        "SELECT 1 FROM network_devices WHERE tenant_id=%s AND (location_id=%s OR device_type_id=%s) LIMIT 1",
                        (self.tenant, group_id, group_id),
                    ).fetchone():
                        raise ValueError("group is assigned")
                    if connection.execute(
                        "SELECT 1 FROM device_console_scopes WHERE tenant_id=%s AND (location_id=%s OR device_type_id=%s) LIMIT 1",
                        (self.tenant, group_id, group_id),
                    ).fetchone():
                        raise ValueError("group is assigned to Web access")
                    connection.execute(
                        "DELETE FROM network_device_groups WHERE tenant_id=%s AND id=%s",
                        (self.tenant, group_id),
                    )
                else:
                    if payload["id"] and previous is None:
                        raise ValueError("group unavailable")
                    if previous and previous[1] != kind:
                        raise ValueError("kind cannot change")
                    if not previous and len(rows) >= 512:
                        raise ValueError("group limit reached")
                    if parent and not any(
                        r[0] == parent and r[1] == kind for r in rows
                    ):
                        raise ValueError("parent unavailable")
                    if any(
                        r[0] != group_id
                        and r[1] == kind
                        and r[2] == name
                        and r[4] == parent
                        for r in rows
                    ):
                        raise ValueError("duplicate group")
                    validate_tree(
                        [r for r in rows if r[0] != group_id]
                        + [(group_id, kind, name, text, parent)]
                    )
                    connection.execute(
                        "INSERT INTO network_device_groups(id,tenant_id,kind,name,description,parent_id) VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name,description=EXCLUDED.description,parent_id=EXCLUDED.parent_id",
                        (group_id, self.tenant, kind, name, text, parent),
                    )
                details = {
                    "target_name": previous[2] if operation == "delete" else name
                }
                if previous and operation == "save":
                    details["changed_fields"] = [
                        field
                        for field, old, new in zip(
                            ("name", "description", "parent"),
                            previous[2:],
                            (name, text, parent),
                        )
                        if old != new
                    ]
                audit(
                    connection,
                    actor=actor,
                    source="admin-device-groups",
                    action="device-group."
                    + (
                        "delete"
                        if operation == "delete"
                        else "update"
                        if previous
                        else "create"
                    ),
                    target=str(group_id),
                    result="success",
                    security_context=details,
                )
        return {"status": "saved", "id": str(group_id)}
