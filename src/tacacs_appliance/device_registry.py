"""Live device configuration with encrypted shared secrets and audited disclosure."""

import ipaddress
import os
import re
import hmac
import hashlib
from uuid import UUID
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .secrets import DeviceSecretProvider, SecretNotFoundError
from .device_console_scope import (
    load_scope,
    require_action,
    require_device_scope,
    source_ipv4,
)


class DeviceRegistry(DeviceSecretProvider):
    def __init__(self, pool, tenant, key, fallback=None, *, observe_runtime=False):
        if len(key) != 32:
            raise ValueError("registry key must be 32 bytes")
        self.pool, self.tenant, self.cipher, self.fallback = (
            pool,
            UUID(tenant),
            AESGCM(key),
            fallback,
        )
        self._fingerprint_key = key
        self.observe_runtime = observe_runtime

    def _aad(self, address):
        return f"{self.tenant}:{address}".encode("ascii")

    def source_state(self, address):
        with self.pool.connection() as connection:
            row = connection.execute(
                "SELECT enabled,revision FROM network_devices WHERE tenant_id=%s AND address=%s",
                (self.tenant, address),
            ).fetchone()
            if row is not None and self.observe_runtime:
                # Record the source-admission snapshot actually read by AAA.
                # A delayed request must never overwrite a newer observation.
                connection.execute(
                    "INSERT INTO device_runtime_observations(tenant_id,address,revision) VALUES (%s,%s,%s) "
                    "ON CONFLICT (tenant_id,address) DO UPDATE SET revision=EXCLUDED.revision,observed_at=now() "
                    "WHERE device_runtime_observations.revision<=EXCLUDED.revision",
                    (self.tenant, address, row[1]),
                )
        return row[0] if row is not None else None

    def resolve(self, address):
        with self.pool.connection() as connection:
            row = connection.execute(
                "SELECT enabled,secret_cipher FROM network_devices WHERE tenant_id=%s AND address=%s",
                (self.tenant, address),
            ).fetchone()
        if row is None and self.fallback is not None:
            return self.fallback.resolve(address)
        if row is None or not row[0]:
            raise SecretNotFoundError("device secret unavailable")
        try:
            value = bytes(row[1])
            return self.cipher.decrypt(value[:12], value[12:], self._aad(address))
        except Exception:
            raise SecretNotFoundError("device secret unavailable") from None

    def reveal_secret(self, actor, address, audit, *, password):
        address = str(ipaddress.IPv4Address(address))
        if not isinstance(password, str) or not 1 <= len(password) <= 1024:
            raise PermissionError("password verification required")
        with self.pool.connection() as connection, connection.transaction():
            connection.execute(
                "SELECT id FROM tenants WHERE id=%s FOR UPDATE", (self.tenant,)
            )
            scope = load_scope(connection, self.tenant, actor)
            require_action(scope, "reveal_secret")
            row = connection.execute(
                "SELECT secret_cipher,location_id,device_type_id FROM network_devices WHERE tenant_id=%s AND address=%s AND NOT deleted",
                (self.tenant, address),
            ).fetchone()
            if row is None:
                if scope is not None:
                    raise PermissionError("permission denied")
                raise ValueError("device secret unavailable")
            if scope is not None:
                require_device_scope(scope, row[1], row[2])
            from .admin_password import verify_current_password

            if (
                verify_current_password(connection, self.tenant, actor, password)
                is not True
            ):
                raise PermissionError("password verification unavailable")
            value = bytes(row[0])
            try:
                secret = self.cipher.decrypt(
                    value[:12], value[12:], self._aad(address)
                ).decode("ascii")
            except (InvalidTag, ValueError):
                raise ValueError("device secret unavailable") from None
            audit(
                connection,
                actor=actor,
                source="admin-devices",
                action="device.secret.reveal",
                target=address,
                result="success",
            )
        return {"secret": secret}

    def list_devices(
        self,
        *,
        search="",
        after=None,
        limit=200,
        status="all",
        actor=None,
        location_id="",
        device_type_id="",
    ):
        if (
            not isinstance(search, str)
            or len(search) > 64
            or any(ord(c) < 32 for c in search)
        ):
            raise ValueError("invalid search")
        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError("invalid page size")
        cursor = str(ipaddress.IPv4Address(after)) if after is not None else None
        clauses = ["tenant_id=%s", "NOT deleted"]
        values = [self.tenant]
        for field, group in (
            ("location_id", location_id),
            ("device_type_id", device_type_id),
        ):
            if group:
                clauses.append(field + "=%s")
                values.append(UUID(group))
        if status not in ("all", "enabled", "disabled"):
            raise ValueError("invalid device status")
        if status != "all":
            clauses.append("enabled=%s")
            values.append(status == "enabled")
        if search:
            escaped = search.replace("!", "!!").replace("%", "!%").replace("_", "!_")
            clauses.append(
                "(name ILIKE %s ESCAPE '!' OR host(address) ILIKE %s ESCAPE '!' OR description ILIKE %s ESCAPE '!')"
            )
            values.extend(["%" + escaped + "%"] * 3)
        if cursor:
            clauses.append("address>%s::inet")
            values.append(cursor)
        with self.pool.connection() as connection:
            scope = None
            if actor is not None:
                connection.execute(
                    "SELECT id FROM tenants WHERE id=%s FOR SHARE", (self.tenant,)
                )
                scope = load_scope(connection, self.tenant, actor)
                if scope is not None:
                    for field in ("location_id", "device_type_id"):
                        if scope[field] is not None:
                            clauses.append(field + "=%s")
                            values.append(scope[field])
            rows = connection.execute(
                "SELECT host(address),name,enabled,shell_group,privilege,updated_at,revision,"
                "(SELECT o.revision FROM device_runtime_observations o WHERE o.tenant_id=network_devices.tenant_id AND o.address=network_devices.address),"
                "(SELECT o.observed_at FROM device_runtime_observations o WHERE o.tenant_id=network_devices.tenant_id AND o.address=network_devices.address),description,location_id,device_type_id,access_mappings FROM network_devices WHERE "
                + " AND ".join(clauses)
                + " ORDER BY address LIMIT %s",
                tuple(values + [limit + 1]),
            ).fetchall()
        items = [
            dict(
                address=r[0],
                name=r[1],
                enabled=r[2],
                shell_group=r[3],
                privilege=r[4],
                saved_at=r[5].isoformat(),
                revision=r[6],
                runtime_revision=r[7],
                runtime_observed_at=r[8].isoformat() if r[8] else None,
                runtime_state="observed" if r[6] == r[7] else "pending",
                description=r[9],
                location_id=str(r[10]) if r[10] else None,
                device_type_id=str(r[11]) if r[11] else None,
                access_mappings=r[12],
            )
            for r in rows[:limit]
        ]
        return {
            "devices": items,
            "access": scope,
            "next_after": items[-1]["address"] if len(rows) > limit else None,
            "search": search,
            "status": status,
            "location_id": location_id,
            "device_type_id": device_type_id,
            "truncated": len(rows) > limit,
            "application": "runtime observation records source admission only; verify authentication, authorization and accounting separately",
            "transport": "TCP/49; host port publishing is operator-managed",
        }

    def save(self, actor, payload, audit):
        required = {"address", "name", "enabled", "secret", "shell_group", "privilege"}
        if (
            not isinstance(payload, dict)
            or not required <= set(payload)
            or set(payload)
            - required
            - {
                "description",
                "location_id",
                "device_type_id",
                "access_mappings",
                "operation",
            }
        ):
            raise ValueError("invalid device schema")
        operation = payload.get("operation")
        if operation not in (None, "create", "edit"):
            raise ValueError("invalid device operation")
        from .device_access import validate_mappings
        from psycopg.types.json import Jsonb
        from .device_groups import description, identifier

        if "description" in payload:
            description(payload["description"])
        for field in ("location_id", "device_type_id"):
            if field in payload and payload[field] is not None:
                identifier(payload[field])
        address = source_ipv4(payload["address"])
        name, group, level, enabled, secret = (
            payload[k]
            for k in ("name", "shell_group", "privilege", "enabled", "secret")
        )
        if not isinstance(name, str) or not re.fullmatch(
            r"[A-Za-z0-9_. -]{1,64}", name
        ):
            raise ValueError("invalid name")
        if not isinstance(group, str) or (
            group and not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", group)
        ):
            raise ValueError("invalid group")
        if type(level) is not int or not 0 <= level <= 15 or type(enabled) is not bool:
            raise ValueError("invalid state")
        mappings = validate_mappings(
            payload.get(
                "access_mappings",
                [dict(group=group, privilege=level, mode="policy")] if group else [],
            )
        )
        if not isinstance(secret, str) or (
            secret
            and (
                not 14 <= len(secret) <= 128
                or any(not 33 <= ord(c) <= 126 for c in secret)
            )
        ):
            raise ValueError(
                "secret requires 14-128 printable non-space ASCII characters"
            )
        with self.pool.connection() as connection:
            with connection.transaction():
                connection.execute(
                    "SELECT id FROM tenants WHERE id=%s FOR UPDATE", (self.tenant,)
                )
                scope = load_scope(connection, self.tenant, actor)
                previous = connection.execute(
                    "SELECT secret_cipher,secret_fingerprint,description,location_id,device_type_id,deleted,"
                    "name,enabled,shell_group,privilege,access_mappings FROM network_devices WHERE tenant_id=%s AND address=%s FOR UPDATE",
                    (self.tenant, address),
                ).fetchone()
                exists = previous is not None and not previous[5]
                if scope is not None and previous is not None:
                    require_device_scope(scope, previous[3], previous[4])
                if (operation == "create" and exists) or (
                    operation == "edit" and not exists
                ):
                    raise ValueError("device state has changed; refresh the list")
                text = payload.get("description", previous[2] if previous else "")
                location = payload.get("location_id", previous[3] if previous else None)
                device_type = payload.get(
                    "device_type_id", previous[4] if previous else None
                )
                if scope is not None:
                    require_device_scope(scope, location, device_type)
                    if exists:
                        if (name, text, str(location), str(device_type)) != (
                            previous[6],
                            previous[2],
                            str(previous[3]),
                            str(previous[4]),
                        ):
                            require_action(scope, "edit")
                        if enabled != previous[7]:
                            require_action(scope, "set_enabled")
                        if secret:
                            require_action(scope, "rotate_secret")
                        if (group, level, mappings) != tuple(previous[8:11]):
                            require_action(scope, "edit_mappings")
                        if not set(scope["actions"]).intersection(
                            ("edit", "set_enabled", "rotate_secret", "edit_mappings")
                        ):
                            raise PermissionError("permission denied")
                    else:
                        require_action(scope, "create")
                        if (
                            scope["location_id"] is not None
                            or scope["device_type_id"] is not None
                        ) and (address not in scope.get("creation_addresses", [])):
                            raise PermissionError("permission denied")
                        if enabled:
                            require_action(scope, "set_enabled")
                        if group or level != 1 or mappings:
                            require_action(scope, "edit_mappings")
                for group_id, kind in (
                    (location, "location"),
                    (device_type, "device_type"),
                ):
                    if (
                        group_id is not None
                        and connection.execute(
                            "SELECT 1 FROM network_device_groups WHERE tenant_id=%s AND kind=%s AND id=%s",
                            (self.tenant, kind, group_id),
                        ).fetchone()
                        is None
                    ):
                        raise ValueError("device group unavailable")
                if previous is None:
                    count = connection.execute(
                        "SELECT count(*) FROM network_devices WHERE tenant_id=%s",
                        (self.tenant,),
                    ).fetchone()[0]
                    if count >= 4096:
                        raise ValueError("device limit reached")
                if not secret and previous is None:
                    raise ValueError("new device requires secret")
                if previous and previous[5] and not secret:
                    raise ValueError("restoring device requires a new secret")
                if (
                    group
                    and connection.execute(
                        "SELECT 1 FROM identity_groups WHERE tenant_id=%s AND name=%s",
                        (self.tenant, group),
                    ).fetchone()
                    is None
                ):
                    raise ValueError("identity group does not exist")
                for mapping in mappings:
                    if (
                        connection.execute(
                            "SELECT 1 FROM identity_groups WHERE tenant_id=%s AND name=%s",
                            (self.tenant, mapping["group"]),
                        ).fetchone()
                        is None
                    ):
                        raise ValueError("identity group does not exist")
                if secret:
                    nonce = os.urandom(12)
                    encrypted = nonce + self.cipher.encrypt(
                        nonce, secret.encode("ascii"), self._aad(address)
                    )
                    fingerprint = hmac.new(
                        self._fingerprint_key,
                        b"device-secret-fingerprint\0" + secret.encode("ascii"),
                        hashlib.sha256,
                    ).digest()
                    if (
                        previous
                        and previous[5]
                        and hmac.compare_digest(fingerprint, bytes(previous[1]))
                    ):
                        raise ValueError("restoring device requires a different secret")
                else:
                    encrypted, fingerprint = bytes(previous[0]), bytes(previous[1])
                if connection.execute(
                    "SELECT 1 FROM network_devices WHERE tenant_id=%s AND address<>%s AND secret_fingerprint=%s",
                    (self.tenant, address, fingerprint),
                ).fetchone():
                    raise ValueError("unique per-device secret required")
                connection.execute(
                    "INSERT INTO network_devices(tenant_id,address,name,enabled,secret_cipher,secret_fingerprint,shell_group,privilege,description,location_id,device_type_id,access_mappings) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (tenant_id,address) DO UPDATE SET "
                    "name=EXCLUDED.name,enabled=EXCLUDED.enabled,secret_cipher=EXCLUDED.secret_cipher,secret_fingerprint=EXCLUDED.secret_fingerprint,shell_group=EXCLUDED.shell_group,"
                    "privilege=EXCLUDED.privilege,description=EXCLUDED.description,location_id=EXCLUDED.location_id,device_type_id=EXCLUDED.device_type_id,access_mappings=EXCLUDED.access_mappings,deleted=false,updated_at=now(),revision=network_devices.revision+1",
                    (
                        self.tenant,
                        address,
                        name,
                        enabled,
                        encrypted,
                        fingerprint,
                        group,
                        level,
                        text,
                        location,
                        device_type,
                        Jsonb(mappings),
                    ),
                )
                details = {"target_name": name}
                if exists:
                    fields = {
                        "name": (previous[6], name),
                        "description": (previous[2], text),
                        "enabled": (previous[7], enabled),
                        "location": (str(previous[3]), str(location)),
                        "device_type": (str(previous[4]), str(device_type)),
                        "access_mappings": (
                            tuple(previous[8:11]),
                            (group, level, mappings),
                        ),
                    }
                    details["changed_fields"] = [
                        key for key, (old, new) in fields.items() if old != new
                    ]
                    if secret and not hmac.compare_digest(
                        bytes(previous[1]), fingerprint
                    ):
                        details["changed_fields"].append("shared_secret")
                audit(
                    connection,
                    actor=actor,
                    source="admin-devices",
                    action="device.update" if previous else "device.create",
                    target=address,
                    result="success",
                    security_context=details,
                )
        return {"status": "saved", "address": address}

    def delete(self, actor, address, audit):
        address = str(ipaddress.IPv4Address(address))
        with self.pool.connection() as connection:
            with connection.transaction():
                connection.execute(
                    "SELECT id FROM tenants WHERE id=%s FOR UPDATE", (self.tenant,)
                )
                scope = load_scope(connection, self.tenant, actor)
                require_action(scope, "delete")
                row = connection.execute(
                    "SELECT enabled,deleted,location_id,device_type_id,name FROM network_devices WHERE tenant_id=%s AND address=%s FOR UPDATE",
                    (self.tenant, address),
                ).fetchone()
                if scope is not None:
                    if row is None:
                        raise PermissionError("permission denied")
                    require_device_scope(scope, row[2], row[3])
                if row is None or row[0] or row[1]:
                    raise ValueError("disable an existing device before removal")
                # Keep a negative registration so a legacy startup client cannot reappear.
                connection.execute(
                    "UPDATE network_devices SET deleted=true,enabled=false,location_id=NULL,device_type_id=NULL,shell_group='',privilege=1,access_mappings='[]'::jsonb,revision=revision+1,updated_at=now() WHERE tenant_id=%s AND address=%s",
                    (self.tenant, address),
                )
                audit(
                    connection,
                    actor=actor,
                    source="admin-devices",
                    action="device.delete",
                    target=address,
                    result="success",
                    security_context={"target_name": row[4]},
                )
        return {"status": "committed"}
