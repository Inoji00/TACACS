"""Explicit switch access; group names never imply a privilege or console role."""

import re
from .command import normalize, CommandError


def validate_mappings(value):
    if not isinstance(value, list) or len(value) > 64:
        raise ValueError("invalid access mappings")
    seen = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {"group", "privilege", "mode"}:
            raise ValueError("invalid access mapping")
        group, level, mode = item["group"], item["privilege"], item["mode"]
        if (
            not isinstance(group, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", group)
            or group in seen
        ):
            raise ValueError("invalid access group")
        if (
            type(level) is not int
            or not 0 <= level <= 15
            or mode not in ("policy", "read_only")
        ):
            raise ValueError("invalid access level")
        if mode == "read_only" and level != 1:
            raise ValueError("read-only shell requires privilege 1")
        seen.add(group)
    return value


def assignment(groups, mappings):
    try:
        validate_mappings(mappings)
    except (ValueError, TypeError):
        return None
    matches = {
        (row["privilege"], row["mode"]) for row in mappings if row["group"] in groups
    }
    # Never choose the highest privilege when memberships conflict.
    return next(iter(matches)) if len(matches) == 1 else None


def read_only_command(command):
    try:
        parsed = normalize(command)
    except (ValueError, TypeError, CommandError):
        return False
    # Conservative IOS cap; active command policy must still allow the command.
    return parsed.verb == "show" and not any(c in command for c in "<>")
