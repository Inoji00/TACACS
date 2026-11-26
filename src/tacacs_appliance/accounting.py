"""Accounting domain record; persistence/audit consumers receive no secrets."""

from dataclasses import dataclass
import re


@dataclass(frozen=True, slots=True)
class AccountingRecord:
    tenant_id: str
    session_id: str
    username: str
    device_id: str
    action: str
    arguments: tuple[str, ...]


def redact_arguments(arguments: tuple[str, ...]) -> tuple[str, ...]:
    """Conservatively suppress the entire command when secret syntax is present.

    TACACS commands arrive split across cmd/cmd-arg attributes, so checking only
    each attribute for password= leaks e.g. `cmd-arg=secret`, `cmd-arg=value`.
    This heuristic is not a complete vendor grammar; uncertain configuration
    commands should be suppressed by vendor-specific adapters in future.
    """
    sensitive = re.compile(
        r"(?:^|[^a-z0-9])(?:password|passwd|secret|key|private-key|"
        r"community|token|credential|credentials|passphrase|"
        r"authentication-key|privacy-key)(?:$|[^a-z0-9])",
        re.I,
    )
    parsed = []
    for argument in arguments:
        # Both mandatory '=' and optional '*' TACACS attribute separators matter.
        separator = next((i for i, c in enumerate(argument) if c in "=*"), -1)
        name = argument[:separator].lower() if separator >= 0 else ""
        value = argument[separator + 1 :] if separator >= 0 else argument
        parsed.append((name, value))
    command_sensitive = any(
        name in ("cmd", "cmd-arg") and sensitive.search(value) for name, value in parsed
    )
    # Test AAA embeds a password positionally, without a password attribute.
    command_text = " ".join(
        value for name, value in parsed if name in ("cmd", "cmd-arg")
    )
    command_sensitive = command_sensitive or bool(
        re.search(
            r"\btest\s+aaa\b|\b(?:snmp-s[\w-]*|usern\w*)\b|\b(?:enab\w*)\b.*\b(?:sec\w*|pass\w*)\b|"
            r"\b(?:passw\w*|secr\w*|commu\w*|toke\w*|credential\w*)\b|"
            r"\b(?:https?|ftp|scp|sftp)://[^\s/]+@",
            command_text,
            re.I,
        )
    )
    return tuple(
        "<redacted>"
        if (
            sensitive.search(argument)
            or command_sensitive
            and name in ("cmd", "cmd-arg")
        )
        else argument
        for argument, (name, _) in zip(arguments, parsed)
    )


def accounting_details(arguments) -> dict:
    """Project only bounded, re-redacted command fields; never expose raw AV pairs.

    Historical rows are rechecked too. This is a conservative IOS-oriented secret
    heuristic, not a complete grammar for every vendor or arbitrary secret text.
    """
    empty = dict(
        kind="other", command=None, redacted=False, task_id=None, privilege=None
    )
    if not isinstance(arguments, (tuple, list)) or len(arguments) > 255:
        return dict(empty, redacted=True)
    if any(not isinstance(x, str) or len(x) > 4096 for x in arguments):
        return dict(empty, redacted=True)
    safe = redact_arguments(tuple(arguments))
    pairs = []
    for arg in safe:
        sep = next((i for i, c in enumerate(arg) if c in "=*"), -1)
        if sep >= 0:
            pairs.append((arg[:sep].lower(), arg[sep + 1 :]))

    def single(name):
        values = [value for key, value in pairs if key == name]
        return values[0] if len(values) == 1 else None

    def text(value, limit):
        return (
            value
            if value is not None
            and len(value) <= limit
            and not any(ord(c) < 32 or ord(c) == 127 for c in value)
            else None
        )

    command = single("cmd")
    args = [v for k, v in pairs if k == "cmd-arg"]
    hidden = "<redacted>" in safe or len([1 for k, v in pairs if k == "cmd"]) > 1
    if command is not None:
        rendered = " ".join([command, *args]).strip()
        if text(rendered, 2048) is None:
            hidden = True
        empty.update(
            kind="command" if command.strip() else "exec",
            command=None if hidden else (rendered or None),
        )
    elif hidden:
        empty["kind"] = "redacted"
    elif single("service") == "shell":
        empty["kind"] = "exec"
    if hidden:
        empty["command"] = None
    level = single("priv-lvl")
    empty.update(
        redacted=hidden,
        task_id=text(single("task_id"), 128),
        privilege=int(level)
        if level is not None
        and level.isascii()
        and level.isdigit()
        and len(level) <= 2
        and 0 <= int(level) <= 15
        else None,
    )
    return empty
