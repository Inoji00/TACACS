"""Command authorization composition for TACACS+ RFC 8907."""

from collections.abc import Callable

from .authorization import AuthorizationEngine, AuthorizationRequest, Decision
from .authorization_packet import (
    parse_authorization_request,
    encode_authorization_reply,
)
from .obfuscation import xor_body
from .protocol import AUTHORIZATION, Frame, Header, encode_frame
from .secrets import DeviceSecretProvider


def classify_request(arguments: tuple[str, ...]) -> str | None:
    """Require one shell service and command; preserve cmd-arg ordering.

    Unsupported mandatory attributes fail closed. Optional attributes cannot
    become server-side groups, roles, or device identities.
    """
    services, commands, parts, contexts = [], [], [], set()
    for argument in arguments:
        positions = [
            (argument.find(separator), separator)
            for separator in ("=", "*")
            if separator in argument
        ]
        if not positions:
            raise ValueError("invalid attribute")
        index, separator = min(positions)
        key, value = argument[:index], argument[index + 1 :]
        if not key:
            raise ValueError("invalid attribute")
        if key == "service":
            services.append(value)
        elif key == "cmd":
            commands.append(value)
        elif key == "cmd-arg":
            parts.append(value)
        elif key == "priv-lvl":
            if (
                key in contexts
                or not value.isascii()
                or not value.isdecimal()
                or not 0 <= int(value) <= 15
            ):
                raise ValueError("invalid privilege context")
            contexts.add(key)  # Context only: never grants the requested level.
        elif separator == "=":
            raise ValueError("unsupported mandatory attribute")
    if services != ["shell"] or len(commands) > 1:
        raise ValueError("unsupported command request")
    if not commands or commands == [""]:
        if parts:
            raise ValueError("shell request contains command arguments")
        return None
    return " ".join((commands[0], *parts))


def extract_command(arguments: tuple[str, ...]) -> str:
    command = classify_request(arguments)
    if command is None:
        raise ValueError("command required")
    return command


class TacacsAuthorizationHandler:
    def __init__(
        self,
        secrets: DeviceSecretProvider,
        engine: AuthorizationEngine | None = None,
        resolve_groups: Callable[[str], frozenset[str] | None] | None = None,
        *,
        service=None,
    ):
        if service is None and (engine is None or resolve_groups is None):
            raise ValueError("authorization dependencies required")
        self._secrets, self._engine, self._groups = secrets, engine, resolve_groups
        self._service = service

    def __call__(self, remote_ip: str, frame: Frame) -> bytes | None:
        return self.handle(remote_ip, frame)

    def handle(self, remote_ip, frame, observe=None):
        if frame.header.packet_type != AUTHORIZATION or frame.header.sequence != 1:
            return None
        secret = self._secrets.resolve(remote_ip)
        details = {}
        try:
            request = parse_authorization_request(xor_body(frame, secret))
            details["attempted_username"] = request.username
            details["remote_address"] = request.remote_address
            command = classify_request(request.arguments)
            details["authorization_kind"] = "exec" if command is None else "command"
            status = 0x10
            arguments = ()
            decision = None
            if command is None:
                if self._service is not None and hasattr(
                    self._service, "authorize_shell"
                ):
                    attributes = self._service.authorize_shell(
                        request.username, remote_ip
                    )
                    if attributes:
                        status = 2
                        arguments = (
                            attributes  # PASS_REPL replaces requested shell attributes.
                        )
                details["reason"] = (
                    "exec-granted" if status == 2 else "exec-not-granted"
                )
            elif self._service is not None:
                decision = self._service.authorize(request.username, remote_ip, command)
                if decision.decision is Decision.ALLOW:
                    status = 1
            else:
                groups = self._groups(request.username)
                if groups is not None:
                    decision = self._engine.evaluate(
                        AuthorizationRequest(
                            request.username, remote_ip, command, groups
                        )
                    )
                    if decision.decision is Decision.ALLOW:
                        status = 1
            if decision is not None:
                details.update(
                    reason={
                        "matched policy rule": "matched-rule",
                        "no policy rule matched": "no-matching-rule",
                        "invalid command": "invalid-command",
                        "identity unavailable": "identity-unavailable",
                        "switch access denied": "device-access-denied",
                        "command authorization unavailable for profile": "unsupported-profile",
                    }.get(decision.explanation),
                    policy_version=decision.policy_version,
                    matched_rule_id=decision.matched_rule_id,
                )
        except ValueError:
            status = 0x11
            details["reason"] = (
                "authorization-error"
                if "authorization_kind" in details
                else "invalid-request"
            )
        if observe is not None:
            observe(details)
        body = encode_authorization_reply(status, arguments if status in (1, 2) else ())
        response = Frame(
            Header(
                frame.header.version,
                AUTHORIZATION,
                2,
                0,
                frame.header.session_id,
                len(body),
            ),
            body,
        )
        return encode_frame(response.header, xor_body(response, secret))
