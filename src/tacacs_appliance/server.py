"""Bounded TCP listener for RFC 8907 TACACS+ traffic.

The listener accepts frames only from an explicit management-network allow-list.
It deliberately does not make AAA decisions or decode secrets.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import ipaddress
import logging
import socket
import threading
import time
from typing import Callable

from .protocol import HEADER_LENGTH, Frame, Header, Limits, ProtocolError, parse_frame
from .rate_limit import SourceRateLimiter

FrameHandler = Callable[[str, Frame], bytes | None]


@dataclass(frozen=True, slots=True)
class ListenerConfig:
    host: str = "0.0.0.0"
    port: int = 49
    allowed_sources: tuple[str, ...] = ()
    limits: Limits = field(default_factory=Limits)
    connection_limit: int = 2_000
    worker_limit: int = 32
    request_limit_per_connection: int = 64
    read_timeout_seconds: float = 10.0
    source_rate_capacity: int = 30
    source_rate_refill_per_second: float = 1.0

    def validate(self) -> None:
        if not 0 <= self.port <= 65535:
            raise ValueError("port must be in 0..65535")
        if self.connection_limit <= 0 or self.worker_limit <= 0:
            raise ValueError("connection and worker limits must be positive")
        if self.request_limit_per_connection <= 0 or self.read_timeout_seconds <= 0:
            raise ValueError("request limit and timeout must be positive")
        for source in self.allowed_sources:
            ipaddress.ip_network(source, strict=False)


class TacacsListener:
    """A finite-worker listener that fails closed for unauthorised sources.

    Threat: a connection flood can otherwise create unlimited threads or body
    allocations. Invariant: each accepted connection consumes a bounded slot,
    each frame is header-validated before the body buffer is created, and each
    connection has deadlines plus a finite request count.
    """

    def __init__(self, config: ListenerConfig, handler: FrameHandler, *, handler_factory: Callable[[], FrameHandler] | None = None, metrics=None,source_state=None) -> None:
        config.validate()
        self._config = config
        self._handler = handler
        self._handler_factory = handler_factory
        self._metrics = metrics
        self._source_state=source_state
        self._networks = tuple(
            ipaddress.ip_network(source, strict=False) for source in config.allowed_sources
        )
        self._slots = threading.BoundedSemaphore(config.connection_limit)
        self._stop = threading.Event()
        self._clients: set[socket.socket] = set()
        self._clients_lock = threading.Lock()
        self._socket: socket.socket | None = None
        self._executor = ThreadPoolExecutor(
            max_workers=config.worker_limit, thread_name_prefix="tacacs-client"
        )
        self._log = logging.getLogger(__name__)
        self._source_limiter = SourceRateLimiter(config.source_rate_capacity, config.source_rate_refill_per_second)

    @property
    def address(self) -> tuple[str, int] | None:
        if self._socket is None:
            return None
        host, port = self._socket.getsockname()[:2]
        return str(host), int(port)

    def start(self) -> None:
        if self._stop.is_set():
            raise RuntimeError("stopped listeners cannot be restarted")
        if self._socket is not None:
            raise RuntimeError("listener already started")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self._config.host, self._config.port))
        listener.listen(self._config.connection_limit)
        listener.settimeout(0.25)
        self._socket = listener

    def serve_forever(self) -> None:
        listener = self._socket
        if listener is None:
            raise RuntimeError("listener must be started before serving")
        while not self._stop.is_set():
            try:
                client, remote = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                raise
            remote_ip = str(remote[0])
            if not self._source_limiter.allow(remote_ip) or not self._source_allowed(remote_ip) or not self._slots.acquire(blocking=False):
                client.close()
                continue
            with self._clients_lock:
                if self._stop.is_set():
                    client.close()
                    self._slots.release()
                    break
                self._clients.add(client)
                try:
                    self._executor.submit(self._handle_client, client, remote_ip)
                except RuntimeError:
                    self._clients.remove(client)
                    client.close()
                    self._slots.release()
                    if not self._stop.is_set():
                        raise

    def shutdown(self) -> None:
        self._stop.set()
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        with self._clients_lock:
            for client in self._clients:
                try:
                    client.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                client.close()
        # Queued workers must run their finally blocks to release their slots.
        self._executor.shutdown(wait=True)

    def _source_allowed(self, remote_ip: str) -> bool:
        if self._source_state is not None:
            try:
                state=self._source_state(remote_ip)
                if state is not None:return state is True
            except Exception:return False
        # Default deny is intentional: an empty ACL permits no TACACS+ device.
        address = ipaddress.ip_address(remote_ip)
        return any(address in network for network in self._networks)

    def _handle_client(self, client: socket.socket, remote_ip: str) -> None:
        try:
            # Stateful AAA handlers are created per connection. This prevents a
            # session ID reused on another TCP connection stealing a challenge.
            handler = self._handler_factory() if self._handler_factory else self._handler
            client.settimeout(self._config.read_timeout_seconds)
            for _ in range(self._config.request_limit_per_connection):
                if self._stop.is_set():
                    break
                deadline = time.monotonic() + self._config.read_timeout_seconds
                header_raw = _read_exact(client, HEADER_LENGTH, deadline=deadline)
                header = Header.parse(header_raw, self._config.limits)
                body = _read_exact(client, header.length, deadline=deadline)
                if self._metrics is not None:
                    self._metrics.increment("tacacs_requests_total")
                response = handler(remote_ip, Frame(header, body))
                if response is None:
                    break
                if response is not None:
                    # The handler owns protocol encoding. Do not reflect raw
                    # peer bytes or exception text into a TACACS+ response.
                    # Verify handler output before network emission. A handler
                    # may not bypass framing/size/flag invariants.
                    reply = parse_frame(response, self._config.limits)
                    if (reply.header.session_id != header.session_id
                            or reply.header.packet_type != header.packet_type
                            or reply.header.version != header.version
                            or header.sequence % 2 != 1
                            or reply.header.sequence != header.sequence + 1):
                        raise ProtocolError("invalid TACACS+ response correlation")
                    client.sendall(response)
        except (ConnectionError, OSError, ProtocolError, TimeoutError):
            # Never log raw frames, body data, usernames, or shared secrets.
            pass
        except Exception:
            # Handler faults must not bring down the listener. Details are local
            # structured logs in the future composition layer, not client output.
            self._log.error("TACACS+ frame handler failed")
        finally:
            client.close()
            with self._clients_lock:
                self._clients.discard(client)
            self._slots.release()


def _read_exact(client: socket.socket, size: int, *, deadline: float | None = None) -> bytes:
    """Read an already locally bounded size or raise on disconnect/timeout."""

    chunks = bytearray()
    while len(chunks) < size:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("frame read deadline exceeded")
            client.settimeout(remaining)
        chunk = client.recv(size - len(chunks))
        if not chunk:
            raise ConnectionError("peer closed TACACS+ connection")
        chunks.extend(chunk)
    return bytes(chunks)
