"""Socket metadata for HTTPS audit, independent of browser HTTP headers."""
import ipaddress
import socket
import struct
from time import monotonic

PROXY_ADDRESS = "\0tnac-admin-https"
PROXY_UID = 10001
PROXY_IP_BYTES = 4  # The deployed Docker relay listens on IPv4.


def audit_ip(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 45 or '%' in value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def proxy_peer(connection):
    """Accept metadata only from the proxy's OS identity in this namespace."""
    credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    _, uid, _ = struct.unpack('3i', credentials)
    if uid != PROXY_UID:
        raise ValueError('untrusted HTTPS relay')
    timeout = connection.gettimeout()
    deadline = monotonic() + timeout
    payload = bytearray()
    try:
        while len(payload) < PROXY_IP_BYTES:
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise TimeoutError('incomplete HTTPS relay metadata')
            connection.settimeout(remaining)
            chunk = connection.recv(PROXY_IP_BYTES - len(payload))
            if not chunk:
                raise ValueError('incomplete HTTPS relay metadata')
            payload.extend(chunk)
    finally:
        connection.settimeout(timeout)
    return str(ipaddress.IPv4Address(bytes(payload)))
