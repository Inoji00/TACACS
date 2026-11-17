"""Canonical DNS identities and verified HTTPS probes for Web Admin."""
import http.client
import ipaddress
import re
import socket
import ssl
import sys


def admin_domain(value):
    if not isinstance(value, str) or len(value) > 253:
        raise ValueError('invalid administration DNS name')
    name = value.lower()
    labels = name.split('.')
    if len(labels) < 2 or not labels[-1][0:1].isalpha() or any(
        not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
        for label in labels
    ):
        raise ValueError('administration DNS name required')
    return name


def verify_dns_binding(name, address):
    expected = ipaddress.IPv4Address(address)
    resolved = {ipaddress.ip_address(result[4][0])
                for result in socket.getaddrinfo(name, 8443, type=socket.SOCK_STREAM)}
    if resolved != {expected}:
        raise ValueError('administration DNS must resolve only to the bound IPv4')


def trust_context(ca_file):
    context = ssl.create_default_context(cafile=str(ca_file))
    context.hostname_checks_common_name = False
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    return context


def verify_certificate(name, cert_file, key_file, ca_file):
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_3
    def reject_encrypted_key():
        raise ValueError('unencrypted PEM key required')
    server_context.load_cert_chain(cert_file, key_file, password=reject_encrypted_key)
    client_in, client_out, server_in, server_out = (ssl.MemoryBIO() for _ in range(4))
    client = trust_context(ca_file).wrap_bio(client_in, client_out, server_hostname=name)
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    pending = [(client, client_out, server_in), (server, server_out, client_in)]
    for _ in range(32):
        unfinished = []
        for endpoint, outgoing, peer_input in pending:
            try:
                endpoint.do_handshake()
            except ssl.SSLWantReadError:
                unfinished.append((endpoint, outgoing, peer_input))
            peer_input.write(outgoing.read())
        if not unfinished:
            return
        pending = unfinished
    raise ValueError('TLS verification did not complete')


def probe_admin(name, address, ca_file):
    context = trust_context(ca_file)

    class BoundConnection(http.client.HTTPSConnection):
        def connect(self):
            with socket.create_connection((address, self.port), timeout=self.timeout) as raw:
                self.sock = context.wrap_socket(raw, server_hostname=name)

    connection = BoundConnection(name, 8443, timeout=5)
    try:
        connection.request('GET', '/')
        with connection.getresponse() as response:
            if response.status != 200:
                raise ValueError('admin readiness failed')
    finally:
        connection.close()


if __name__ == '__main__':
    probe_admin(*sys.argv[1:])
