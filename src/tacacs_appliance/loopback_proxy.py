"""Bounded opaque TCP relay for Docker Desktop local HTTPS publishing.

TLS terminates only at the existing loopback-only administration server.
No credentials, application bodies or TLS keys are read by this process.
"""
import argparse
import ipaddress
import select
import signal
import socket
import threading
import time
from .web_audit_network import PROXY_ADDRESS


def relay(client,backend,*,timeout=30):
    deadline=time.monotonic()+timeout
    readers=[client,backend]
    while readers:
        remaining=deadline-time.monotonic()
        if remaining<=0:return
        readable,_,_=select.select(readers,[],[],min(remaining,0.5))
        for source in readable:
            target=backend if source is client else client
            data=source.recv(16384)
            if not data:
                readers.remove(source)
                target.shutdown(socket.SHUT_WR)
            else:target.sendall(data)


def main():
    parser=argparse.ArgumentParser(description='Local Docker HTTPS opaque relay')
    parser.add_argument('--bind-name',required=True)
    args=parser.parse_args()
    address=socket.gethostbyname(args.bind_name)
    parsed=ipaddress.IPv4Address(address)
    if parsed.is_unspecified or parsed.is_loopback or parsed.is_multicast:
        raise ValueError('explicit container interface required')
    stopped=threading.Event();slots=threading.BoundedSemaphore(8)
    active=set();lock=threading.Lock()
    def serve(client, peer):
        backend=None
        try:
            client.settimeout(0.5)
            backend=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            backend.settimeout(0.5)
            backend.connect(PROXY_ADDRESS)
            backend.sendall(ipaddress.IPv4Address(peer).packed)
            with lock:active.add(backend)
            relay(client,backend)
        except (OSError,ValueError):pass
        finally:
            with lock:
                active.discard(client);active.discard(backend)
            client.close()
            if backend:backend.close()
            slots.release()
    signal.signal(signal.SIGTERM,lambda *_:stopped.set())
    signal.signal(signal.SIGINT,lambda *_:stopped.set())
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listener.bind((address,8443));listener.listen(8);listener.settimeout(0.5)
        print('Local opaque HTTPS relay ready.',flush=True)
        try:
            while not stopped.is_set():
                try:client,peer=listener.accept()
                except socket.timeout:continue
                if not slots.acquire(blocking=False):client.close();continue
                with lock:active.add(client)
                threading.Thread(target=serve,args=(client,peer[0]),daemon=True).start()
        finally:
            with lock:
                for connection in active:
                    try:connection.shutdown(socket.SHUT_RDWR)
                    except OSError:pass
    return 0


if __name__=='__main__':raise SystemExit(main())
