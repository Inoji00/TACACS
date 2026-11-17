"""Bounded HTTPS WSGI adapter with TLS, worker, header and request limits."""
import ssl
import socket
import socketserver
import threading
import math
import io
from http.client import LineTooLong,HTTPException
from wsgiref.simple_server import WSGIServer,WSGIRequestHandler,ServerHandler
from .health import BoundedHealthServer
from .web_audit_network import PROXY_ADDRESS, proxy_peer


class BoundedHeaderReader:
    """Parser-only view; leaves body bytes in the original buffered stream."""
    def __init__(self,stream):
        self.stream=stream
        self.remaining=32768

    def readline(self,size=-1):
        limit=min(8193,self.remaining+1)
        if size>=0:limit=min(limit,size)
        line=self.stream.readline(limit)
        if len(line)>8192 or len(line)>self.remaining:
            raise LineTooLong('bounded request headers')
        if not line.endswith(b'\r\n'):
            raise HTTPException('Incomplete request headers')
        self.remaining-=len(line)
        return line


class SanitizedServerHandler(ServerHandler):
    server_software='TACACS+'
    def log_exception(self,exc_info):
        # Exception text and tracebacks can contain credentials or SQL data.
        # Preserve the generic WSGI 500 response without stderr diagnostics.
        pass


class AdminRequestHandler(WSGIRequestHandler):
    server_version='TACACS+'
    sys_version=''
    def handle(self):
        self.raw_requestline=self.rfile.readline(65537)
        if len(self.raw_requestline)>65536:
            self.requestline='';self.request_version='';self.command=''
            self.send_error(414)
            return
        if not self.parse_request():
            return
        length=int(self.headers.get('Content-Length','0'))
        body=self.rfile.read(length)
        if len(body)!=length:
            self.send_error(400,'Incomplete request body')
            return
        # Every API receives only its own bounded body, never the raw socket.
        # Consume even bodies ignored by logout/error routes before responding.
        handler=SanitizedServerHandler(io.BytesIO(body),self.wfile,self.get_stderr(),
                                       self.get_environ(),multithread=True)
        handler.request_handler=self
        handler.run(self.server.get_app())

    def parse_request(self):
        original=self.rfile
        self.rfile=BoundedHeaderReader(original)
        try:parsed=super().parse_request()
        finally:self.rfile=original
        if not parsed:
            return False
        protected=("Host","Content-Length","Content-Type","Cookie","Origin","X-CSRF-Token","Authorization")
        if any(len(self.headers.get_all(name,[]))>1 for name in protected):
            self.send_error(400,"Ambiguous request headers")
            return False
        if self.headers.get("Transfer-Encoding") is not None:
            self.send_error(400,"Transfer encoding unsupported")
            return False
        if self.request_version=="HTTP/1.1" and not self.headers.get("Host"):
            self.send_error(400,"Host header required")
            return False
        if sum(len(name)+len(value) for name,value in self.headers.items())>32768:
            self.send_error(431,"Request headers too large")
            return False
        length=self.headers.get("Content-Length")
        if length is not None and (not length.isascii() or not length.isdecimal() or len(length)>6 or int(length)>65536):
            self.send_error(400,"Invalid request length")
            return False
        return True

    def setup(self):
        self.request.settimeout(5)
        super().setup()

    def get_environ(self):
        environment=super().get_environ()
        environment["HTTPS"]="on"
        environment["tnac.source_ip"]=self.client_address[0]
        environment["tnac.via_proxy"]=self.server.relayed
        if environment["tnac.via_proxy"]:
            # Preserve the existing rate-limit key for relayed requests.
            environment["REMOTE_ADDR"]="127.0.0.1"
        else:
            environment["tnac.destination_ip"]=self.request.getsockname()[0]
        return environment

    def log_message(self,*args):
        pass


class AdminHttpsServer(BoundedHealthServer,WSGIServer):
    relayed=False
    def __init__(self,address,application,context,*,worker_limit=8,request_deadline=10):
        if not isinstance(context,ssl.SSLContext):
            raise ValueError("explicit TLS context required")
        if context.minimum_version != ssl.TLSVersion.TLSv1_3 or context.maximum_version != ssl.TLSVersion.TLSv1_3:
            raise ValueError("TLS 1.3-only context required")
        self._tls=context
        if type(request_deadline) not in (int,float) or not math.isfinite(request_deadline) or not 0<request_deadline<=60:
            raise ValueError('invalid absolute request deadline')
        self._request_deadline=request_deadline
        super().__init__(address,AdminRequestHandler,worker_limit=worker_limit)
        self.set_app(application)

    def finish_request(self,request,client_address):
        # Handshake occurs inside an already-budgeted worker, never accept loop.
        request.settimeout(5)
        secure=None
        watchdog=None
        try:
            if self.relayed:
                client_address=(proxy_peer(request),0)
            secure=self._tls.wrap_socket(request,server_side=True,do_handshake_on_connect=False)
            with self._clients_lock:
                self._clients.add(secure)
            def expire():
                # shutdown interrupts blocked buffered reads, unlike refreshing
                # a socket timeout for each byte supplied by a slow client.
                try:secure.shutdown(socket.SHUT_RDWR)
                except OSError:pass
            watchdog=threading.Timer(self._request_deadline,expire)
            watchdog.daemon=True
            watchdog.start()
            secure.do_handshake()
            if secure.selected_alpn_protocol() not in (None,"http/1.1"):
                return
            self.RequestHandlerClass(secure,client_address,self)
        except (OSError,ValueError):
            pass
        finally:
            if watchdog is not None:
                watchdog.cancel()
                watchdog.join()
            if secure is not None:
                secure.close()
                with self._clients_lock:self._clients.discard(secure)

    def handle_error(self,request,client_address):
        # WSGI/runtime failures must not expose exception text or request bodies.
        pass


class ProxiedAdminHttpsServer(AdminHttpsServer):
    relayed=True
    address_family=getattr(socket,'AF_UNIX',None)

    def __init__(self, application, context, direct_server):
        if self.address_family is None:
            raise OSError('Unix sockets unavailable')
        super().__init__(PROXY_ADDRESS, application, context)
        self._worker_slots=direct_server._worker_slots

    def server_bind(self):
        # WSGIServer.server_bind assumes an Internet socket address tuple.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port='localhost',8443
        self.setup_environ()
