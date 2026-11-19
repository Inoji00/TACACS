"""Real loopback TLS with ephemeral certificates; no persistent private key."""
import datetime
import socket
import ssl
import tempfile
import threading
from pathlib import Path
import unittest
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
except ImportError:
    x509=None
from tacacs_appliance.admin_tls import create_admin_tls_context


@unittest.skipIf(x509 is None,"cryptography test dependency missing")
class TlsHandshakeTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        root=Path(self.directory.name)
        key=ec.generate_private_key(ec.SECP256R1())
        name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"localhost")])
        now=datetime.datetime.now(datetime.timezone.utc)
        certificate=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                     .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
                     .not_valid_after(now+datetime.timedelta(hours=1))
                     .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]),critical=False)
                     .sign(key,hashes.SHA256()))
        self.cert,self.key=root/"cert.pem",root/"key.pem"
        self.cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        self.key.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        self.key.chmod(0o600)
        self.context=create_admin_tls_context(self.cert,self.key)

    def tearDown(self):self.directory.cleanup()

    def handshake(self,version,*,hostname="localhost",client_identity=False):
        listener=socket.socket();listener.bind(("127.0.0.1",0));listener.listen(1);listener.settimeout(2)
        errors=[]
        def serve():
            try:
                peer,_=listener.accept()
                with peer:
                    peer.settimeout(2)
                    with self.context.wrap_socket(peer,server_side=True) as tls:
                        tls.sendall(b"ok")
            except (OSError,ssl.SSLError) as error:errors.append(type(error).__name__)
        thread=threading.Thread(target=serve);thread.start()
        client=ssl.create_default_context(cafile=str(self.cert))
        client.minimum_version=version;client.maximum_version=version
        client.set_alpn_protocols(["http/1.1"])
        if client_identity:
            client.load_cert_chain(str(self.cert),str(self.key))
        try:
            with socket.create_connection(listener.getsockname(),timeout=2) as peer:
                with client.wrap_socket(peer,server_hostname=hostname) as tls:
                    return tls.version(),tls.selected_alpn_protocol(),tls.recv(2)
        finally:
            listener.close();thread.join(3)
            self.assertFalse(thread.is_alive())
            self.server_errors=errors

    def test_tls13_handshake_with_certificate_and_hostname_verification(self):
        self.assertEqual(self.handshake(ssl.TLSVersion.TLSv1_3),("TLSv1.3","http/1.1",b"ok"))

    def test_tls12_handshake_rejected(self):
        with self.assertRaises(ssl.SSLError):self.handshake(ssl.TLSVersion.TLSv1_2)

    def test_admin_api_is_served_over_real_https(self):
        import http.client
        from unittest.mock import Mock
        from tacacs_appliance.admin_api import AdminApi
        from tacacs_appliance.admin_console import AdminConsole
        from tacacs_appliance.admin_server import AdminHttpsServer
        sessions=Mock();sessions.resolve.return_value="user"
        app=AdminApi(sessions,Mock(return_value=True),b"k"*32,"https://localhost")
        server=AdminHttpsServer(("127.0.0.1",0),AdminConsole(app),self.context,worker_limit=2)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        client=http.client.HTTPSConnection("localhost",server.server_address[1],timeout=2,
                                          context=ssl.create_default_context(cafile=str(self.cert)))
        try:
            client.request('GET','/')
            page=client.getresponse()
            self.assertEqual(page.status,200)
            self.assertIn(b'Administrator sign-in',page.read())
            self.assertIn("script-src 'self'",page.getheader('Content-Security-Policy'))
            client.request("GET","/api/session",headers={"Cookie":"__Host-tacacs_session="+"a"*43})
            response=client.getresponse();body=response.read()
            self.assertEqual(response.status,200)
            self.assertNotIn('CPython',response.getheader('Server',''))
            self.assertNotIn('WSGIServer',response.getheader('Server',''))
            self.assertIn(b'"user_id":"user"',body)
            self.assertEqual(response.getheader("Cache-Control"),"no-store")
        finally:
            client.close();server.shutdown();server.server_close();thread.join(2)

    def test_https_ambiguous_headers_rejected_before_wsgi(self):
        import http.client
        from unittest.mock import Mock
        from tacacs_appliance.admin_server import AdminHttpsServer
        app=Mock()
        server=AdminHttpsServer(("127.0.0.1",0),app,self.context)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            for headers in ((('Content-Length','0'),('Content-Length','0')),
                            (('Transfer-Encoding','chunked'),),
                            (('Origin','https://localhost'),('Origin','https://evil.local')),
                            (('Content-Length','65537'),),
                            (('X-Large','x'*9000),),
                            tuple(('X-'+str(index),'x'*4000) for index in range(9))):
                client=http.client.HTTPSConnection("localhost",server.server_address[1],timeout=2,
                    context=ssl.create_default_context(cafile=str(self.cert)))
                try:
                    client.putrequest("POST","/api/login")
                    for name,value in headers:client.putheader(name,value)
                    client.endheaders()
                    response=client.getresponse();response.read()
                    self.assertEqual(response.status,431 if any(name.startswith('X-') for name,_ in headers) else 400)
                finally:client.close()
            app.assert_not_called()
        finally:
            server.shutdown();server.server_close();thread.join(2)

    def test_wsgi_exception_is_sanitized_and_threading_is_declared(self):
        import contextlib
        import http.client
        import io
        from tacacs_appliance.admin_server import AdminHttpsServer
        observed=[]
        def application(environment,start_response):
            observed.append(environment['wsgi.multithread'])
            raise RuntimeError('password=SENSITIVE_DATABASE_DIAGNOSTIC')
        server=AdminHttpsServer(('127.0.0.1',0),application,self.context)
        captured=io.StringIO()
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        client=http.client.HTTPSConnection('localhost',server.server_address[1],timeout=2,
            context=ssl.create_default_context(cafile=str(self.cert)))
        try:
            with contextlib.redirect_stderr(captured):
                thread.start()
                client.request('GET','/')
                response=client.getresponse();body=response.read()
                self.assertEqual(response.status,500)
                self.assertNotIn(b'SENSITIVE_DATABASE_DIAGNOSTIC',body)
            self.assertEqual(captured.getvalue(),'')
            self.assertEqual(observed,[True])
        finally:
            client.close();server.shutdown();server.server_close();thread.join(2)

    def test_absolute_deadline_interrupts_incomplete_headers_and_body(self):
        from unittest.mock import Mock
        from tacacs_appliance.admin_server import AdminHttpsServer
        import time
        def application(environment,start_response):
            environment['wsgi.input'].read(100)
            start_response('200 OK',[('Content-Length','0')])
            return [b'']
        app=Mock(side_effect=application)
        server=AdminHttpsServer(('127.0.0.1',0),app,self.context,request_deadline=0.3)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        client_context=ssl.create_default_context(cafile=str(self.cert))
        try:
            for request in (b'GET / HTTP/1.1\r\nHost: localhost\r\nX-Slow: ',
                            b'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\nx'):
                with socket.create_connection(server.server_address,timeout=2) as peer:
                    with client_context.wrap_socket(peer,server_hostname='localhost') as tls:
                        started=time.monotonic();tls.sendall(request)
                        while tls.recv(4096):pass
                        self.assertLess(time.monotonic()-started,1.5)
            self.assertEqual(app.call_count,0)
        finally:
            server.shutdown();server.server_close();thread.join(2)

    def test_absolute_deadline_interrupts_incomplete_tls_handshake(self):
        from unittest.mock import Mock
        from tacacs_appliance.admin_server import AdminHttpsServer
        server=AdminHttpsServer(('127.0.0.1',0),Mock(),self.context,request_deadline=0.2)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with socket.create_connection(server.server_address,timeout=2) as peer:
                self.assertEqual(peer.recv(1),b'')
            server.get_app().assert_not_called()
        finally:
            server.shutdown();server.server_close();thread.join(2)

    def test_ignored_request_body_does_not_truncate_https_response(self):
        import http.client
        from tacacs_appliance.admin_server import AdminHttpsServer
        observed=[]
        def application(environment,start_response):
            observed.append(environment['wsgi.input'].getbuffer().nbytes)
            start_response('200 OK',[('Content-Length','23')])
            return [b'{"status":"logged_out"}']
        server=AdminHttpsServer(('127.0.0.1',0),application,self.context)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        context=ssl.create_default_context(cafile=str(self.cert))
        try:
            for _ in range(10):
                client=http.client.HTTPSConnection('localhost',server.server_address[1],timeout=3,context=context)
                try:
                    client.request('POST','/api/logout',body=b'x'*65536)
                    response=client.getresponse()
                    self.assertEqual(response.status,200)
                    self.assertEqual(len(response.read()),23)
                finally:client.close()
            self.assertEqual(observed,[65536]*10)
        finally:
            server.shutdown();server.server_close();thread.join(2)

    def test_wrong_hostname_is_rejected(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.handshake(ssl.TLSVersion.TLSv1_3,hostname="wrong.local")

    def test_mtls_without_client_certificate_is_rejected(self):
        self.context=create_admin_tls_context(self.cert,self.key,client_ca=self.cert)
        try:
            result=self.handshake(ssl.TLSVersion.TLSv1_3)
        except ssl.SSLError:
            result=None
        # Some TLS stacks expose the server rejection as EOF instead of raising
        # on the client's first read. No application data must be delivered.
        if result is not None:self.assertEqual(result[2],b"")
        self.assertIn("SSLError",self.server_errors)

    def test_mtls_with_explicitly_trusted_test_identity_succeeds(self):
        # Direct trust uses the ephemeral test certificate for both roles.
        # Production server/client credentials must be distinct CA-issued certs.
        self.context=create_admin_tls_context(self.cert,self.key,client_ca=self.cert)
        self.assertEqual(self.handshake(ssl.TLSVersion.TLSv1_3,client_identity=True),
                         ("TLSv1.3","http/1.1",b"ok"))


    @unittest.skipUnless(hasattr(socket,"SO_PEERCRED"),"Linux relay credentials required")
    def test_relay_peer_metadata_survives_real_tls(self):
        import ipaddress
        import os
        from unittest.mock import Mock, patch
        from uuid import uuid4
        from tacacs_appliance.admin_api import AdminApi
        from tacacs_appliance.admin_server import AdminHttpsServer, ProxiedAdminHttpsServer

        sessions=Mock()
        audit=Mock()
        login=Mock()
        login.login.return_value=None
        app=AdminApi(sessions,Mock(),b"k"*32,"https://admin.local",
                     lan_ip="192.0.2.151",login=login,web_audit=audit)
        with AdminHttpsServer(("127.0.0.1",0),app,self.context) as direct, \
             patch("tacacs_appliance.admin_server.PROXY_ADDRESS","\0tnac-test-"+uuid4().hex), \
             patch("tacacs_appliance.web_audit_network.PROXY_UID",os.getuid()), \
             ProxiedAdminHttpsServer(app,self.context,direct) as proxied:
            thread=threading.Thread(target=proxied.serve_forever,daemon=True)
            thread.start()
            try:
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
                    client.settimeout(3)
                    client.connect(proxied.server_address)
                    client.sendall(ipaddress.IPv4Address("192.0.2.14").packed)
                    context=ssl.create_default_context(cafile=str(self.cert))
                    with context.wrap_socket(client,server_hostname="localhost") as tls:
                        body=b'{"username":"operator","password":"private","factor_id":"","code":""}'
                        tls.sendall(b"POST /api/login HTTP/1.1\r\nHost: admin.local\r\n"
                                    b"Origin: https://admin.local\r\nContent-Type: application/json\r\n"
                                    b"X-Forwarded-For: 192.0.2.99\r\nContent-Length: "
                                    +str(len(body)).encode()+b"\r\n\r\n"+body)
                        with tls.makefile("rb") as response:
                            self.assertIn(b"401 Unauthorized",response.readline())
                self.assertEqual(audit.call_args.kwargs["security_context"],
                                 {"source_ip":"192.0.2.14","destination_ip":"192.0.2.151",
                                  "attempted_username":"operator"})
            finally:
                proxied.shutdown()
                thread.join(3)
