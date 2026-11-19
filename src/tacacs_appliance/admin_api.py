"""HTTPS-only WSGI administration boundary with session-bound CSRF.

Password/TOTP is the default. Explicit password-only configuration may use
password-only ephemeral sessions; TLS and CSRF remain enforced.
"""
import hashlib
import hmac
import ipaddress
import json
import logging
import re
from .rate_limit import SourceRateLimiter
from .web_audit_network import audit_ip
from http.cookies import SimpleCookie, CookieError

COOKIE_NAME = "__Host-tacacs_session"
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}\Z")


def lan_admin_origin(address, domain=None):
    if address is None:
        if domain is not None:
            raise ValueError('administration DNS requires a LAN binding')
        return None
    ip = ipaddress.IPv4Address(address)
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved or ip.is_link_local:
        raise ValueError('unicast administration IPv4 required')
    if domain is not None:
        from .admin_endpoint import admin_domain
        return f'https://{admin_domain(domain)}:8443'
    return f'https://{ip}:8443'


class AdminApi:
    def __init__(self, sessions, permissions, csrf_key: bytes, origin: str, *, login=None, policies=None,audit=None,simulation=None,password_only=False,password_change=None,inventory=None,identities=None,devices=None,device_audit=None,accounting=None,deployment=None,lan_ip=None,dashboard=None,logs=None,device_operator=None,lan_domain=None,web_audit=None,alerts=None):
        from urllib.parse import urlsplit
        url = urlsplit(origin)
        if (url.scheme != "https" or not url.hostname or url.username or url.password
                or url.path or url.query or url.fragment):
            raise ValueError("canonical HTTPS origin required")
        if len(csrf_key) < 32:
            raise ValueError("CSRF key must be at least 32 bytes")
        self._sessions, self._permissions = sessions, permissions
        self._device_operator = device_operator
        if type(password_only) is not bool or (password_only and origin not in ('https://localhost:8443', lan_admin_origin(lan_ip,lan_domain))):
            raise ValueError('password-only mode requires a configured administration origin')
        self.password_only=password_only
        self._key, self._origin = csrf_key, origin
        self._login = login
        self._web_audit=web_audit
        self._web_destination=audit_ip(lan_ip) or audit_ip(url.hostname)
        if self._web_destination is None and url.hostname=='localhost':
            self._web_destination='127.0.0.1'
        self._policies = policies
        self._audit=audit
        self._simulation=simulation
        self._password_change=password_change
        self._inventory=inventory
        self._devices,self._device_audit=devices,device_audit
        self._accounting,self._deployment=accounting,deployment
        self._dashboard=dashboard
        self._logs=logs
        self._alerts=alerts
        self._identities=identities
        self._device_write_limiter=SourceRateLimiter(5,1/60,idle_seconds=600)
        self._password_limiter=SourceRateLimiter(3,1/60,idle_seconds=600)
        self._login_limiter = SourceRateLimiter(5, 1 / 60, idle_seconds=600)

    def _record_web_access(self, environ, action, result, *, username=None, token=None, actor=None):
        if self._web_audit is None:
            return
        source_ip=audit_ip(environ.get('tnac.source_ip'))
        destination_ip=(self._web_destination if environ.get('tnac.via_proxy')
                        else audit_ip(environ.get('tnac.destination_ip')))
        details={key:value for key,value in (
            ('source_ip',source_ip),('destination_ip',destination_ip)) if value is not None}
        if isinstance(username,str) and re.fullmatch(r'[A-Za-z0-9_.@-]{1,64}',username):
            details['attempted_username']=username
        try:
            if token is not None:
                actor=self._sessions.resolve(token)
            self._web_audit(actor=actor or 'anonymous',source='admin-web',action=action,
                            target=destination_ip or 'web-ui',result=result,security_context=details)
        except Exception:
            # Audit availability must never prevent a user from signing out.
            logging.getLogger(__name__).error('{"event":"WEB_ACCESS_AUDIT_FAILED"}')

    def csrf_token(self, session_token: str) -> str:
        return hmac.new(self._key, b"admin-csrf-v1\0" + session_token.encode("ascii"), hashlib.sha256).hexdigest()

    @staticmethod
    def session_cookie(token: str) -> str:
        if not TOKEN_PATTERN.fullmatch(token):
            raise ValueError("invalid session token")
        return f"{COOKIE_NAME}={token}; Path=/; Secure; HttpOnly; SameSite=Strict"

    def __call__(self, environ, start_response):
        def respond(status, body, extra=()):
            encoded = json.dumps(body, separators=(",", ":")).encode()
            start_response(status, [
                ("Content-Type", "application/json"), ("Content-Length", str(len(encoded))),
                ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"),
                ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"),
                ("Strict-Transport-Security", "max-age=31536000"), *extra])
            return [encoded]
        # Do not trust forwarded headers to assert TLS or same-origin status.
        if environ.get("wsgi.url_scheme") != "https":
            return respond("400 Bad Request", {"error": "HTTPS required"})
        method, path = environ.get("REQUEST_METHOD"), environ.get("PATH_INFO")
        if "HTTP_X_TACACS_TENANT" in environ:
            return respond("400 Bad Request", {"error": "tenant selection unavailable"})
        if path=='/api/login-options' and method=='GET':
            return respond('200 OK',{'mfa_required':not self.password_only})
        if path == "/api/login" and method == "POST" and self._login is not None:
            if environ.get("HTTP_ORIGIN") != self._origin:
                return respond("403 Forbidden", {"error": "request verification failed"})
            # Use only the socket peer supplied by the server, not X-Forwarded-For.
            peer = environ.get("REMOTE_ADDR")
            if not isinstance(peer, str) or not peer or not self._login_limiter.allow(peer):
                return respond("429 Too Many Requests", {"error": "retry later"})
            if environ.get("CONTENT_TYPE") != "application/json":
                return respond("415 Unsupported Media Type", {"error": "JSON required"})
            try:
                length = int(environ.get("CONTENT_LENGTH", ""))
                if not 1 <= length <= 8192:
                    raise ValueError("invalid body size")
                raw = environ["wsgi.input"].read(length)
                if len(raw) != length:
                    raise ValueError("incomplete request")
                def unique_fields(pairs):
                    result = {}
                    for key, value in pairs:
                        if key in result:
                            raise ValueError("duplicate field")
                        result[key] = value
                    return result
                body = json.loads(raw, object_pairs_hook=unique_fields)
                fields={'username','password'} if self.password_only else {'username','password','factor_id','code'}
                if not isinstance(body, dict) or set(body) != fields:
                    raise ValueError("invalid login schema")
            except (ValueError, KeyError, UnicodeError):
                return respond("400 Bad Request", {"error": "invalid request"})
            try:
                new_token = self._login.login(**body)
                if new_token is None:
                    self._record_web_access(environ,'web.login','fail',username=body['username'])
                    return respond("401 Unauthorized", {"error": "invalid credentials"})
                response={"status": "authenticated", "csrf_token": self.csrf_token(new_token)}
                cookie=self.session_cookie(new_token)
                self._record_web_access(environ,'web.login','success',username=body['username'],token=new_token)
                return respond("200 OK", response,
                               [("Set-Cookie", cookie)])
            except Exception:
                return respond("503 Service Unavailable", {"error": "service unavailable"})
        cookie_raw = environ.get("HTTP_COOKIE", "")
        if len(cookie_raw) > 4096:
            return respond("401 Unauthorized", {"error": "authentication required"})
        # Reject duplicate session cookie names rather than choose arbitrarily.
        if sum(part.strip().split("=", 1)[0] == COOKIE_NAME for part in cookie_raw.split(";")) != 1:
            return respond("401 Unauthorized", {"error": "authentication required"})
        cookies = SimpleCookie()
        try:
            cookies.load(cookie_raw)
            token = cookies[COOKIE_NAME].value
            if not TOKEN_PATTERN.fullmatch(token):
                raise ValueError("invalid cookie")
        except (CookieError, KeyError, ValueError):
            return respond("401 Unauthorized", {"error": "authentication required"})
        try:
            user_id = self._sessions.resolve(token)
            if user_id is None:
                return respond("401 Unauthorized", {"error": "authentication required"})
            if method not in ("GET", "HEAD", "OPTIONS"):
                supplied = environ.get("HTTP_X_CSRF_TOKEN", "")
                if (environ.get("HTTP_ORIGIN") != self._origin or not isinstance(supplied, str) or len(supplied) != 64
                        or not supplied.isascii() or not hmac.compare_digest(supplied, self.csrf_token(token))):
                    return respond("403 Forbidden", {"error": "request verification failed"})
            if (self._device_operator is not None
                    and path not in {'/api/session', '/api/inventory', '/api/logout', '/api/password',
                                     '/api/devices', '/api/devices/delete', '/api/devices/secret',
                                     '/api/device-groups', '/api/logs', '/api/accounting'}
                    and self._device_operator(user_id)):
                return respond("403 Forbidden", {"error": "permission denied"})
            if path == "/api/session" and method == "GET":
                if not self._permissions(user_id, "console.read"):
                    return respond("403 Forbidden", {"error": "permission denied"})
                session = {"user_id": user_id, "csrf_token": self.csrf_token(token)}
                if self._device_operator is not None:
                    session["device_operator"] = self._device_operator(user_id)
                    if session["device_operator"]:
                        session["device_aaa_logs"] = self._permissions(user_id, "devices.aaa.read")
                return respond("200 OK", session)
            if path == "/api/device-syslog":
                if not self._permissions(user_id, "users.manage"):
                    return respond("403 Forbidden", {"error": "permission denied"})
                if method != "GET":
                    return respond("405 Method Not Allowed", {"error": "method not allowed"})
                from .device_syslog import search
                query = environ.get("QUERY_STRING", "")
                if len(query) > 2048:
                    return respond("400 Bad Request", {"error": "invalid syslog filters"})
                try:
                    return respond("200 OK", search(query))
                except (ValueError, OverflowError):
                    return respond("400 Bad Request", {"error": "invalid syslog filters"})
            if path in ('/api/alerts', '/api/alerts/test') and self._alerts is not None:
                if not self._permissions(user_id, 'users.manage'):
                    return respond('403 Forbidden', {'error': 'permission denied'})
                if environ.get('QUERY_STRING', ''):
                    return respond('400 Bad Request', {'error': 'unexpected query'})
                if path == '/api/alerts' and method == 'GET':
                    return respond('200 OK', self._alerts.public())
                if method != 'POST':
                    return respond('405 Method Not Allowed', {'error': 'method not allowed'})
                try:
                    length = int(environ.get('CONTENT_LENGTH', ''))
                    if environ.get('CONTENT_TYPE') != 'application/json' or not 1 <= length <= 4096:
                        raise ValueError('invalid body')
                    raw = environ['wsgi.input'].read(length)
                    if len(raw) != length:
                        raise ValueError('incomplete body')
                    def alert_fields(pairs):
                        fields = {}
                        for key, value in pairs:
                            if key in fields:
                                raise ValueError('duplicate alert field')
                            fields[key] = value
                        return fields
                    values = json.loads(raw, object_pairs_hook=alert_fields)
                    if path == '/api/alerts/test' and values != {}:
                        raise ValueError('invalid test request')
                    if self._web_audit is None:
                        raise RuntimeError('alert audit unavailable')
                    self._web_audit(actor=user_id, source='admin-alerts',
                                    action='slack.alerts.test' if path.endswith('/test') else 'slack.alerts.configure',
                                    target='slack', result='requested', security_context={})
                    if path.endswith('/test'):
                        return respond('202 Accepted', self._alerts.request_test())
                    return respond('200 OK', self._alerts.save(values))
                except (ValueError, TypeError, KeyError, UnicodeError):
                    return respond('400 Bad Request', {'error': 'invalid alert settings or test cooldown'})
            if path=='/api/inventory' and method=='GET' and self._inventory is not None:
                if not self._permissions(user_id,'console.read'):return respond('403 Forbidden',{'error':'permission denied'})
                if environ.get('QUERY_STRING',''):return respond('400 Bad Request',{'error':'unexpected query'})
                if self._device_operator is not None and self._device_operator(user_id):
                    return respond('200 OK',self._inventory.read(only_user=user_id))
                return respond('200 OK',self._inventory.read())
            if path in ('/api/logs','/api/reports') and method=='GET' and self._logs is not None:
                if not (self._permissions(user_id, 'audit.read') or
                        (path == '/api/logs' and self._permissions(user_id, 'devices.aaa.read'))):
                    return respond('403 Forbidden', {'error': 'permission denied'})
                from urllib.parse import parse_qs
                try:
                    query=environ.get('QUERY_STRING','')
                    if len(query)>4096:raise ValueError()
                    fields=parse_qs(query,keep_blank_values=True,strict_parsing=True,max_num_fields=12)
                    if set(fields)-{'kind','search','action','result','device','session','actor','since','until','before','limit'} or any(len(v)!=1 for v in fields.values()):raise ValueError()
                    values={key:items[0] for key,items in fields.items()}
                    if 'limit' in values:
                        if not values['limit'].isascii() or not values['limit'].isdecimal() or len(values['limit'])>3:raise ValueError()
                        values['limit']=int(values['limit'])
                    return respond('200 OK',self._logs.read(user_id,report=path=='/api/reports',**values))
                except PermissionError:return respond('403 Forbidden',{'error':'permission denied'})
                except (ValueError,TypeError,KeyError,OverflowError):return respond('400 Bad Request',{'error':'invalid log query'})
            if path=='/api/dashboard' and method=='GET' and self._dashboard is not None:
                if not self._permissions(user_id,'audit.read'):return respond('403 Forbidden',{'error':'permission denied'})
                if environ.get('QUERY_STRING',''):return respond('400 Bad Request',{'error':'unexpected query'})
                try:return respond('200 OK',self._dashboard.read(user_id))
                except PermissionError:return respond('403 Forbidden',{'error':'permission denied'})
            if path=='/api/deployment' and method=='GET' and self._deployment is not None:
                if not self._permissions(user_id,'console.read'):return respond('403 Forbidden',{'error':'permission denied'})
                if environ.get('QUERY_STRING',''):return respond('400 Bad Request',{'error':'unexpected query'})
                return respond('200 OK',self._deployment.read())
            if path=='/api/accounting' and method=='GET' and self._accounting is not None:
                if not (self._permissions(user_id, 'audit.read') or self._permissions(user_id, 'devices.aaa.read')):
                    return respond('403 Forbidden', {'error': 'permission denied'})
                from urllib.parse import parse_qs
                try:
                    query=environ.get('QUERY_STRING','')
                    if len(query)>2048:raise ValueError()
                    fields=parse_qs(query,keep_blank_values=True,strict_parsing=True,max_num_fields=9)
                    if set(fields)-{'username','device','session','action','command','since','until','before','limit'} or any(len(v)!=1 for v in fields.values()):raise ValueError()
                    values={key:items[0] for key,items in fields.items()}
                    if 'limit' in values:
                        if not values['limit'].isascii() or not values['limit'].isdecimal() or len(values['limit'])>3:raise ValueError()
                        values['limit']=int(values['limit'])
                    return respond('200 OK',self._accounting.list_events(user_id,**values))
                except PermissionError:return respond('403 Forbidden',{'error':'permission denied'})
                except (ValueError,TypeError,KeyError):return respond('400 Bad Request',{'error':'invalid accounting query'})
            if path in ('/api/devices','/api/devices/delete','/api/devices/secret','/api/device-groups') and method in ('GET','POST'):
                if not self._permissions(user_id,'devices.manage'):return respond('403 Forbidden',{'error':'permission denied'})
                if self._devices is None:return respond('503 Service Unavailable',{'error':'device registry not provisioned'})
                if method=='GET':
                    if path in ('/api/devices/delete','/api/devices/secret'):return respond('405 Method Not Allowed',{'error':'invalid device request; check fields and group'})
                    if path=='/api/device-groups':
                        if environ.get('QUERY_STRING',''):return respond('400 Bad Request',{'error':'invalid device query'})
                        from .device_groups import DeviceGroups
                        try:return respond('200 OK',DeviceGroups(self._devices.pool,self._devices.tenant).list(actor=user_id))
                        except PermissionError:return respond('403 Forbidden',{'error':'permission denied'})
                    from urllib.parse import parse_qs
                    try:
                        query=environ.get('QUERY_STRING','')
                        if len(query)>512:raise ValueError()
                        fields=parse_qs(query,keep_blank_values=True,strict_parsing=True,max_num_fields=6)
                        if set(fields)-{'search','after','limit','status','location_id','device_type_id'} or any(len(v)!=1 for v in fields.values()):raise ValueError()
                        values={key:items[0] for key,items in fields.items()}
                        if 'limit' in values:
                            if not values['limit'].isascii() or not values['limit'].isdecimal() or len(values['limit'])>3:raise ValueError()
                            values['limit']=int(values['limit'])
                        return respond('200 OK',self._devices.list_devices(actor=user_id,**values))
                    except PermissionError:return respond('403 Forbidden',{'error':'permission denied'})
                    except (ValueError,TypeError,KeyError):return respond('400 Bad Request',{'error':'invalid device query'})
                try:
                    limited = path == '/api/devices/secret' or not self._permissions(user_id, 'users.manage')
                    if limited and not self._device_write_limiter.allow(user_id):
                        return respond('429 Too Many Requests', {'error': 'retry later'})
                    if environ.get('CONTENT_TYPE')!='application/json' or environ.get('QUERY_STRING',''):raise ValueError()
                    length=int(environ.get('CONTENT_LENGTH',''))
                    if not 1<=length<=16384:raise ValueError()
                    raw=environ['wsgi.input'].read(length)
                    if len(raw)!=length:raise ValueError()
                    def device_fields(pairs):
                        result={}
                        for key,value in pairs:
                            if key in result:raise ValueError()
                            result[key]=value
                        return result
                    payload=json.loads(raw,object_pairs_hook=device_fields)
                    if path=='/api/devices/delete':
                        if not isinstance(payload,dict) or set(payload)!={'address'}:raise ValueError()
                        return respond('200 OK',self._devices.delete(user_id,payload['address'],self._device_audit))
                    if path=='/api/devices/secret':
                        if not isinstance(payload,dict) or set(payload)!={'address','password'}:raise ValueError()
                        password=payload['password']
                        if not isinstance(password,str) or not 1<=len(password)<=1024:raise ValueError()
                        return respond('200 OK',self._devices.reveal_secret(user_id,payload['address'],self._device_audit,password=password))
                    if path=='/api/device-groups':
                        from .device_groups import DeviceGroups
                        return respond('200 OK',DeviceGroups(self._devices.pool,self._devices.tenant).save(user_id,payload,self._device_audit))
                    return respond('200 OK',self._devices.save(user_id,payload,self._device_audit))
                except PermissionError:return respond('403 Forbidden',{'error':'permission denied'})
                except (ValueError,TypeError,KeyError,UnicodeError):return respond('400 Bad Request',{'error':'invalid device request; check fields and group'})
            if path in ('/api/identity-groups','/api/identities/list') and method=='GET' and self._identities is not None:
                if not self._permissions(user_id,'users.manage'):return respond('403 Forbidden',{'error':'permission denied'})
                try:
                    from urllib.parse import parse_qs
                    query=environ.get('QUERY_STRING','')
                    if len(query)>100:raise ValueError()
                    fields=parse_qs(query,strict_parsing=True,max_num_fields=1,keep_blank_values=True)
                    if set(fields)-{'after'} or any(len(v)!=1 for v in fields.values()):raise ValueError()
                    if path=='/api/identity-groups':
                        from .identity_groups import IdentityGroups
                        return respond('200 OK',IdentityGroups(self._identities).list(user_id,fields.get('after',[None])[0]))
                    return respond('200 OK',self._identities.list_users(user_id,fields.get('after',[None])[0]))
                except (ValueError,TypeError):return respond('400 Bad Request',{'error':'invalid identity request'})
            if path in ('/api/identity-groups','/api/identities','/api/identities/state','/api/identities/update','/api/identities/delete','/api/identities/unlock','/api/identities/console-access') and method=='POST' and self._identities is not None:
                from .admin_identities import IdentityProtectedError,IdentityNameUnavailable
                if not self._permissions(user_id,'users.manage'):return respond('403 Forbidden',{'error':'permission denied'})
                try:
                    if environ.get('CONTENT_TYPE')!='application/json' or environ.get('QUERY_STRING',''):raise ValueError()
                    length=int(environ.get('CONTENT_LENGTH',''))
                    if not 1<=length<=16384:raise ValueError()
                    raw=environ['wsgi.input'].read(length)
                    if len(raw)!=length:raise ValueError()
                    def identity_fields(pairs):
                        result={}
                        for key,value in pairs:
                            if key in result:raise ValueError()
                            result[key]=value
                        return result
                    payload=json.loads(raw,object_pairs_hook=identity_fields)
                    if path=='/api/identity-groups':
                        from .identity_groups import IdentityGroups
                        return respond('200 OK',IdentityGroups(self._identities).save(user_id,payload))
                    if path=='/api/identities/console-access':
                        if not isinstance(payload,dict) or set(payload) not in ({'user_id','enabled'},{'user_id','enabled','access'}):raise ValueError()
                        return respond('200 OK',self._identities.set_console_access(user_id,**payload))
                    actions={
                        '/api/identities':({'username','password','group_name'},self._identities.create),
                        '/api/identities/state':({'user_id','enabled'},self._identities.set_enabled),
                        '/api/identities/update':({'user_id','username','password','group_name','enabled'},self._identities.update),
                        '/api/identities/delete':({'user_id'},self._identities.delete),
                        '/api/identities/unlock':({'user_id'},self._identities.unlock)}
                    fields,action=actions[path]
                    if not isinstance(payload,dict) or set(payload)!=fields:raise ValueError()
                    return respond('201 Created' if path=='/api/identities' else '200 OK',action(user_id,**payload))
                except IdentityProtectedError:return respond('400 Bad Request',{'error':'identity protected'})
                except IdentityNameUnavailable:return respond('400 Bad Request',{'error':'username unavailable'})
                except PermissionError:return respond('403 Forbidden',{'error':'permission denied'})
                except (ValueError,KeyError,TypeError,UnicodeError):return respond('400 Bad Request',{'error':'invalid identity request'})
            if path=='/api/password' and method=='POST' and self._password_change is not None:
                if not self._password_limiter.allow(user_id):return respond('429 Too Many Requests',{'error':'retry later'})
                try:
                    if environ.get('CONTENT_TYPE')!='application/json' or environ.get('QUERY_STRING',''):raise ValueError()
                    length=int(environ.get('CONTENT_LENGTH',''))
                    if not 1<=length<=16384:raise ValueError()
                    raw=environ['wsgi.input'].read(length)
                    if len(raw)!=length:raise ValueError()
                    def exact_fields(pairs):
                        result={}
                        for key,value in pairs:
                            if key in result:raise ValueError()
                            result[key]=value
                        return result
                    payload=json.loads(raw,object_pairs_hook=exact_fields)
                    if not isinstance(payload,dict) or set(payload)!={'current_password','new_password'}:raise ValueError()
                    self._password_change.change(user_id,**payload)
                    return respond('200 OK',{'status':'password changed; sign in again'},[('Set-Cookie',
                        f'{COOKIE_NAME}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0')])
                except PermissionError:return respond('403 Forbidden',{'error':'password verification failed'})
                except (ValueError,KeyError,UnicodeError):return respond('400 Bad Request',{'error':'invalid password change'})
            if method=='GET' and ((path=='/api/policies' and self._policies is not None) or (path=='/api/audit' and self._audit is not None)):
                from urllib.parse import parse_qs
                try:
                    query=environ.get('QUERY_STRING','')
                    if len(query)>128:raise ValueError('query too large')
                    fields=parse_qs(query,keep_blank_values=True,strict_parsing=True,max_num_fields=2)
                    if set(fields)-{'before','limit'} or any(len(value)!=1 for value in fields.values()):
                        raise ValueError('invalid pagination')
                    values={}
                    for name,entries in fields.items():
                        value=entries[0]
                        if not value.isascii() or not value.isdecimal() or len(value)>19:raise ValueError('invalid pagination')
                        values[name]=int(value)
                    read=self._audit.list_events if path=='/api/audit' else self._policies.list_versions
                    return respond('200 OK',read(user_id,**values))
                except PermissionError:return respond('403 Forbidden',{'error':'permission denied'})
                except ValueError:return respond('400 Bad Request',{'error':'invalid pagination'})
            if method=='GET' and self._simulation is not None and path.startswith('/api/policies/'):
                parts=path.split('/')
                if len(parts) in (5,6) and parts[4]=='simulation-records':
                    from urllib.parse import parse_qs
                    try:
                        query=environ.get('QUERY_STRING','')
                        if len(query)>128:raise ValueError('query too large')
                        if len(parts)==6:
                            if query:raise ValueError('unexpected detail query')
                            result=self._simulation.inspect_record(parts[3],user_id,parts[5])
                        else:
                            fields=parse_qs(query,keep_blank_values=True,strict_parsing=True,max_num_fields=2)
                            if set(fields)-{'before','limit'} or any(len(value)!=1 for value in fields.values()):
                                raise ValueError('invalid evidence pagination')
                            values={name:entries[0] for name,entries in fields.items()}
                            if 'limit' in values:
                                limit=values['limit']
                                if not limit.isascii() or not limit.isdecimal() or len(limit)>2:
                                    raise ValueError('invalid evidence page limit')
                                values['limit']=int(limit)
                            if 'before' in values and not values['before']:
                                raise ValueError('empty evidence cursor')
                            result=self._simulation.list_records(parts[3],user_id,**values)
                        if result is None:return respond('404 Not Found',{'error':'not found'})
                        return respond('200 OK',result)
                    except PermissionError:return respond('403 Forbidden',{'error':'permission denied'})
                    except ValueError:return respond('400 Bad Request',{'error':'invalid evidence request'})
            if method == "GET" and self._policies is not None and path.startswith("/api/policies/"):
                parts=path.split("/")
                if len(parts)!=4:return respond("404 Not Found",{"error":"not found"})
                try:
                    policy=self._policies.inspect(parts[3],user_id)
                    if policy is None:return respond("404 Not Found",{"error":"not found"})
                    return respond("200 OK",policy)
                except PermissionError:
                    return respond("403 Forbidden",{"error":"permission denied"})
                except ValueError:
                    return respond("400 Bad Request",{"error":"invalid policy request"})
            if method == "POST" and self._policies is not None and (path == "/api/policies" or path.startswith("/api/policies/")):
                if environ.get("CONTENT_TYPE") != "application/json":
                    return respond("415 Unsupported Media Type", {"error": "JSON required"})
                try:
                    length = int(environ.get("CONTENT_LENGTH", ""))
                    if not 1 <= length <= 65536:
                        raise ValueError("invalid body size")
                    raw = environ["wsgi.input"].read(length)
                    if len(raw) != length:
                        raise ValueError("incomplete body")
                    def unique(pairs):
                        result = {}
                        for key,value in pairs:
                            if key in result: raise ValueError("duplicate field")
                            result[key]=value
                        return result
                    payload = json.loads(raw,object_pairs_hook=unique)
                    if not isinstance(payload,dict): raise ValueError("object required")
                    if path == "/api/policies":
                        if set(payload) != {"rules"}: raise ValueError("invalid draft schema")
                        version=self._policies.draft(user_id,payload["rules"])
                        return respond("201 Created", {"version_id":version})
                    parts=path.split("/")
                    if len(parts)==7 and parts[4]=='simulation-records' and parts[6]=='verify' and self._simulation is not None:
                        if set(payload)!={'samples'} or environ.get('QUERY_STRING',''):
                            raise ValueError('simulation samples required')
                        result=self._simulation.verify_record(parts[3],user_id,parts[5],payload['samples'])
                        return respond('404 Not Found',{'error':'not found'}) if result is None else respond('200 OK',result)
                    if len(parts)!=5: raise ValueError("invalid policy route")
                    version,action=parts[3:]
                    if action=='simulate' and self._simulation is not None:
                        if set(payload)!={'samples'}:raise ValueError('simulation samples required')
                        return respond('200 OK',self._simulation.compare(version,user_id,payload['samples']))
                    if action=='simulation-records' and self._simulation is not None:
                        if set(payload)!={'samples'}:raise ValueError('simulation samples required')
                        return respond('201 Created',self._simulation.record(version,user_id,payload['samples']))
                    if action == "test":
                        if set(payload)!={"cases"}: raise ValueError("test cases required")
                        report=self._policies.test_version(version,user_id,payload["cases"])
                        return respond("200 OK", {"total":report.total,"rules_digest":report.rules_digest,"cases_digest":report.cases_digest})
                    if payload: raise ValueError("empty transition object required")
                    if action=='discard':
                        self._policies.discard(version,user_id)
                        return respond('200 OK',{'status':'committed'})
                    if action == "rollback":
                        return respond("201 Created", {"version_id":self._policies.rollback_draft(version,user_id)})
                    if action not in ("submit","approve","activate"): raise ValueError("unsupported action")
                    self._policies.transition(version,user_id,action)
                    return respond("200 OK", {"status":"committed"})
                except PermissionError:
                    return respond("403 Forbidden", {"error":"permission denied"})
                except (ValueError,KeyError,UnicodeError):
                    return respond("400 Bad Request", {"error":"invalid policy request"})
            if path == "/api/logout" and method == "POST":
                self._sessions.revoke(token)
                self._record_web_access(environ,'web.logout','success',actor=user_id)
                return respond("200 OK", {"status": "logged_out"}, [("Set-Cookie",
                    f"{COOKIE_NAME}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0")])
            return respond("404 Not Found", {"error": "not found"})
        except Exception:
            # Never return exception text, DB diagnostics or bearer credentials.
            return respond("503 Service Unavailable", {"error": "service unavailable"})
