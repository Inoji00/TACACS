"""AAA routing boundary; protocol codecs remain independent of dependencies."""
from collections.abc import Callable

from .protocol import AUTHENTICATION, AUTHORIZATION, ACCOUNTING, Frame
from .authorization_handler import TacacsAuthorizationHandler
from .tacacs_handler import TacacsAuthenticationHandler

Handler = Callable[[str, Frame], bytes | None]


class TacacsRouter:
    def __init__(self, authentication: TacacsAuthenticationHandler,
                 authorization: Handler, accounting: Handler):
        self._authentication = authentication
        self._authorization = authorization
        self._accounting = accounting
        self.authorization_details = None

    def new_connection(self) -> "TacacsRouter":
        """Separate authentication challenges while sharing stateless services."""
        return TacacsRouter(self._authentication.new_connection(),
                            self._authorization, self._accounting)

    def authentication_username(self):
        """Username from START or a validated GETUSER response."""
        return self._authentication.attempted_username

    def authentication_remote_address(self):
        return self._authentication.remote_address

    def __call__(self, remote_ip: str, frame: Frame) -> bytes | None:
        self._authentication.attempted_username = None
        self._authentication.remote_address = None
        self.authorization_details = None
        if frame.header.sequence % 2 != 1:
            return None
        handler = {
            AUTHENTICATION: self._authentication,
            AUTHORIZATION: self._authorization,
            ACCOUNTING: self._accounting,
        }.get(frame.header.packet_type)
        if handler is None:
            return None
        if isinstance(handler, TacacsAuthorizationHandler):
            return handler.handle(remote_ip, frame, self._observe_authorization)
        return handler(remote_ip, frame)

    def _observe_authorization(self, details):
        self.authorization_details = details
