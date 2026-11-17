"""Local administrator TLS context; no plaintext or auto-certificate fallback."""
from pathlib import Path
import os
import ssl
from .runtime import validate_secret_metadata


def create_admin_tls_context(cert_file: Path, key_file: Path, *, client_ca: Path | None = None,
                             key_password=None) -> ssl.SSLContext:
    if key_file.is_symlink() or cert_file.is_symlink() or (client_ca is not None and client_ca.is_symlink()):
        raise ValueError("TLS credential links unsupported")
    # Deploy on immutable operator-owned mounts to prevent path replacement
    # between the permission check and OpenSSL's certificate loading.
    with key_file.open("rb") as stream:
        validate_secret_metadata(os.fstat(stream.fileno()),posix=os.name!="nt",
                                 runtime_uid=os.geteuid() if hasattr(os,"geteuid") else None)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version=ssl.TLSVersion.TLSv1_3
    context.maximum_version=ssl.TLSVersion.TLSv1_3
    context.options |= ssl.OP_NO_TICKET
    context.num_tickets=0
    context.set_alpn_protocols(["http/1.1"])
    def no_prompt():
        raise ValueError("encrypted TLS key requires an explicit password resolver")
    context.load_cert_chain(str(cert_file),str(key_file),password=key_password or no_prompt)
    if client_ca is not None:
        context.load_verify_locations(cafile=str(client_ca))
        context.verify_mode=ssl.CERT_REQUIRED
    return context
