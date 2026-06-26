"""xts core: read and decrypt an Xshell ``.xts`` backup into in-memory structures.

:func:`load_backup` returns a :class:`Backup` (the parsed ``.xts``); each target
format (ssh config today, others later) converts to/from it.
"""
from .container import (
    Backup,
    Forward,
    HostKey,
    Proxy,
    Session,
    UserKey,
    load_backup,
)
from .crypto import decrypt_password, encrypt_password, xts_decrypt_field
from .hostkeys import known_hosts_line
from .rsakey import (
    KeyConversionError,
    RSAKey,
    convert_to_openssh_pem,
    parse_nsssh_private_key,
)

__all__ = [
    "Backup", "Forward", "HostKey", "Proxy", "Session", "UserKey", "load_backup",
    "decrypt_password", "encrypt_password", "xts_decrypt_field",
    "known_hosts_line",
    "KeyConversionError", "RSAKey", "convert_to_openssh_pem", "parse_nsssh_private_key",
]
