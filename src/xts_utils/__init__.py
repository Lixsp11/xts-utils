"""xts-utils -- a toolkit built around Xshell ``.xts`` backups.

The library is built around the ``.xts`` format: ``core`` parses a backup, and each
target format converts to/from it (``.xts`` -> ssh_config today). Pure standard
library, no third-party dependencies.
"""
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("xts-utils")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "0.0.0"

from .core import (
    Backup,
    HostKey,
    KeyConversionError,
    Proxy,
    Session,
    UserKey,
    convert_to_openssh_pem,
    decrypt_password,
    encrypt_password,
    load_backup,
)

__all__ = [
    "__version__",
    "Backup", "Session", "Proxy", "UserKey", "HostKey",
    "load_backup", "convert_to_openssh_pem", "decrypt_password", "encrypt_password",
    "KeyConversionError",
]
