"""Xshell/Xmanager password cryptography primitives (pure Python, no third-party deps).

Based on the reverse-engineering results from
HyperSine/how-does-Xmanager-encrypt-password, and verified against a real
Xshell 8 backup (Version 8.1, master-password protected):

  ciphertext(base64) = RC4_decrypt(key, ciphertext) || SHA256(plaintext)[32 bytes]
  The key depends on the session version:
    < 5.1            : MD5("!X@s#h$e%l^l&")          (Xshell fixed key)
    5.1 ~ 5.2        : SHA256(SID)
    > 5.2 no master  : SHA256(UserName + SID)
    > 5.2 w/ master  : SHA256(master password)   <- Xshell 7/8 after setting a master password

For the UN/CN/SI fields inside the .xts container's xts.zcf, a fixed XFtp key
MD5("!X@s#c$e%l^l&") + RC4 is used, with a trailing 16-byte MD5 checksum.
"""
from __future__ import annotations

import base64
import hashlib


def rc4(key: bytes, data: bytes) -> bytes:
    """Standard RC4 stream cipher (same function encrypts and decrypts)."""
    s = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + s[i] + key[i % klen]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray(len(data))
    i = j = 0
    for n, b in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[n] = b ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


# Fixed key for the .xts container metadata fields (UN/CN/SI)
_XTS_KEY = hashlib.md5(b"!X@s#c$e%l^l&").digest()
# Fixed key for legacy Xshell versions (< 5.1)
_XSHELL_LEGACY_KEY = hashlib.md5(b"!X@s#h$e%l^l&").digest()


def session_key(version: float, *, sid: str = "", username: str = "",
                master_password: str = "") -> bytes:
    """Derive the RC4 key according to the session file version."""
    if version <= 0:
        raise ValueError(f"Invalid session version: {version}")
    if version < 5.1:
        return _XSHELL_LEGACY_KEY
    if version <= 5.2:
        return hashlib.sha256(sid.encode()).digest()
    # version > 5.2
    if master_password:
        return hashlib.sha256(master_password.encode()).digest()
    return hashlib.sha256((username + sid).encode()).digest()


def decrypt_password(b64: str, version: float, *, sid: str = "",
                     username: str = "", master_password: str = "") -> str | None:
    """Decrypt a Password/Passphrase field from a session file.

    Returns the plaintext; returns None if the checksum fails (wrong key, e.g.
    incorrect master password); returns "" for an empty input.
    """
    if not b64:
        return ""
    data = base64.b64decode(b64)
    key = session_key(version, sid=sid, username=username,
                      master_password=master_password)
    if version < 5.1:
        try:
            return rc4(key, data).decode()
        except UnicodeDecodeError:
            return None
    if len(data) < 32:
        return None
    ciphertext, checksum = data[:-32], data[-32:]
    plain = rc4(key, ciphertext)
    if hashlib.sha256(plain).digest() != checksum:
        return None
    try:
        return plain.decode()
    except UnicodeDecodeError:
        return plain.decode("latin-1")


def encrypt_password(plaintext: str, version: float, *, sid: str = "",
                     username: str = "", master_password: str = "") -> str:
    """Encrypt a password into the base64 form Xshell stores in session files.

    Inverse of :func:`decrypt_password`. Useful for the future "encode back to
    .xts" direction.
    """
    key = session_key(version, sid=sid, username=username,
                      master_password=master_password)
    raw = plaintext.encode()
    if version < 5.1:
        return base64.b64encode(rc4(key, raw)).decode()
    ciphertext = rc4(key, raw)
    checksum = hashlib.sha256(raw).digest()
    return base64.b64encode(ciphertext + checksum).decode()


def xts_decrypt_field(b64: str) -> str | None:
    """Decrypt a UN/CN/SI field from xts.zcf (fixed key + MD5 checksum)."""
    if not b64:
        return ""
    data = base64.b64decode(b64)
    if len(data) < 16:
        return None
    ciphertext, checksum = data[:-16], data[-16:]
    plain = rc4(_XTS_KEY, ciphertext)
    if hashlib.md5(plain).digest() != checksum:
        return None
    try:
        return plain.decode()
    except UnicodeDecodeError:
        return plain.decode("latin-1")
