"""RFC4716 (`---- BEGIN SSH2 PUBLIC KEY ----`) public key -> OpenSSH known_hosts line."""
from __future__ import annotations

import base64
import struct

from .container import HostKey


def _rfc4716_to_blob(text: str) -> bytes:
    body = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("----"):
            continue
        if ":" in s and not s.endswith("="):  # header line (Comment:, Subject:, etc.)
            # RFC4716 header lines may continue with a backslash; just skip
            # lines containing a colon that are not pure base64.
            if all(c.isalnum() or c in "+/=" for c in s):
                body.append(s)
            continue
        body.append(s)
    return base64.b64decode("".join(body))


def _keytype(blob: bytes) -> str:
    (n,) = struct.unpack(">I", blob[:4])
    return blob[4:4 + n].decode("ascii", "replace")


def known_hosts_line(hk: HostKey) -> str | None:
    """Build a single known_hosts record; returns None on failure."""
    try:
        blob = _rfc4716_to_blob(hk.text)
        ktype = _keytype(blob)
        b64 = base64.b64encode(blob).decode()
    except Exception:
        return None
    host = hk.host
    if hk.port and hk.port not in ("22", ""):
        host = f"[{hk.host}]:{hk.port}"
    return f"{host} {ktype} {b64}"
