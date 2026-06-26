"""Parse NetSarang's proprietary `NSSSH PRIVATE KEY` (nsssh-key-v6) format and
convert it into a standard PKCS#1 PEM private key that OpenSSH can use directly.

The file looks like:

    ---- BEGIN NSSSH PRIVATE KEY ----
    Comment: ...
    Key: 7, ssh-rsa
    <base64 block 1: standard ssh-rsa public key blob>
    <base64 block 2: nsssh-key-v6 private key container>
    ---- END NSSSH PRIVATE KEY ----

There is no blank line between the two base64 blocks; they are concatenated.
Block 1 ends with base64 padding (`=`), which is used to split them. Block 2's
structure mirrors OpenSSH's openssh-key-v1:

    magic        : "nsssh-key-v6\\0"   (13 bytes, NOT length-prefixed)
    cipher       : string  (only "none", i.e. unencrypted, is supported here)
    kdf          : string  ("none")
    kdfoptions   : string
    numkeys      : uint32
    privsection  : string  ->  uint32 check x2 (equal) + p + q + d + iqmp + comment + padding

Verified against a real sample: fields = [p, q, d, iqmp], satisfying p*q==n and
(e*d) mod lcm(p-1,q-1) == 1. We compute iqmp ourselves via pow(q,-1,p) rather than
trusting the stored value.
"""
from __future__ import annotations

import base64
import re
import struct
from dataclasses import dataclass


class KeyConversionError(Exception):
    pass


@dataclass
class RSAKey:
    n: int
    e: int
    d: int
    p: int
    q: int
    comment: str = ""

    def to_pem_pkcs1(self) -> str:
        """Emit a traditional PKCS#1 `BEGIN RSA PRIVATE KEY` PEM (usable by OpenSSH)."""
        p, q = self.p, self.q
        # PKCS#1 convention: coefficient = q^{-1} mod p
        try:
            iqmp = pow(q, -1, p)
        except ValueError:
            p, q = q, p
            iqmp = pow(q, -1, p)
        exp1 = self.d % (p - 1)
        exp2 = self.d % (q - 1)
        seq = b"".join(_der_int(x) for x in
                       (0, self.n, self.e, self.d, p, q, exp1, exp2, iqmp))
        der = _der_seq(seq)
        return _pem("RSA PRIVATE KEY", der)


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der_int(value: int) -> bytes:
    if value == 0:
        body = b"\x00"
    else:
        body = value.to_bytes((value.bit_length() + 7) // 8 + 1, "big")
        # Strip excess leading zeros, but keep one to stay positive (when MSB is set)
        while len(body) > 1 and body[0] == 0 and body[1] < 0x80:
            body = body[1:]
    return b"\x02" + _der_len(len(body)) + body


def _der_seq(content: bytes) -> bytes:
    return b"\x30" + _der_len(len(content)) + content


def _pem(label: str, der: bytes) -> str:
    b64 = base64.encodebytes(der).decode().replace("\n", "")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


def _read_str(buf: bytes, off: int) -> tuple[bytes, int]:
    (n,) = struct.unpack(">I", buf[off:off + 4])
    off += 4
    return buf[off:off + n], off + n


def _split_blocks(text: str) -> tuple[bytes, bytes]:
    """Extract and split the public/private base64 blocks from .pri text."""
    body = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("----"):
            continue
        # Skip header lines like "Comment:", "Key:", "Subject:"
        if re.match(r"^[A-Za-z][A-Za-z0-9]*\s*:", s):
            continue
        body.append(s)
    blob = "".join(body)
    m = re.search(r"=+", blob)
    if not m:
        raise KeyConversionError("Could not find public/private block boundary (no base64 padding)")
    pub = base64.b64decode(blob[:m.end()])
    priv = base64.b64decode(blob[m.end():])
    return pub, priv


def parse_nsssh_private_key(text: str) -> RSAKey:
    """Parse NSSSH private key text into an RSAKey. Only unencrypted ssh-rsa is supported."""
    pub, priv = _split_blocks(text)

    ktype, o = _read_str(pub, 0)
    if ktype != b"ssh-rsa":
        raise KeyConversionError(f"Unsupported key type: {ktype!r} (only ssh-rsa is supported)")
    e_b, o = _read_str(pub, o)
    n_b, o = _read_str(pub, o)
    e = int.from_bytes(e_b, "big")
    n = int.from_bytes(n_b, "big")

    if priv[:12] != b"nsssh-key-v6":
        raise KeyConversionError(f"Unknown private key container magic: {priv[:12]!r}")
    o = 13  # skip "nsssh-key-v6\0"
    cipher, o = _read_str(priv, o)
    kdf, o = _read_str(priv, o)
    _kdfopts, o = _read_str(priv, o)
    if cipher != b"none" or kdf != b"none":
        raise KeyConversionError(
            f"Private key is passphrase-encrypted (cipher={cipher!r}, kdf={kdf!r}); "
            "decryption is not supported yet")
    o += 4  # numkeys
    section, _ = _read_str(priv, o)

    check1, check2 = struct.unpack(">II", section[:8])
    if check1 != check2:
        raise KeyConversionError("Private key check fields mismatch; file may be corrupted")
    po = 8
    fields: list[bytes] = []
    while po + 4 <= len(section):
        (ln,) = struct.unpack(">I", section[po:po + 4])
        if ln == 0 or po + 4 + ln > len(section):
            break
        fields.append(section[po + 4:po + 4 + ln])
        po += 4 + ln
    if len(fields) < 3:
        raise KeyConversionError("Not enough private key fields to reconstruct RSA parameters")

    p = int.from_bytes(fields[0], "big")
    q = int.from_bytes(fields[1], "big")
    d = int.from_bytes(fields[2], "big")
    comment = ""
    if len(fields) >= 5:
        try:
            comment = fields[4].decode()
        except UnicodeDecodeError:
            comment = fields[4].decode("latin-1")

    if p * q != n:
        raise KeyConversionError("p*q != n; RSA parameter reconstruction failed")

    return RSAKey(n=n, e=e, d=d, p=p, q=q, comment=comment)


def convert_to_openssh_pem(pri_text: str) -> tuple[str, str]:
    """Convenience wrapper: NSSSH private key text -> (PEM string, comment)."""
    key = parse_nsssh_private_key(pri_text)
    return key.to_pem_pkcs1(), key.comment
