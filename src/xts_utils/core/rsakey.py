"""Parse NetSarang's proprietary `NSSSH PRIVATE KEY` (nsssh-key-v6) format and
convert it into a private key OpenSSH can use directly: PKCS#1 PEM for RSA,
``openssh-key-v1`` PEM for Ed25519.

The file looks like:

    ---- BEGIN NSSSH PRIVATE KEY ----
    Comment: ...
    Key: 7, ssh-rsa
    <base64 block 1: standard ssh public key blob>
    <base64 block 2: nsssh-key-v6 private key container>
    ---- END NSSSH PRIVATE KEY ----

There is no blank line between the two base64 blocks; they are concatenated.
Each block is independently base64-padded to a 4-char boundary, so block 2 always
begins at a multiple-of-4 offset -- we locate it by scanning those offsets for the
one whose bytes start with the ``nsssh-key-v6`` magic (splitting on ``=`` padding
fails for e.g. Ed25519, whose 51-byte public block needs no padding).

Block 2 mirrors OpenSSH's openssh-key-v1, but its private section stores only the
secret scalars (no key-type tag, no redundant public fields):

    magic        : "nsssh-key-v6\\0"   (13 bytes, NOT length-prefixed)
    cipher       : string  (only "none", i.e. unencrypted, is supported here)
    kdf          : string  ("none")
    kdfoptions   : string
    numkeys      : uint32
    privsection  : string  ->  uint32 check x2 (equal) + <secret fields> + comment + padding
        ssh-rsa     : fields = [p, q, d, iqmp]   (p*q == n; iqmp recomputed via pow(q,-1,p))
        ssh-ed25519 : fields = [priv64]          (32-byte seed || 32-byte public key)
"""
from __future__ import annotations

import base64
import re
import struct
from dataclasses import dataclass

_NSSSH_MAGIC = b"nsssh-key-v6"


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


def _ssh_string(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def _read_str(buf: bytes, off: int) -> tuple[bytes, int]:
    (n,) = struct.unpack(">I", buf[off:off + 4])
    off += 4
    return buf[off:off + n], off + n


def _split_blocks(text: str) -> tuple[bytes, bytes]:
    """Extract and split the public/private base64 blocks from .pri text.

    Returns (public-key blob, nsssh-key-v6 private container).
    """
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
    # Block 2 starts at a multiple-of-4 offset; find the one beginning with the magic.
    for i in range(4, len(blob) + 1, 4):
        try:
            tail = base64.b64decode(blob[i:])
        except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
            continue
        if tail[:len(_NSSSH_MAGIC)] == _NSSSH_MAGIC:
            try:
                pub = base64.b64decode(blob[:i])
            except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
                continue
            return pub, tail
    raise KeyConversionError("Could not locate the nsssh-key-v6 private block")


def _private_section(priv: bytes) -> bytes:
    """Validate the container header and return the (unencrypted) private section."""
    if priv[:len(_NSSSH_MAGIC)] != _NSSSH_MAGIC:
        raise KeyConversionError(f"Unknown private key container magic: {priv[:12]!r}")
    o = len(_NSSSH_MAGIC) + 1  # skip "nsssh-key-v6\0"
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
    return section


def _section_fields(section: bytes) -> list[bytes]:
    """Read the length-prefixed secret fields after the 8-byte check header."""
    po = 8
    fields: list[bytes] = []
    while po + 4 <= len(section):
        (ln,) = struct.unpack(">I", section[po:po + 4])
        if ln == 0 or po + 4 + ln > len(section):
            break
        fields.append(section[po + 4:po + 4 + ln])
        po += 4 + ln
    return fields


def _decode_comment(raw: bytes) -> str:
    try:
        return raw.decode()
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def parse_nsssh_private_key(text: str) -> RSAKey:
    """Parse an NSSSH **ssh-rsa** private key into an RSAKey. Unencrypted only."""
    pub, priv = _split_blocks(text)

    ktype, o = _read_str(pub, 0)
    if ktype != b"ssh-rsa":
        raise KeyConversionError(f"Unsupported key type: {ktype!r} (only ssh-rsa is supported here)")
    e_b, o = _read_str(pub, o)
    n_b, o = _read_str(pub, o)
    e = int.from_bytes(e_b, "big")
    n = int.from_bytes(n_b, "big")

    fields = _section_fields(_private_section(priv))
    if len(fields) < 3:
        raise KeyConversionError("Not enough private key fields to reconstruct RSA parameters")
    p = int.from_bytes(fields[0], "big")
    q = int.from_bytes(fields[1], "big")
    d = int.from_bytes(fields[2], "big")
    comment = _decode_comment(fields[4]) if len(fields) >= 5 else ""

    if p * q != n:
        raise KeyConversionError("p*q != n; RSA parameter reconstruction failed")

    return RSAKey(n=n, e=e, d=d, p=p, q=q, comment=comment)


def _openssh_key_v1_pem(pub_blob: bytes, priv_entry: bytes, comment: bytes) -> str:
    """Wrap one unencrypted key into an ``openssh-key-v1`` PEM.

    ``priv_entry`` is the per-key private body (key-type + public + private parts);
    the check ints, comment and block padding are added here.
    """
    check = 0x6E737368  # "nssh" -- deterministic so output is reproducible
    section = struct.pack(">II", check, check) + priv_entry + _ssh_string(comment)
    pad = 1
    while len(section) % 8 != 0:  # cipher "none" -> 8-byte block
        section += bytes([pad & 0xFF])
        pad += 1
    body = (b"openssh-key-v1\0"
            + _ssh_string(b"none")        # ciphername
            + _ssh_string(b"none")        # kdfname
            + _ssh_string(b"")            # kdfoptions
            + struct.pack(">I", 1)        # numkeys
            + _ssh_string(pub_blob)
            + _ssh_string(section))
    return _pem("OPENSSH PRIVATE KEY", body)


def _generic_to_openssh(pub_blob: bytes, priv: bytes) -> tuple[str, str]:
    """Convert any non-RSA NSSSH key to an openssh-key-v1 PEM.

    For ed25519/ecdsa/dss the openssh private entry is simply the public blob
    followed by the secret scalar(s); the public parameters are already carried
    by ``pub_blob``. nsssh stores those secrets (then the comment) in the same
    order, so wrapping is uniform. Verified against ssh-ed25519; ecdsa/dss follow
    the same openssh-key-v1 layout but are best-effort (no sample to validate).
    """
    fields = _section_fields(_private_section(priv))
    if not fields:
        raise KeyConversionError("No private fields found in the key container")
    if len(fields) >= 2:
        *secrets, comment = fields
    else:
        secrets, comment = fields, b""
    priv_entry = pub_blob + b"".join(_ssh_string(f) for f in secrets)
    return _openssh_key_v1_pem(pub_blob, priv_entry, comment), _decode_comment(comment)


def convert_to_openssh_pem(pri_text: str) -> tuple[str, str]:
    """NSSSH private key text -> (PEM string, comment).

    ssh-rsa is emitted as PKCS#1; every other type (ed25519, ecdsa, dss, ...) goes
    through the generic openssh-key-v1 path. Only unencrypted keys are supported.
    """
    pub, priv = _split_blocks(pri_text)
    ktype, _ = _read_str(pub, 0)
    if ktype == b"ssh-rsa":
        key = parse_nsssh_private_key(pri_text)
        return key.to_pem_pkcs1(), key.comment
    return _generic_to_openssh(pub, priv)
