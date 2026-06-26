import base64
import struct

import pytest

from xts_utils.core.rsakey import (
    KeyConversionError,
    convert_to_openssh_pem,
    parse_nsssh_private_key,
)

pytestmark = pytest.mark.rsakey


def _read_str(buf, off):
    (n,) = struct.unpack(">I", buf[off:off + 4])
    return buf[off + 4:off + 4 + n], off + 4 + n


def test_parse_recovers_rsa_parameters(make_nsssh_key, rsa_params):
    key = parse_nsssh_private_key(make_nsssh_key("k1"))
    assert key.n == rsa_params["n"]
    assert key.e == rsa_params["e"]
    assert key.d == rsa_params["d"]
    assert {key.p, key.q} == {rsa_params["p"], rsa_params["q"]}
    assert key.comment == "k1"
    assert key.p * key.q == key.n


def _der_first_two_ints(der: bytes):
    """Minimal DER reader: returns (version, modulus) from an RSAPrivateKey SEQUENCE."""
    assert der[0] == 0x30  # SEQUENCE
    i = 2
    if der[1] & 0x80:
        i = 2 + (der[1] & 0x7F)
    out = []
    for _ in range(2):
        assert der[i] == 0x02  # INTEGER
        ln = der[i + 1]
        j = i + 2
        if ln & 0x80:
            nbytes = ln & 0x7F
            ln = int.from_bytes(der[i + 2:i + 2 + nbytes], "big")
            j = i + 2 + nbytes
        out.append(int.from_bytes(der[j:j + ln], "big"))
        i = j + ln
    return out


def test_pem_is_valid_pkcs1(make_nsssh_key, rsa_params):
    pem, comment = convert_to_openssh_pem(make_nsssh_key("k2"))
    assert pem.startswith("-----BEGIN RSA PRIVATE KEY-----")
    assert pem.strip().endswith("-----END RSA PRIVATE KEY-----")
    assert comment == "k2"
    b64 = "".join(line for line in pem.splitlines() if not line.startswith("-----"))
    der = base64.b64decode(b64)
    version, modulus = _der_first_two_ints(der)
    assert version == 0
    assert modulus == rsa_params["n"]


def test_ed25519_emits_openssh_key_v1(nsssh_ed25519_key, ed25519_material):
    pub32, priv64 = ed25519_material
    pem, comment = convert_to_openssh_pem(nsssh_ed25519_key)
    assert pem.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert comment == "ed-key"

    b64 = "".join(line for line in pem.splitlines() if not line.startswith("-----"))
    blob = base64.b64decode(b64)
    assert blob[:15] == b"openssh-key-v1\0"
    o = 15
    cipher, o = _read_str(blob, o)
    kdf, o = _read_str(blob, o)
    _kdfopts, o = _read_str(blob, o)
    assert cipher == b"none" and kdf == b"none"
    (numkeys,) = struct.unpack(">I", blob[o:o + 4])
    o += 4
    assert numkeys == 1
    pubblob, o = _read_str(blob, o)
    section, o = _read_str(blob, o)

    # public blob carries the key type + 32-byte public key
    ktype, po = _read_str(pubblob, 0)
    pubkey, po = _read_str(pubblob, po)
    assert ktype == b"ssh-ed25519" and pubkey == pub32

    # private section: equal check ints, then key-type + pub32 + priv64 + comment
    c1, c2 = struct.unpack(">II", section[:8])
    assert c1 == c2
    so = 8
    ktype2, so = _read_str(section, so)
    spub, so = _read_str(section, so)
    spriv, so = _read_str(section, so)
    scomment, so = _read_str(section, so)
    assert ktype2 == b"ssh-ed25519" and spub == pub32
    assert spriv == priv64 and scomment == b"ed-key"


def test_ed25519_split_without_base64_padding(nsssh_ed25519_key):
    # The ed25519 public block is 51 bytes -> base64 has no '=' padding; the
    # block split must not rely on padding to find the boundary.
    assert "=" not in nsssh_ed25519_key.split("ssh-ed25519\n", 1)[1].split("----")[0].replace("\n", "")[:60]
    pem, _ = convert_to_openssh_pem(nsssh_ed25519_key)
    assert "OPENSSH PRIVATE KEY" in pem


def test_malformed_key_raises():
    with pytest.raises(KeyConversionError):
        parse_nsssh_private_key(
            "---- BEGIN NSSSH PRIVATE KEY ----\nKey: 7, ssh-rsa\n"
            "QUJD\nWFla\n---- END NSSSH PRIVATE KEY ----\n")
