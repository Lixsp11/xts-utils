import base64

import pytest

from xts_utils.core.rsakey import (
    KeyConversionError,
    convert_to_openssh_pem,
    parse_nsssh_private_key,
)

pytestmark = pytest.mark.rsakey


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


def test_malformed_key_raises():
    with pytest.raises(KeyConversionError):
        parse_nsssh_private_key(
            "---- BEGIN NSSSH PRIVATE KEY ----\nKey: 7, ssh-rsa\n"
            "QUJD\nWFla\n---- END NSSSH PRIVATE KEY ----\n")
