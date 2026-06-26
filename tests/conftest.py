"""Common pytest fixtures.

Everything here is synthetic so the test suite needs no real (sensitive) .xts file.
The RSA key parameters below come from a throwaway 1024-bit key generated with
``openssl genrsa`` (satisfies p*q==n); they are NOT secret.
"""
from __future__ import annotations

import base64
import struct
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

# --- throwaway RSA key (NOT secret; for tests only) ---------------------------
_RSA_N = 152833839755140675922376990367680754380360970113214392663203669732308657782444749890130147728129881059242457727049835273833826082334326612972127150842617374313936328034203174071998482484870648514392880918620031892294738505474100311446242759180114776906612594139184491825577058777166160709496274364374088263227  # noqa: E501
_RSA_E = 65537
_RSA_D = 74361240952014445780808323418133820817653695683355468496445907147933627885146035670637655379508941778477260929588447707046999592404209419226425049344927894541945950391629183584476789161324399975347700111786953211877966751112806120445163888161357939237302189164836331505188428849564876870404752697827812120369  # noqa: E501
_RSA_P = 13211832071080931492177802054172267665816022780397488774975674122803395849287878234737894315453108805342138530310950009437621562524820006973287945317929193  # noqa: E501
_RSA_Q = 11567952039723171584532392077597085147806898271179199386478923550849076087925264163014278839896325951211253770539960601206581829579519943207760734558807939  # noqa: E501

_MASTER_PASSWORD = "test-master-pw"


def _ssh_string(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def _ssh_mpint(value: int) -> bytes:
    blob = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if blob[0] & 0x80:  # keep positive
        blob = b"\x00" + blob
    return _ssh_string(blob)


def _rsa_pub_blob() -> bytes:
    return _ssh_string(b"ssh-rsa") + _ssh_mpint(_RSA_E) + _ssh_mpint(_RSA_N)


def _make_nsssh_private_key(comment: str = "test-key") -> str:
    """Build a valid, unencrypted nsssh-key-v6 NSSSH PRIVATE KEY text."""
    iqmp = pow(_RSA_Q, -1, _RSA_P)
    section = struct.pack(">II", 0x01020304, 0x01020304)  # two equal check ints
    for value in (_RSA_P, _RSA_Q, _RSA_D, iqmp):
        section += _ssh_mpint(value)
    section += _ssh_string(comment.encode())
    pad = bytearray()
    i = 1
    while (len(section) + len(pad)) % 8 != 0:
        pad.append(i)
        i += 1
    section += bytes(pad)

    priv = b"nsssh-key-v6\x00"
    priv += _ssh_string(b"none") + _ssh_string(b"none") + _ssh_string(b"")
    priv += struct.pack(">I", 1)
    priv += _ssh_string(bytes(section))

    pub_b64 = base64.b64encode(_rsa_pub_blob()).decode()
    priv_b64 = base64.b64encode(priv).decode()

    def wrap(b64: str) -> str:
        return "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))

    return ("---- BEGIN NSSSH PRIVATE KEY ----\n"
            f"Comment: {comment}\n"
            "Key: 7, ssh-rsa\n"
            f"{wrap(pub_b64)}\n{wrap(priv_b64)}\n"
            "---- END NSSSH PRIVATE KEY ----\n")


# Throwaway Ed25519 material (NOT a real keypair; only exercises the wrapping path).
_ED_PUB = bytes(range(32))
_ED_PRIV = _ED_PUB * 2  # 64 bytes = seed || public, as openssh stores it


def _ed25519_pub_blob() -> bytes:
    return _ssh_string(b"ssh-ed25519") + _ssh_string(_ED_PUB)


def _make_nsssh_ed25519_key(comment: str = "ed-key") -> str:
    """Build an unencrypted nsssh-key-v6 ssh-ed25519 key (public block has no '=')."""
    section = struct.pack(">II", 0x0A0B0C0D, 0x0A0B0C0D)
    section += _ssh_string(_ED_PRIV)
    section += _ssh_string(comment.encode())
    i = 1
    while len(section) % 8 != 0:
        section += bytes([i])
        i += 1
    priv = (b"nsssh-key-v6\x00"
            + _ssh_string(b"none") + _ssh_string(b"none") + _ssh_string(b"")
            + struct.pack(">I", 1) + _ssh_string(section))
    blob = base64.b64encode(_ed25519_pub_blob()).decode() + base64.b64encode(priv).decode()

    def wrap(b64: str) -> str:
        return "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))

    return ("---- BEGIN NSSSH PRIVATE KEY ----\n"
            f"Comment: {comment}\n"
            "Key: 2, ssh-ed25519\n"
            f"{wrap(blob)}\n"
            "---- END NSSSH PRIVATE KEY ----\n")


def _make_host_key_pub() -> str:
    b64 = base64.b64encode(_rsa_pub_blob()).decode()
    body = "\n".join(b64[i:i + 70] for i in range(0, len(b64), 70))
    return ("---- BEGIN SSH2 PUBLIC KEY ----\n"
            'Comment: "test host key"\n'
            f"{body}\n"
            "---- END SSH2 PUBLIC KEY ----\n")


def _xsh(host: str, port: str, user: str, *, user_key: str = "mykey",
         proxy: str = "", forwards: tuple = (), password_b64: str = "") -> str:
    fwd = [f"FwdReqCount={len(forwards)}"]
    for i, (kind, bind, bport, dhost, dport) in enumerate(forwards):
        incoming = "1" if kind == "remote" else "0"
        fwd += [f"FwdReq_{i}_Incoming={incoming}", f"FwdReq_{i}_Source={bind}",
                f"FwdReq_{i}_Port={bport}", f"FwdReq_{i}_Host={dhost}",
                f"FwdReq_{i}_HostPort={dport}", f"FwdReq_{i}_LocalOnly=1"]
    return (
        "[SessionInfo]\nVersion=8.1\n"
        "[CONNECTION]\n"
        f"Host={host}\nPort={port}\nProtocol=SSH\n"
        "[CONNECTION:PROXY]\n"
        f"Proxy={proxy}\n"
        "[CONNECTION:SSH]\n"
        "AgentForwarding=0\nCompression=0\nForwardX11=0\n" + "\n".join(fwd) + "\n"
        "[CONNECTION:AUTHENTICATION]\n"
        f"UserName={user}\nUserKey={user_key}\nAuthMethodList=00,11,20,30\n"
        f"Password={password_b64}\nPassphrase=\n"
    )


@pytest.fixture
def master_password() -> str:
    return _MASTER_PASSWORD


@pytest.fixture
def rsa_params() -> dict[str, int]:
    return {"n": _RSA_N, "e": _RSA_E, "d": _RSA_D, "p": _RSA_P, "q": _RSA_Q}


@pytest.fixture
def make_nsssh_key() -> Callable[[str], str]:
    """Return a factory that builds NSSSH private key text with a given comment."""
    return _make_nsssh_private_key


@pytest.fixture
def nsssh_key() -> str:
    return _make_nsssh_private_key()


@pytest.fixture
def nsssh_ed25519_key() -> str:
    return _make_nsssh_ed25519_key()


@pytest.fixture
def ed25519_material() -> tuple[bytes, bytes]:
    return _ED_PUB, _ED_PRIV


@pytest.fixture
def xts_path(tmp_path: Path) -> str:
    """Create a synthetic .xts backup and return its path."""
    from xts_utils.core.crypto import encrypt_password

    path = tmp_path / "backup.xts"
    pwd = encrypt_password("s3cret", 8.1, master_password=_MASTER_PASSWORD)
    proxy_ini = (
        "[SECTION]\nTYPE=5\nHOST=\nPORT=22\nUSERNAME=\n"
        r"SESSION=D:\Sessions\web.xsh" "\nJUMPHOST=\n"
    )
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("xts.zcf", "[SessionInfo]\nVersion=6.0\nClear=0\nMaster=1\n")
        z.writestr("Xshell/web.xsh",
                   _xsh("example.com", "2222", "alice",
                        forwards=[("local", "localhost", "8080", "localhost", "80")]))
        z.writestr("Xshell/group/db.xsh",
                   _xsh("10.0.0.5", "22", "bob", proxy="jumpproxy", password_b64=pwd))
        z.writestr("com/SECSH/UserKeys/mykey.pri", _make_nsssh_private_key("mykey"))
        z.writestr("com/Common/Proxy/jumpproxy.ini", proxy_ini)
        z.writestr("com/SECSH/HostKeys/key_example.com_2222.pub", _make_host_key_pub())
    return str(path)
