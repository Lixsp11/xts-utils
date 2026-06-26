import pytest

from xts_utils.core.crypto import decrypt_password, encrypt_password, rc4

pytestmark = pytest.mark.crypto


def test_rc4_is_involutive():
    key = b"some key"
    data = b"hello world, this is RC4"
    assert rc4(key, rc4(key, data)) == data


def test_master_password_roundtrip(master_password):
    enc = encrypt_password("hunter2", 8.1, master_password=master_password)
    assert decrypt_password(enc, 8.1, master_password=master_password) == "hunter2"


def test_wrong_master_password_returns_none(master_password):
    enc = encrypt_password("hunter2", 8.1, master_password=master_password)
    assert decrypt_password(enc, 8.1, master_password="wrong") is None


def test_empty_password(master_password):
    assert decrypt_password("", 8.1, master_password=master_password) == ""


def test_sid_username_roundtrip_no_master():
    enc = encrypt_password("pw", 6.0, username="Admin", sid="S-1-5-21-1-2-3")
    assert decrypt_password(enc, 6.0, username="Admin", sid="S-1-5-21-1-2-3") == "pw"
