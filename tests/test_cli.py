import os

import pytest

from xts_utils.cli import main

pytestmark = pytest.mark.cli


def test_list_command(xts_path, capsys):
    rc = main(["list", xts_path])
    assert rc == 0
    out = capsys.readouterr().out
    assert "sessions=2" in out
    assert "example.com" in out


def test_export_sshconfig_command(xts_path, tmp_path):
    out = tmp_path / "out"
    rc = main(["export", "sshconfig", xts_path, "-o", str(out)])
    assert rc == 0
    assert os.path.isfile(out / "config")
    assert os.path.isfile(out / "keys" / "mykey")


def test_dump_credentials_requires_master_password(xts_path, tmp_path):
    rc = main(["export", "sshconfig", xts_path, "-o", str(tmp_path / "o"), "--dump-credentials"])
    assert rc == 2


def test_dump_credentials_writes_file(xts_path, tmp_path, master_password):
    out = tmp_path / "out"
    rc = main(["export", "sshconfig", xts_path, "-o", str(out),
               "--dump-credentials", "--master-password", master_password])
    assert rc == 0
    cred = out / "credentials.txt"
    assert cred.is_file()
    assert "s3cret" in cred.read_text()


def test_no_command_returns_nonzero():
    assert main([]) == 1
