import pytest

from xts_utils.core.container import load_backup

pytestmark = pytest.mark.container


def test_load_backup_basic(xts_path):
    b = load_backup(xts_path)
    assert b.container_version == "6.0"
    assert b.master_protected is True
    assert len(b.sessions) == 2
    assert "mykey" in b.user_keys
    assert "jumpproxy" in b.proxies
    assert len(b.host_keys) == 1


def test_directory_structure_preserved(xts_path):
    b = load_backup(xts_path)
    by_name = {s.name: s for s in b.sessions}
    assert by_name["web"].rel_dir == ""
    assert by_name["db"].rel_dir == "group"


def test_session_fields(xts_path):
    b = load_backup(xts_path)
    web = next(s for s in b.sessions if s.name == "web")
    assert web.host == "example.com"
    assert web.port == "2222"
    assert web.username == "alice"
    assert web.user_key == "mykey"
    assert web.uses_pubkey
    assert len(web.forwards) == 1
    fwd = web.forwards[0]
    assert fwd.kind == "local"
    assert (fwd.bind_port, fwd.dest_host, fwd.dest_port) == ("8080", "localhost", "80")


def test_jumphost_proxy_detected(xts_path):
    b = load_backup(xts_path)
    proxy = b.proxies["jumpproxy"]
    assert proxy.type == 5
    assert proxy.is_jumphost
