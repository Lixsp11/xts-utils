import os

import pytest

from xts_utils.core.container import Backup, Session, load_backup
from xts_utils.sshconfig.exporter import export_backup
from xts_utils.sshconfig.render import build_alias_map, host_alias, render_session

pytestmark = pytest.mark.sshconfig


def test_aliases_are_slash_free(xts_path):
    b = load_backup(xts_path)
    amap = build_alias_map(b.sessions)
    for alias in amap.values():
        assert "/" not in alias


def test_render_session_reproduces_settings(xts_path):
    b = load_backup(xts_path)
    amap = build_alias_map(b.sessions)
    web = next(s for s in b.sessions if s.name == "web")
    text = render_session(web, b, amap, key_dir="~/.ssh/xts/keys")
    assert "HostName example.com" in text
    assert "Port 2222" in text
    assert "User alice" in text
    assert "IdentityFile ~/.ssh/xts/keys/mykey" in text
    assert "LocalForward 8080 localhost:80" in text


def test_jumphost_becomes_proxyjump(xts_path):
    b = load_backup(xts_path)
    amap = build_alias_map(b.sessions)
    db = next(s for s in b.sessions if s.name == "db")
    text = render_session(db, b, amap)
    # jumpproxy references the "web" session -> ProxyJump to web's alias
    assert f"ProxyJump {host_alias(next(s for s in b.sessions if s.name == 'web'), amap)}" in text


def test_export_backup_writes_tree(xts_path, tmp_path):
    b = load_backup(xts_path)
    out = tmp_path / "out"
    result = export_backup(b, str(out))
    assert os.path.isfile(out / "config")
    assert os.path.isfile(out / "conf.d" / "web.conf")
    assert os.path.isfile(out / "conf.d" / "group" / "db.conf")
    assert os.path.isfile(out / "keys" / "mykey")  # key installed under <base>/keys
    assert result.keys_converted == 1
    assert result.sessions == 2
    assert "Include" in (out / "config").read_text()


def test_unresolved_proxy_is_flagged_not_dropped(tmp_path):
    s = Session(rel_dir="", name="srv", host="10.0.0.9", username="root",
                proxy_name="Clash")  # proxy 'Clash' has no definition in the backup
    b = Backup(sessions=[s], proxies={}, user_keys={}, host_keys=[])
    amap = build_alias_map(b.sessions)

    text = render_session(s, b, amap)
    assert "Clash" in text and "set ProxyJump/ProxyCommand manually" in text

    result = export_backup(b, str(tmp_path / "o"))
    assert any("Clash" in w for w in result.warnings)


def test_unconverted_key_is_flagged(tmp_path):
    s = Session(rel_dir="", name="srv", host="10.0.0.9", username="root", user_key="ghost")
    b = Backup(sessions=[s], proxies={}, user_keys={}, host_keys=[])
    amap = build_alias_map(b.sessions)
    # 'ghost' is referenced but absent from converted_keys -> IdentityFile flagged
    text = render_session(s, b, amap, converted_keys=set())
    assert "could not be converted" in text
    assert "IdentityFile" in text


def test_export_credentials_requires_master_password(xts_path, tmp_path):
    b = load_backup(xts_path)
    with pytest.raises(ValueError):
        export_backup(b, str(tmp_path / "o"), dump_credentials=True, master_password=None)
