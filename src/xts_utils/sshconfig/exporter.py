"""Orchestration: turn a parsed :class:`Backup` into an on-disk OpenSSH config tree.

Everything is written under a single base directory (default ``~/.ssh/xts``,
overridable with ``-o``)::

    <base>/config          top-level config (Includes conf.d/**)
    <base>/conf.d/...      one .conf per session, mirroring the Xshell group tree
    <base>/keys/...        private keys converted to OpenSSH PEM
    <base>/known_hosts
    <base>/credentials.txt (only when credentials are dumped)
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from ..core.container import Backup
from ..core.crypto import decrypt_password
from ..core.hostkeys import known_hosts_line
from ..core.rsakey import KeyConversionError, convert_to_openssh_pem
from .render import build_alias_map, host_alias, proxy_uses_netcat, quote_path, render_session

DEFAULT_HOME = "~/.ssh/xts"


@dataclass
class ExportResult:
    output_dir: str                  # filesystem base dir (expanded)
    config_path: str
    key_dir_filesystem: str          # where keys were actually written
    key_dir_in_config: str           # what IdentityFile references (verbatim)
    sessions: int = 0
    groups: int = 0
    keys_converted: int = 0
    keys_total: int = 0
    known_hosts_path: str | None = None
    credentials_path: str | None = None
    warnings: list[str] = field(default_factory=list)


def _write(path: str, content: str, mode: int | None = None) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    if mode is not None:
        _chmod(path, mode)


def _chmod(path: str, mode: int) -> None:
    """chmod that silently tolerates platforms without POSIX permissions (Windows)."""
    try:
        os.chmod(path, mode)
    except (OSError, NotImplementedError):
        pass


def _config_base(base_raw: str, base_fs: str) -> str:
    """The base path written into ``Include`` and ``IdentityFile`` entries.

    Keep a leading ``~`` (portable) verbatim; otherwise use the absolute path so
    the result is unambiguous regardless of the working directory. Always uses
    forward slashes -- OpenSSH (including Windows builds) accepts them, while a
    literal backslash would be parsed as an escape.
    """
    if base_raw.startswith("~"):
        return base_raw.replace("\\", "/").rstrip("/")
    return base_fs.replace("\\", "/").rstrip("/")


def install_keys(backup: Backup, key_dir_fs: str) -> tuple[dict[str, str], list[str]]:
    """Convert and write all user private keys into ``key_dir_fs``.

    Returns (name->path, warnings).
    """
    os.makedirs(key_dir_fs, exist_ok=True)
    _chmod(key_dir_fs, 0o700)
    written: dict[str, str] = {}
    warnings: list[str] = []
    for name, uk in sorted(backup.user_keys.items()):
        path = os.path.join(key_dir_fs, name)
        try:
            pem, _comment = convert_to_openssh_pem(uk.text)
        except KeyConversionError as exc:
            warnings.append(f"key {name} conversion failed: {exc} (saved as-is to {name}.nsssh)")
            _write(path + ".nsssh", uk.text)
            continue
        _write(path, pem, mode=0o600)
        written[name] = path
    return written, warnings


def _known_hosts_text(backup: Backup) -> str:
    lines = []
    for hk in backup.host_keys:
        if not hk.host:
            continue
        line = known_hosts_line(hk)
        if line:
            lines.append(line)
    return "\n".join(lines) + ("\n" if lines else "")


def _credentials_text(backup: Backup, master_password: str) -> str:
    out = ["# Plaintext credentials -- keep safe and delete promptly\n"]
    for s in backup.sessions:
        items = []
        for label, enc in (("Password", s.password_enc), ("Passphrase", s.passphrase_enc)):
            if not enc:
                continue
            val = decrypt_password(enc, s.version, master_password=master_password)
            if val is None:
                items.append(f"{label}=<decryption failed: master password may be wrong>")
            elif val:
                items.append(f"{label}={val}")
        if items:
            out.append(f"[{host_alias(s)}]  ({s.username}@{s.host}:{s.port})")
            out.extend("    " + it for it in items)
            out.append("")
    return "\n".join(out)


def export_backup(backup: Backup, output_dir: str = DEFAULT_HOME, *,
                  identities_only: bool = True,
                  dump_credentials: bool = False,
                  master_password: str | None = None) -> ExportResult:
    """Write the full ssh-config export tree under ``output_dir`` (default ``~/.ssh/xts``).

    Raises ValueError if ``dump_credentials`` is set without a master password.
    """
    if dump_credentials and not master_password:
        raise ValueError("dump_credentials requires a master password")

    base_raw = output_dir or DEFAULT_HOME
    base_fs = os.path.abspath(os.path.expanduser(base_raw))
    os.makedirs(base_fs, exist_ok=True)

    cfg_base = _config_base(base_raw, base_fs)
    key_dir_fs = os.path.join(base_fs, "keys")
    cfg_key_dir = cfg_base + "/keys"
    written_keys, warnings = install_keys(backup, key_dir_fs)

    converted = set(written_keys)
    windows = os.name == "nt"
    needs_netcat = False
    for s in backup.sessions:
        p = backup.proxy_for(s)
        if s.proxy_name and p is None:
            warnings.append(f"session '{s.name}' references proxy '{s.proxy_name}', which is not "
                            "in the backup; its proxy was omitted (set ProxyJump/ProxyCommand manually)")
        elif p and not p.is_jumphost and not proxy_uses_netcat(p) and (p.host or p.session_ref):
            warnings.append(f"session '{s.name}' uses proxy '{p.name}' ({p.type_name}), which has no "
                            "OpenSSH equivalent; set ProxyJump/ProxyCommand manually")
        if p and proxy_uses_netcat(p):
            needs_netcat = True

    alias_map = build_alias_map(backup.sessions)
    conf_d = os.path.join(base_fs, "conf.d")
    max_depth = 1
    for s in backup.sessions:
        rel = s.rel_dir  # e.g. "cluster", "" or "a/b"
        depth = (rel.count("/") + 2) if rel else 1
        max_depth = max(max_depth, depth)
        block = render_session(s, backup, alias_map, key_dir=cfg_key_dir,
                               identities_only=identities_only, converted_keys=converted,
                               windows=windows)
        _write(os.path.join(conf_d, rel, s.name + ".conf"), block)

    if needs_netcat:
        tool = "Nmap ncat (https://nmap.org/ncat/)" if windows else "OpenBSD netcat (the 'nc' command)"
        warnings.append(f"some sessions use an HTTP/SOCKS proxy via ProxyCommand; install {tool} "
                        "for those connections to work")

    # Top-level config: multi-depth glob Includes to cover arbitrary nesting.
    # Use the config base (forward slashes / portable '~') so paths work on
    # Windows too -- relative Include paths would resolve against ~/.ssh, not here.
    top = ["# Generated by xts-utils from an Xshell backup",
           "# Directory layout mirrors Xshell session groups; just `ssh <alias>`", ""]
    for d in range(1, max_depth + 1):
        glob = "/".join([cfg_base, "conf.d", *(["*"] * (d - 1)), "*.conf"])
        top.append(f"Include {quote_path(glob)}")
    top.append("")
    config_path = os.path.join(base_fs, "config")
    _write(config_path, "\n".join(top))

    result = ExportResult(
        output_dir=base_fs,
        config_path=config_path,
        key_dir_filesystem=key_dir_fs,
        key_dir_in_config=cfg_key_dir,
        sessions=len(backup.sessions),
        groups=len({s.rel_dir for s in backup.sessions}),
        keys_converted=len(written_keys),
        keys_total=len(backup.user_keys),
        warnings=warnings,
    )

    kh = _known_hosts_text(backup)
    if kh:
        result.known_hosts_path = os.path.join(base_fs, "known_hosts")
        _write(result.known_hosts_path, kh)

    if dump_credentials:
        assert master_password is not None  # guaranteed by the check above
        result.credentials_path = os.path.join(base_fs, "credentials.txt")
        _write(result.credentials_path, _credentials_text(backup, master_password), mode=0o600)

    return result
