"""Read an Xshell `.xts` backup (which is really a ZIP) and parse out sessions,
proxies, user keys, and host keys into a :class:`Backup`.

The Xshell session directory structure is preserved (the zip path
`Xshell/<group>/<name>.xsh`). :class:`Backup` is the in-memory form of the
``.xts``; converters (ssh config today, others later) read from it.
"""
from __future__ import annotations

import configparser
import posixpath
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass, field

# Placeholder host value recorded when a session fails to parse.
PARSE_FAILED_PREFIX = "<parse failed:"


def _decode(data: bytes) -> str:
    for enc in ("utf-8-sig", "utf-16", "utf-8", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1")


def _parse_ini(text: str) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser(strict=False, interpolation=None)
    cfg.optionxform = str  # type: ignore[method-assign, assignment]  # preserve key name case
    cfg.read_string(text)
    return cfg


@dataclass
class Forward:
    kind: str           # "local" | "remote" | "dynamic"
    bind_addr: str      # local/remote listen address (Source)
    bind_port: str
    dest_host: str
    dest_port: str
    local_only: bool    # True = bind to localhost only
    description: str = ""


# Xshell "Proxy > Type" enumeration, numbered in the order shown in its UI.
PROXY_SOCKS4 = 0
PROXY_SOCKS4A = 1
PROXY_SOCKS5 = 2
PROXY_HTTP = 3
PROXY_SSH_PASSTHROUGH = 4
PROXY_JUMPHOST = 5

PROXY_TYPE_NAMES = {
    PROXY_SOCKS4: "SOCKS4",
    PROXY_SOCKS4A: "SOCKS4A",
    PROXY_SOCKS5: "SOCKS5",
    PROXY_HTTP: "HTTP",
    PROXY_SSH_PASSTHROUGH: "SSH PASSTHROUGH",
    PROXY_JUMPHOST: "JUMPHOST",
}


@dataclass
class Proxy:
    name: str
    type: int                 # one of the PROXY_* constants above
    host: str = ""
    port: str = ""
    username: str = ""
    session_ref: str = ""     # path of the session file referenced by a jump host
    jumphost: str = ""

    @property
    def is_jumphost(self) -> bool:
        return self.type == PROXY_JUMPHOST or (bool(self.session_ref) and not self.host)

    @property
    def type_name(self) -> str:
        return PROXY_TYPE_NAMES.get(self.type, f"type {self.type}")


@dataclass
class Session:
    rel_dir: str              # group directory under Xshell ("" for root, "cluster", etc.)
    name: str                 # session name (file name without .xsh)
    version: float = 8.0
    host: str = ""
    port: str = "22"
    protocol: str = "SSH"
    username: str = ""
    user_key: str = ""        # referenced user key name (UserKeys file name without ext)
    password_enc: str = ""
    passphrase_enc: str = ""
    auth_method_list: str = ""
    proxy_name: str = ""
    forwards: list[Forward] = field(default_factory=list)
    agent_forwarding: bool = False
    compression: bool = False
    x11: bool = False

    @property
    def uses_pubkey(self) -> bool:
        # AuthMethodList starts with 00 (publickey), or a UserKey is explicitly set
        first = self.auth_method_list.split(",")[0].strip() if self.auth_method_list else ""
        return bool(self.user_key) or first == "00"


@dataclass
class UserKey:
    name: str       # file name without .pri
    text: str       # raw NSSSH private key text


@dataclass
class HostKey:
    host: str
    port: str
    text: str       # raw RFC4716 public key text


@dataclass
class Backup:
    sessions: list[Session]
    proxies: dict[str, Proxy]
    user_keys: dict[str, UserKey]
    host_keys: list[HostKey]
    container_version: str = ""
    master_protected: bool = False

    def proxy_for(self, session: Session) -> Proxy | None:
        if not session.proxy_name:
            return None
        return self.proxies.get(session.proxy_name)


def _parse_forwards(ssh: Mapping[str, str]) -> list[Forward]:
    forwards = []
    count = int(ssh.get("FwdReqCount", "0") or 0)
    for i in range(count):
        def g(suffix: str, default: str = "", _prefix: str = f"FwdReq_{i}_") -> str:
            return ssh.get(_prefix + suffix, default)
        incoming = g("Incoming", "0") == "1"
        dest_host = g("Host")
        if incoming:
            kind = "remote"
        elif not dest_host:
            kind = "dynamic"
        else:
            kind = "local"
        forwards.append(Forward(
            kind=kind,
            bind_addr=g("Source", "localhost"),
            bind_port=g("Port"),
            dest_host=dest_host,
            dest_port=g("HostPort"),
            local_only=g("LocalOnly", "1") == "1",
            description=g("Description"),
        ))
    return forwards


def _parse_session(rel_dir: str, name: str, text: str) -> Session:
    cfg = _parse_ini(text)

    info = cfg["SessionInfo"] if cfg.has_section("SessionInfo") else {}
    conn = cfg["CONNECTION"] if cfg.has_section("CONNECTION") else {}
    auth = cfg["CONNECTION:AUTHENTICATION"] if cfg.has_section("CONNECTION:AUTHENTICATION") else {}
    proxy = cfg["CONNECTION:PROXY"] if cfg.has_section("CONNECTION:PROXY") else {}
    ssh = cfg["CONNECTION:SSH"] if cfg.has_section("CONNECTION:SSH") else None

    try:
        version = float(info.get("Version", "8.0"))
    except (TypeError, ValueError):
        version = 8.0

    s = Session(
        rel_dir=rel_dir,
        name=name,
        version=version,
        host=conn.get("Host", ""),
        port=conn.get("Port", "22") or "22",
        protocol=conn.get("Protocol", "SSH"),
        username=auth.get("UserName", ""),
        user_key=auth.get("UserKey", ""),
        password_enc=auth.get("Password", ""),
        passphrase_enc=auth.get("Passphrase", ""),
        auth_method_list=auth.get("AuthMethodList", ""),
        proxy_name=proxy.get("Proxy", ""),
    )
    if ssh is not None:
        s.forwards = _parse_forwards(ssh)
        s.agent_forwarding = ssh.get("AgentForwarding", "0") == "1"
        s.compression = ssh.get("Compression", "0") == "1"
        s.x11 = ssh.get("ForwardX11", "0") == "1"
    return s


def _parse_proxy(name: str, text: str) -> Proxy:
    cfg = _parse_ini(text)
    sec = cfg["SECTION"] if cfg.has_section("SECTION") else {}
    try:
        ptype = int(sec.get("TYPE", "0") or 0)
    except ValueError:
        ptype = 0
    return Proxy(
        name=name,
        type=ptype,
        host=sec.get("HOST", ""),
        port=sec.get("PORT", ""),
        username=sec.get("USERNAME", ""),
        session_ref=sec.get("SESSION", ""),
        jumphost=sec.get("JUMPHOST", ""),
    )


def load_backup(xts_path: str) -> Backup:
    """Load and parse an entire .xts backup."""
    sessions: list[Session] = []
    proxies: dict[str, Proxy] = {}
    user_keys: dict[str, UserKey] = {}
    host_keys: list[HostKey] = []
    container_version = ""
    master = False

    with zipfile.ZipFile(xts_path) as z:
        names = z.namelist()
        if "xts.zcf" in names:
            try:
                zcf = _parse_ini(_decode(z.read("xts.zcf")))
                si = zcf["SessionInfo"] if zcf.has_section("SessionInfo") else {}
                container_version = si.get("Version", "")
                master = si.get("Master", "0") == "1"
            except Exception:
                pass

        for n in names:
            low = n.lower()
            if n.endswith("/"):
                continue
            if low.startswith("xshell/") and low.endswith(".xsh"):
                rel = n[len("Xshell/"):]
                rel_dir = posixpath.dirname(rel)
                name = posixpath.splitext(posixpath.basename(rel))[0]
                try:
                    sessions.append(_parse_session(rel_dir, name, _decode(z.read(n))))
                except Exception as exc:  # one bad session must not break the whole run
                    sessions.append(Session(rel_dir=rel_dir, name=name,
                                            host=f"{PARSE_FAILED_PREFIX} {exc}>"))
            elif low.startswith("com/common/proxy/") and low.endswith(".ini"):
                pname = posixpath.splitext(posixpath.basename(n))[0]
                try:
                    proxies[pname] = _parse_proxy(pname, _decode(z.read(n)))
                except Exception:
                    pass
            elif low.startswith("com/secsh/userkeys/") and low.endswith(".pri"):
                kname = posixpath.splitext(posixpath.basename(n))[0]
                user_keys[kname] = UserKey(name=kname, text=_decode(z.read(n)))
            elif low.startswith("com/secsh/hostkeys/") and low.endswith(".pub"):
                base = posixpath.splitext(posixpath.basename(n))[0]  # key_<host>_<port>
                host, port = "", ""
                if base.startswith("key_"):
                    rest = base[4:]
                    idx = rest.rfind("_")
                    if idx != -1:
                        host, port = rest[:idx], rest[idx + 1:]
                host_keys.append(HostKey(host=host, port=port, text=_decode(z.read(n))))

    sessions.sort(key=lambda s: (s.rel_dir, s.name))
    return Backup(sessions=sessions, proxies=proxies, user_keys=user_keys,
                  host_keys=host_keys, container_version=container_version,
                  master_protected=master)
