"""Render parsed sessions into OpenSSH config text (preserving the group tree).

Pure functions, no I/O. Each session becomes one Host block, reproducing:
  - HostName / Port / User
  - public key auth -> IdentityFile (pointing at the converted OpenSSH key)
  - proxy          -> ProxyJump (JUMPHOST) or ProxyCommand (HTTP/SOCKS)
  - port forwards  -> LocalForward / RemoteForward / DynamicForward
  - misc           -> ForwardAgent / Compression / ForwardX11
"""
from __future__ import annotations

import posixpath
from collections import Counter

from ..core.container import PARSE_FAILED_PREFIX, Backup, Forward, Proxy, Session

AliasMap = dict[tuple[str, str], str]


def _norm(text: str) -> str:
    return text.replace("/", "-").replace(" ", "_")


def quote_path(path: str) -> str:
    """Double-quote a path for ssh_config when it contains spaces.

    OpenSSH treats a space as a token separator, so a Windows home like
    ``C:/Users/John Doe/...`` must be quoted to be read as one path.
    """
    return f'"{path}"' if " " in path else path


def build_alias_map(sessions: list[Session]) -> AliasMap:
    """Assign each session a unique, slash-free ssh alias (ProxyJump forbids '/').

    Uses the session name by default; when the same name collides across groups,
    all of them get a "<group>-" prefix; remaining collisions get a numeric suffix.
    """
    name_counts = Counter(s.name for s in sessions)
    used: set[str] = set()
    alias_map: AliasMap = {}
    for s in sessions:
        if name_counts[s.name] > 1 and s.rel_dir:
            base = f"{_norm(s.rel_dir)}-{_norm(s.name)}"
        else:
            base = _norm(s.name)
        alias = base
        i = 2
        while alias in used:
            alias = f"{base}-{i}"
            i += 1
        used.add(alias)
        alias_map[(s.rel_dir, s.name)] = alias
    return alias_map


def host_alias(session: Session, alias_map: AliasMap | None = None) -> str:
    """Host alias (slash-free). Falls back to the normalized session name with no map."""
    if alias_map is not None:
        a = alias_map.get((session.rel_dir, session.name))
        if a:
            return a
    return _norm(session.name)


def _forward_line(f: Forward) -> str | None:
    bind = f.bind_addr or "localhost"
    if f.kind == "dynamic":
        spec = f"{bind}:{f.bind_port}" if not f.local_only else f.bind_port
        return f"DynamicForward {spec}"
    if not f.bind_port or not f.dest_host or not f.dest_port:
        return None
    # local_only=False means listen on all interfaces (GatewayPorts), needs a bind address
    if f.local_only:
        listen = f.bind_port
    else:
        listen = f"{bind}:{f.bind_port}" if f.kind == "local" else f"*:{f.bind_port}"
    target = f"{f.dest_host}:{f.dest_port}"
    keyword = "LocalForward" if f.kind == "local" else "RemoteForward"
    return f"{keyword} {listen} {target}"


def _proxy_lines(session: Session, proxy: Proxy, backup: Backup,
                 alias_map: AliasMap) -> list[str]:
    """Generate proxy-related config lines (possibly multiple lines + comments)."""
    lines: list[str] = []
    if proxy.is_jumphost:
        # Via another session acting as a jump host -> ProxyJump
        jump = _resolve_jump_alias(proxy, backup, alias_map)
        if jump:
            lines.append(f"ProxyJump {jump}")
        else:
            lines.append(f"# Jump-host proxy '{proxy.name}' could not be resolved to a "
                         "known session; please set ProxyJump manually")
    elif proxy.host and proxy.port:
        # HTTP / SOCKS proxy -> ProxyCommand (requires nc / ncat on the system)
        if proxy.type == 2:
            ptype, flag = "HTTP", "-X connect"
        elif proxy.type in (0, 1):
            ptype, flag = "SOCKS4", "-X 4"
        else:
            ptype, flag = "SOCKS5", "-X 5"
        lines.append(f"# Via {ptype} proxy {proxy.host}:{proxy.port} (requires OpenBSD netcat)")
        lines.append(f"ProxyCommand nc {flag} -x {proxy.host}:{proxy.port} %h %p")
    return lines


def _resolve_jump_alias(proxy: Proxy, backup: Backup, alias_map: AliasMap) -> str | None:
    """Resolve the session referenced by a jump-host proxy into a ProxyJump target.

    Prefer the jump session's bare alias (its own Host block supplies user/port/key),
    to avoid ssh parse errors with the `user@alias:port` form or aliases containing '/'.
    """
    ref = proxy.session_ref.replace("\\", "/")
    target_name = posixpath.splitext(posixpath.basename(ref))[0] if ref else proxy.name
    for s in backup.sessions:
        if s.name == target_name:
            return host_alias(s, alias_map)
    # Jump session not in the backup: fall back to explicit user@host:port (real host, not alias)
    if proxy.username or proxy.host:
        user = proxy.username
        host = proxy.host or target_name
        prefix = f"{user}@" if user else ""
        if proxy.port and proxy.port not in ("22", ""):
            return f"{prefix}{host}:{proxy.port}"
        return f"{prefix}{host}"
    return target_name or None


def render_session(session: Session, backup: Backup, alias_map: AliasMap, *,
                   key_dir: str = "~/.ssh/xts/keys",
                   identities_only: bool = True) -> str:
    """Render a single session as one Host block."""
    lines: list[str] = []
    alias = host_alias(session, alias_map)
    origin = posixpath.join(session.rel_dir, session.name) if session.rel_dir else session.name
    if session.host.startswith(PARSE_FAILED_PREFIX):
        return f"# Host {alias}  -- {session.host}\n"

    lines.append(f"# Xshell: {origin}")
    lines.append(f"Host {alias}")
    if session.host:
        lines.append(f"    HostName {session.host}")
    if session.port and session.port != "22":
        lines.append(f"    Port {session.port}")
    if session.username:
        lines.append(f"    User {session.username}")

    if session.uses_pubkey and session.user_key:
        keypath = posixpath.join(key_dir, session.user_key)
        lines.append(f"    IdentityFile {quote_path(keypath)}")
        if identities_only:
            lines.append("    IdentitiesOnly yes")

    proxy = backup.proxy_for(session)
    if proxy:
        for pl in _proxy_lines(session, proxy, backup, alias_map):
            lines.append(f"    {pl}")

    for f in session.forwards:
        fl = _forward_line(f)
        if fl:
            comment = f"  # {f.description}" if f.description else ""
            lines.append(f"    {fl}{comment}")

    if session.agent_forwarding:
        lines.append("    ForwardAgent yes")
    if session.compression:
        lines.append("    Compression yes")
    if session.x11:
        lines.append("    ForwardX11 yes")

    if session.protocol.upper() != "SSH":
        lines.insert(1, f"    # Note: original protocol was {session.protocol}, not SSH; "
                        "the settings below may not apply")

    return "\n".join(lines) + "\n"
