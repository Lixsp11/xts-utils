# xts-utils

Decode Xshell **`.xts`** backup into a **OpenSSH config**, preserving the session group tree and reproducing each server's key, proxy and port forwarding.

## Install

```bash
pip install .
```

## Usage

```bash
# Inspect a backup (writes nothing)
xts-utils list backup.xts

# Decode .xts -> OpenSSH config
xts-utils export sshconfig backup.xts

# Connect
ssh -F ~/.ssh/xts/config <alias>
```

By default everything is written under **`~/.ssh/xts/`**:

```
~/.ssh/xts/
  config            # top-level, Includes everything below
  conf.d/...        # one .conf per session, mirroring the Xshell group tree
  keys/...          # private keys converted to OpenSSH format
  known_hosts
```

Change the location with `-o`:

```bash
xts-utils export sshconfig backup.xts -o ./out   # -> ./out/...
```

Passwords are discarded by default. To also dump decrypted passwords/passphrases:

```bash
xts-utils export sshconfig backup.xts --dump-credentials --master-password '<pw>'
# writes <base>/credentials.txt (mode 0600) -- keep safe, never commit
```

## Key types

Private keys are converted to a format OpenSSH reads directly: RSA → PKCS#1 PEM,
everything else (Ed25519 verified; ECDSA / DSA best-effort) → `openssh-key-v1`.
Passphrase-encrypted keys are not decrypted; they are copied out as `<name>.nsssh`
with a warning, and the session keeps a flagged `IdentityFile`.

## Proxy support

Xshell's per-session **Proxy → Type** maps to OpenSSH as follows:

| Xshell type | OpenSSH output |
| --- | --- |
| `JUMPHOST` | `ProxyJump <alias>` (the jump session's alias, or `user@host:port` if it isn't in the backup) |
| `SOCKS5` | `ProxyCommand` via netcat |
| `SOCKS4` / `SOCKS4A` | `ProxyCommand` via netcat (no separate SOCKS4A dialect) |
| `HTTP 1.1` | `ProxyCommand` via netcat |
| `SSH PASSTHROUGH` | not supported — emitted as a comment to set manually |

The `ProxyCommand` form matches the OS you run the export on, and the other is kept
as a comment so the tree works on either platform:

```sshconfig
# Linux/macOS
ProxyCommand nc -X 5 -x 127.0.0.1:7890 %h %p
# Windows
ProxyCommand ncat --proxy-type socks5 --proxy 127.0.0.1:7890 %h %p
```

So install **OpenBSD netcat** (`nc`) on Linux/macOS or **Nmap `ncat`** on Windows for
those sessions to connect; the export prints a reminder when any session needs it.

## Develop

```bash
pip install -e .
pip install -r requirements-dev.txt
pytest        # synthetic fixtures, no real .xts needed
ruff check . && mypy src/xts_utils
```
