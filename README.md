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

## Develop

```bash
pip install -e .
pip install -r requirements-dev.txt
pytest        # synthetic fixtures, no real .xts needed
ruff check . && mypy src/xts_utils
```
