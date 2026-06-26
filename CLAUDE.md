# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`xts-utils` decodes an Xshell **`.xts`** backup (a ZIP encrypted by a master password) into a ready-to-use **OpenSSH `ssh_config(5)`** tree — preserving the Xshell session group structure and reproducing each server's identity key, connection proxy (ProxyJump / ProxyCommand) and port forwarding. Pure Python standard library, **no runtime dependencies**.

## Commands

```bash
pip install -e .                      # editable install — REQUIRED before tests (src-layout)
pip install -r requirements-dev.txt   # dev tooling (ruff, mypy, pytest, build)

pytest                                # full suite (synthetic fixtures, no real .xts needed)
pytest tests/test_crypto.py           # one file
pytest -m sshconfig                   # by marker: crypto | rsakey | container | sshconfig | cli
pytest tests/test_cli.py::test_name   # one test

ruff check .                          # lint (line-length 120, py311; excludes examples/)
mypy src/xts_utils                    # type-check (strict, but untyped defs allowed)
```

Run the tool: `xts-utils list backup.xts` and `xts-utils export sshconfig backup.xts [-o DIR]`.

## Architecture

The library is **xts-centric**: there is intentionally **no intermediate/neutral representation**. `core/` is the `.xts` format itself; each target format lives in its own package and converts to/from the parsed backup. Do not reintroduce a `model.py`-style IR.

- **`core/`** — everything about the `.xts` format.
  - `container.py` — `load_backup(path) -> Backup`. Reads the ZIP, parses sessions (`Xshell/<group>/<name>.xsh`), proxies (`com/Common/Proxy/*.ini`), user keys (`com/SECSH/UserKeys/*.pri`), host keys (`com/SECSH/HostKeys/*.pub`). `Backup` is the in-memory `.xts`; converters read from it. A failed session becomes a placeholder host (`PARSE_FAILED_PREFIX`) rather than aborting the run.
  - `crypto.py` — RC4 + version-dependent key derivation. For Xshell >5.2 with a master password, the key is `SHA256(master_password)` — fully offline, no SID/machine binding. `encrypt_password` is the inverse, kept for the future import direction.
  - `rsakey.py` — converts NetSarang `nsssh-key-v6` private keys to PKCS#1 PEM (hand-rolled DER, recomputes `iqmp` rather than trusting the stored value).
  - `hostkeys.py` — RFC4716 public key → `known_hosts` line.
- **`sshconfig/`** — the `.xts` ↔ `ssh_config` converter (export today; `importer` is the planned reverse).
  - `render.py` — pure, no-I/O rendering of one `Session` into a `Host` block.
  - `exporter.py` — orchestration: writes the on-disk tree (`config` + `conf.d/` mirroring the group tree + `keys/` + `known_hosts`) under one base dir.
- **`cli.py`** — verb-then-format command tree: `list`, `export sshconfig` (`import` is reserved/planned).

## Conventions and non-obvious constraints

- **ssh aliases must be slash-free.** OpenSSH rejects `/` in `ProxyJump` targets, so `build_alias_map` produces slash-free aliases (group-prefixed on collision) and jump hosts reference the bare alias. Don't put `/` into a Host alias.
- **Windows-safe paths.** Anything written *into* config files (`Include`, `IdentityFile`) uses forward slashes and is quoted when it contains spaces (`quote_path`). A leading `~` is kept verbatim (portable); otherwise the path is made absolute (a relative `Include` would resolve against `~/.ssh`, not the base dir). See `_config_base`.
- **Output location** is controlled only by `-o` (default `~/.ssh/xts`). There is no environment variable — do not add one.
- **Secrets are opt-in.** Passwords are discarded unless `--dump-credentials --master-password <pw>` is given; that path writes `credentials.txt` (mode 0600). Private keys are written 0600, key dir 0700.
- `examples/` (real `.xts` samples + research clones) and `credentials.txt` are git-ignored and must never be committed.
- **License is GPLv3**; do **not** add per-file license headers.
- Commit style: Conventional Commits.
