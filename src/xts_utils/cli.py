"""Command-line entry point for ``xts-utils``.

Command structure (verb, then format -- extensible as more are added):

    xts-utils list <xts>                 inspect backup contents
    xts-utils export sshconfig <xts>     decode .xts -> OpenSSH config
    xts-utils import sshconfig ...        (planned) encode ssh config -> .xts
"""
from __future__ import annotations

import argparse
import sys
from typing import cast

from . import __version__
from .core.container import load_backup
from .sshconfig.exporter import DEFAULT_HOME, export_backup
from .sshconfig.render import build_alias_map, host_alias


def _cmd_list(args: argparse.Namespace) -> int:
    backup = load_backup(args.xts_path)
    alias_map = build_alias_map(backup.sessions)
    print(f"container_version={backup.container_version} "
          f"master_protected={backup.master_protected} "
          f"sessions={len(backup.sessions)} proxies={len(backup.proxies)} "
          f"user_keys={len(backup.user_keys)} host_keys={len(backup.host_keys)}\n")
    for s in backup.sessions:
        proxy = f" proxy={s.proxy_name}" if s.proxy_name else ""
        key = f" key={s.user_key}" if s.user_key else ""
        fwd = f" forwards={len(s.forwards)}" if s.forwards else ""
        print(f"  {host_alias(s, alias_map):40s} {s.username}@{s.host}:{s.port}{key}{proxy}{fwd}")
    return 0


def _cmd_export_sshconfig(args: argparse.Namespace) -> int:
    if args.dump_credentials and not args.master_password:
        print("error: --dump-credentials requires --master-password", file=sys.stderr)
        return 2

    template_text = None
    if args.template:
        try:
            with open(args.template, encoding="utf-8") as f:
                template_text = f.read()
        except OSError as exc:
            print(f"error: cannot read template {args.template}: {exc}", file=sys.stderr)
            return 2

    backup = load_backup(args.xts_path)
    result = export_backup(
        backup, args.output,
        identities_only=not args.no_identities_only,
        dump_credentials=args.dump_credentials,
        master_password=args.master_password,
        template_text=template_text,
    )

    print(f"OK  parsed {result.sessions} sessions in {result.groups} groups")
    print(f"OK  converted {result.keys_converted}/{result.keys_total} private keys "
          f"-> {result.key_dir_filesystem}")
    print(f"OK  ssh config -> {result.config_path}  (conf.d/ mirrors the Xshell tree)")
    if result.template_path:
        print(f"OK  template -> {result.template_path}  (Included first; overrides every host)")
    if result.known_hosts_path:
        print(f"OK  known_hosts -> {result.known_hosts_path}")
    if result.credentials_path:
        print(f"OK  plaintext credentials -> {result.credentials_path}")
    for w in result.warnings:
        print(f"  ! {w}", file=sys.stderr)
    print(f"\nUsage: ssh -F {result.config_path} <alias>")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xts-utils",
        description="Toolkit for Xshell .xts backups (decode to OpenSSH config, and more).")
    parser.add_argument("-V", "--version", action="version",
                        version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_list = sub.add_parser("list", help="list backup contents only, generate nothing")
    p_list.add_argument("xts_path", help="path to the .xts backup file")
    p_list.set_defaults(func=_cmd_list)

    p_export = sub.add_parser("export", help="decode a .xts backup into another format")
    exp_sub = p_export.add_subparsers(dest="format")

    p_ssh = exp_sub.add_parser("sshconfig", help="export to an OpenSSH ssh_config tree")
    p_ssh.add_argument("xts_path", help="path to the .xts backup file")
    p_ssh.add_argument(
        "-o", "--output", default=DEFAULT_HOME,
        help=f"output base directory (default: {DEFAULT_HOME}). "
             "config, conf.d/, keys/ and known_hosts are written under it.")
    p_ssh.add_argument("--no-identities-only", action="store_true",
                       help="do not emit 'IdentitiesOnly yes'")
    p_ssh.add_argument("--template", default=None, metavar="FILE",
                       help="ssh_config snippet (e.g. a 'Host *' block) copied in and Included "
                            "first, so its options override every host")
    p_ssh.add_argument("--dump-credentials", action="store_true",
                       help="also export plaintext passwords/passphrases (needs --master-password)")
    p_ssh.add_argument("--master-password", default=None,
                       help="master password (used to decrypt credentials)")
    p_ssh.set_defaults(func=_cmd_export_sshconfig)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        # Incomplete (sub)command: show the most relevant help.
        if getattr(args, "command", None) == "export":
            parser.parse_args(["export", "--help"])
        parser.print_help()
        return 1
    return cast(int, args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
