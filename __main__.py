"""Command line interface: python -m pqtrust <command>."""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__
from .core import fingerprint_file, load_default, where


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pqtrust")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("where", help="print path of the bundled registry")
    sub.add_parser("list", help="list anchors grouped by algorithm")
    check = sub.add_parser("check", help="is a fingerprint trusted today?")
    check.add_argument("fingerprint")
    exp = sub.add_parser("expiring", help="anchors expiring soon")
    exp.add_argument("--days", type=int, default=365)
    fp = sub.add_parser("fingerprint", help="SHA3-256 of a key file")
    fp.add_argument("path")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command in (None, "where"):
        print(where())
        return 0
    if args.command == "fingerprint":
        print(fingerprint_file(args.path))
        return 0

    registry = load_default()
    if args.command == "list":
        for algo, anchors in registry.group_by_algorithm().items():
            print(f"{algo} ({len(anchors)})")
            for a in anchors:
                print(f"  {a.name:<28} {a.status:<8} until {a.not_after}")
    elif args.command == "check":
        trusted = registry.is_trusted(args.fingerprint.lower())
        print("TRUSTED" if trusted else "NOT TRUSTED")
        return 0 if trusted else 1
    elif args.command == "expiring":
        for a in registry.expiring_within(args.days):
            print(f"{a.not_after}  {a.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
