#!/usr/bin/env python3
"""Reject a fixed packet subnet that overlaps any supplied host/Docker prefix."""

from __future__ import annotations

import argparse
import ipaddress
import sys


def overlaps(candidate: str, existing: list[str]) -> list[str]:
    wanted = ipaddress.ip_network(candidate, strict=False)
    conflicts: list[str] = []
    for raw in existing:
        try:
            current = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if wanted.version == current.version and wanted.overlaps(current):
            conflicts.append(str(current))
    return conflicts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate")
    parser.add_argument("existing", nargs="*")
    args = parser.parse_args()
    return 1 if overlaps(args.candidate, args.existing) else 0


if __name__ == "__main__":
    sys.exit(main())
