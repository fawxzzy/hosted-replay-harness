#!/usr/bin/env python3
"""Install and remove one packet-owned nftables boundary.

Only closed, sanitized TSV state is written to stdout.  The foreign ruleset is
held transiently in memory and reduced to canonical counts and a SHA-256.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from typing import Any


SCHEMA = "fawxzzy.hosted-replay-harness.firewall-boundary.v1"
TABLE = "fp_hosted_replay_ro_001"
INPUT_CHAIN = "packet_input"
FORWARD_CHAIN = "packet_forward"
INPUT_COUNTER = "packet_input_deny"
FORWARD_COUNTER = "packet_forward_deny"
VERSION_RE = re.compile(r"^nftables v([0-9]+)\.([0-9]+)\.([0-9]+)(?:[ -].*)?$")
SAFE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
SAFE_IFACE_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,15}$")
SAFE_SUBNET_RE = re.compile(r"^[0-9]{1,3}(?:\.[0-9]{1,3}){3}/[0-9]{1,2}$")
LEDGER_KEYS = {
    "schema",
    "table",
    "interface",
    "subnet",
    "preimage_sha256",
    "preimage_counts",
    "installed",
    "owned_sha256",
}


class BoundaryError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def state_line(key: str, kind: str, value: Any) -> str:
    rendered = str(value).lower() if isinstance(value, bool) else str(value)
    rendered = rendered.replace("\t", " ").replace("\r", " ").replace("\n", " ")
    return f"{key}\t{kind}\t{rendered}"


def emit(values: list[tuple[str, str, Any]]) -> None:
    for key, kind, value in values:
        print(state_line(key, kind, value))


def _run(command: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        input=input_text,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )


def locate_tools() -> tuple[str, str]:
    sudo = shutil.which("sudo")
    nft = shutil.which("nft")
    if not sudo or not nft:
        raise BoundaryError("FIREWALL_TOOL_UNAVAILABLE")
    return sudo, nft


def privileged_prefix() -> tuple[list[str], str]:
    sudo, nft = locate_tools()
    iptables = shutil.which("iptables")
    if not iptables:
        raise BoundaryError("FIREWALL_TOOL_UNAVAILABLE")
    authority = _run([sudo, "-n", "true"])
    if authority.returncode != 0:
        raise BoundaryError("FIREWALL_PRIVILEGE_UNAVAILABLE")
    version = _run([nft, "--version"])
    if version.returncode != 0:
        raise BoundaryError("FIREWALL_BACKEND_UNAVAILABLE")
    match = VERSION_RE.fullmatch(version.stdout.strip())
    if not match:
        raise BoundaryError("FIREWALL_BACKEND_AMBIGUOUS")
    compatibility = _run([iptables, "--version"])
    if compatibility.returncode != 0 or "(nf_tables)" not in compatibility.stdout:
        raise BoundaryError("FIREWALL_BACKEND_AMBIGUOUS")
    return [sudo, "-n", nft], f"nftables-v{match.group(1)}-iptables-nft"


def parse_ruleset(raw: str) -> list[dict[str, Any]]:
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        raise BoundaryError("FIREWALL_INSPECTION_FAILED") from exc
    entries = parsed.get("nftables") if isinstance(parsed, dict) else None
    if not isinstance(entries, list) or any(not isinstance(item, dict) for item in entries):
        raise BoundaryError("FIREWALL_INSPECTION_FAILED")
    return entries


def read_ruleset(prefix: list[str]) -> list[dict[str, Any]]:
    completed = _run([*prefix, "-j", "list", "ruleset"])
    if completed.returncode != 0:
        raise BoundaryError("FIREWALL_INSPECTION_FAILED")
    return parse_ruleset(completed.stdout)


def table_identity(entry: dict[str, Any]) -> tuple[str, str] | None:
    table = entry.get("table")
    if not isinstance(table, dict):
        return None
    family = table.get("family")
    name = table.get("name")
    return (family, name) if isinstance(family, str) and isinstance(name, str) else None


def belongs_to_table(entry: dict[str, Any], table_name: str) -> bool:
    for payload in entry.values():
        if isinstance(payload, dict) and payload.get("family") == "inet" and payload.get("table") == table_name:
            return True
    return table_identity(entry) == ("inet", table_name)


def _canonicalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _canonicalize(item)
            for key, item in sorted(value.items())
            if key not in {"handle", "packets", "bytes"}
        }
    if isinstance(value, list):
        return [_canonicalize(item) for item in value]
    return value


def canonical_snapshot(
    entries: list[dict[str, Any]], *, exclude_table: str | None = None
) -> tuple[str, dict[str, int]]:
    retained: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    for entry in entries:
        if "metainfo" in entry:
            continue
        if exclude_table and belongs_to_table(entry, exclude_table):
            continue
        retained.append(_canonicalize(entry))
        for kind in entry:
            counts[kind] = counts.get(kind, 0) + 1
    encoded = json.dumps(retained, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest(), dict(sorted(counts.items()))


def owned_entries(entries: list[dict[str, Any]], table_name: str) -> list[dict[str, Any]]:
    return [entry for entry in entries if belongs_to_table(entry, table_name)]


def build_batch(table_name: str, interface: str, subnet: str) -> str:
    if not SAFE_NAME_RE.fullmatch(table_name):
        raise BoundaryError("FIREWALL_IDENTITY_INVALID")
    if not SAFE_IFACE_RE.fullmatch(interface):
        raise BoundaryError("FIREWALL_INTERFACE_INVALID")
    if not SAFE_SUBNET_RE.fullmatch(subnet):
        raise BoundaryError("FIREWALL_SUBNET_INVALID")
    return "\n".join(
        (
            f"add table inet {table_name}",
            f"add counter inet {table_name} {INPUT_COUNTER}",
            f"add counter inet {table_name} {FORWARD_COUNTER}",
            f"add chain inet {table_name} {INPUT_CHAIN} {{ type filter hook input priority -10; policy accept; }}",
            f"add chain inet {table_name} {FORWARD_CHAIN} {{ type filter hook forward priority -10; policy accept; }}",
            f'add rule inet {table_name} {INPUT_CHAIN} iifname "{interface}" ip saddr {subnet} ct state established,related accept',
            f'add rule inet {table_name} {INPUT_CHAIN} iifname "{interface}" ip saddr {subnet} counter name {INPUT_COUNTER} drop',
            f'add rule inet {table_name} {FORWARD_CHAIN} iifname "{interface}" oifname "{interface}" ip saddr {subnet} ip daddr {subnet} accept',
            f'add rule inet {table_name} {FORWARD_CHAIN} iifname "{interface}" ip saddr {subnet} ct state established,related accept',
            f'add rule inet {table_name} {FORWARD_CHAIN} iifname "{interface}" ip saddr {subnet} counter name {FORWARD_COUNTER} drop',
            "",
        )
    )


def validate_owned(entries: list[dict[str, Any]], table_name: str) -> tuple[str, dict[str, int]]:
    selected = owned_entries(entries, table_name)
    digest, counts = canonical_snapshot(selected)
    expected = {"chain": 2, "counter": 2, "rule": 5, "table": 1}
    if counts != expected:
        raise BoundaryError("FIREWALL_INSTALLATION_MISMATCH")
    return digest, counts


def write_ledger(path: Path, ledger: dict[str, Any]) -> None:
    if set(ledger) != LEDGER_KEYS:
        raise BoundaryError("FIREWALL_LEDGER_INVALID")
    path.parent.mkdir(parents=True, exist_ok=True)
    exists = os.path.lexists(path)
    if exists:
        observed = path.lstat()
        if not stat.S_ISREG(observed.st_mode) or stat.S_ISLNK(observed.st_mode):
            raise BoundaryError("FIREWALL_LEDGER_INVALID")
    flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    flags |= os.O_TRUNC if exists else os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, (json.dumps(ledger, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600)


def read_ledger(path: Path) -> dict[str, Any]:
    try:
        observed = path.lstat()
    except OSError as exc:
        raise BoundaryError("FIREWALL_LEDGER_INVALID") from exc
    if not stat.S_ISREG(observed.st_mode) or stat.S_ISLNK(observed.st_mode):
        raise BoundaryError("FIREWALL_LEDGER_INVALID")
    try:
        ledger = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BoundaryError("FIREWALL_LEDGER_INVALID") from exc
    if not isinstance(ledger, dict) or set(ledger) != LEDGER_KEYS:
        raise BoundaryError("FIREWALL_LEDGER_INVALID")
    if ledger.get("schema") != SCHEMA or ledger.get("table") != TABLE:
        raise BoundaryError("FIREWALL_LEDGER_INVALID")
    if not SAFE_IFACE_RE.fullmatch(str(ledger.get("interface", ""))):
        raise BoundaryError("FIREWALL_LEDGER_INVALID")
    if not SAFE_SUBNET_RE.fullmatch(str(ledger.get("subnet", ""))):
        raise BoundaryError("FIREWALL_LEDGER_INVALID")
    if not isinstance(ledger.get("installed"), bool):
        raise BoundaryError("FIREWALL_LEDGER_INVALID")
    counts = ledger.get("preimage_counts")
    if not isinstance(counts, dict) or any(
        not isinstance(key, str) or not isinstance(value, int) or value < 0
        for key, value in counts.items()
    ):
        raise BoundaryError("FIREWALL_LEDGER_INVALID")
    for key in ("preimage_sha256",):
        value = ledger.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise BoundaryError("FIREWALL_LEDGER_INVALID")
    owned = ledger.get("owned_sha256")
    if not isinstance(owned, str) or (owned and not re.fullmatch(r"[0-9a-f]{64}", owned)):
        raise BoundaryError("FIREWALL_LEDGER_INVALID")
    return ledger


def install(ledger_path: Path, interface: str, subnet: str) -> None:
    if os.path.lexists(ledger_path):
        raise BoundaryError("FIREWALL_LEDGER_COLLISION")
    prefix, backend_class = privileged_prefix()
    entries = read_ruleset(prefix)
    if owned_entries(entries, TABLE):
        raise BoundaryError("FIREWALL_TABLE_COLLISION")
    pre_sha, pre_counts = canonical_snapshot(entries, exclude_table=TABLE)
    ledger = {
        "schema": SCHEMA,
        "table": TABLE,
        "interface": interface,
        "subnet": subnet,
        "preimage_sha256": pre_sha,
        "preimage_counts": pre_counts,
        "installed": False,
        "owned_sha256": "",
    }
    write_ledger(ledger_path, ledger)
    batch = build_batch(TABLE, interface, subnet)
    checked = _run([*prefix, "--check", "-f", "-"], input_text=batch)
    if checked.returncode != 0:
        ledger_path.unlink(missing_ok=True)
        raise BoundaryError("FIREWALL_ATOMIC_CHECK_FAILED")
    applied = _run([*prefix, "-f", "-"], input_text=batch)
    if applied.returncode != 0:
        raise BoundaryError("FIREWALL_ATOMIC_INSTALL_FAILED")
    after = read_ruleset(prefix)
    owned_sha, owned_counts = validate_owned(after, TABLE)
    foreign_sha, foreign_counts = canonical_snapshot(after, exclude_table=TABLE)
    if foreign_sha != pre_sha or foreign_counts != pre_counts:
        raise BoundaryError("FIREWALL_FOREIGN_STATE_DRIFT")
    ledger["installed"] = True
    ledger["owned_sha256"] = owned_sha
    write_ledger(ledger_path, ledger)
    emit(
        [
            ("firewall.backend_class", "str", backend_class),
            ("firewall.atomic_install", "bool", True),
            ("firewall.preimage_sha256", "str", pre_sha),
            ("firewall.preimage_table_count", "int", pre_counts.get("table", 0)),
            ("firewall.preimage_chain_count", "int", pre_counts.get("chain", 0)),
            ("firewall.preimage_rule_count", "int", pre_counts.get("rule", 0)),
            ("firewall.owned_sha256", "str", owned_sha),
            ("firewall.owned_chain_count", "int", owned_counts["chain"]),
            ("firewall.owned_rule_count", "int", owned_counts["rule"]),
        ]
    )


def counter_packets(entries: list[dict[str, Any]], name: str) -> int:
    found: list[int] = []
    for entry in entries:
        counter = entry.get("counter")
        if not isinstance(counter, dict):
            continue
        if counter.get("family") == "inet" and counter.get("table") == TABLE and counter.get("name") == name:
            packets = counter.get("packets")
            if not isinstance(packets, int) or packets < 0:
                raise BoundaryError("FIREWALL_COUNTER_INVALID")
            found.append(packets)
    if len(found) != 1:
        raise BoundaryError("FIREWALL_COUNTER_INVALID")
    return found[0]


def counters(ledger_path: Path) -> None:
    ledger = read_ledger(ledger_path)
    if ledger.get("installed") is not True:
        raise BoundaryError("FIREWALL_LEDGER_INVALID")
    prefix, _ = privileged_prefix()
    entries = read_ruleset(prefix)
    validate_owned(entries, TABLE)
    emit(
        [
            ("firewall.counters.input_deny", "int", counter_packets(entries, INPUT_COUNTER)),
            ("firewall.counters.forward_deny", "int", counter_packets(entries, FORWARD_COUNTER)),
        ]
    )


def remove(ledger_path: Path) -> None:
    prefix, _ = privileged_prefix()
    entries = read_ruleset(prefix)
    selected = owned_entries(entries, TABLE)
    if not os.path.lexists(ledger_path):
        if selected:
            raise BoundaryError("FIREWALL_LEDGER_MISSING")
        emit([("firewall.rollback_idempotent", "bool", True)])
        return
    ledger = read_ledger(ledger_path)
    before_sha, before_counts = canonical_snapshot(entries, exclude_table=TABLE)
    foreign_drift = before_sha != ledger["preimage_sha256"] or before_counts != ledger["preimage_counts"]
    if selected:
        batch = f"delete table inet {TABLE}\n"
        checked = _run([*prefix, "--check", "-f", "-"], input_text=batch)
        if checked.returncode != 0:
            raise BoundaryError("FIREWALL_ATOMIC_ROLLBACK_CHECK_FAILED")
        deleted = _run([*prefix, "-f", "-"], input_text=batch)
        if deleted.returncode != 0:
            raise BoundaryError("FIREWALL_ATOMIC_ROLLBACK_FAILED")
    after = read_ruleset(prefix)
    if owned_entries(after, TABLE):
        raise BoundaryError("FIREWALL_ROLLBACK_RESIDUE")
    post_sha, post_counts = canonical_snapshot(after, exclude_table=TABLE)
    ledger_path.unlink(missing_ok=True)
    emit(
        [
            ("firewall.rollback_removed_table_count", "int", 1 if selected else 0),
            ("firewall.rollback_foreign_preimage_restored", "bool", not foreign_drift and post_sha == ledger["preimage_sha256"] and post_counts == ledger["preimage_counts"]),
            ("firewall.rollback_postimage_sha256", "str", post_sha),
            ("firewall.rollback_postimage_table_count", "int", post_counts.get("table", 0)),
            ("firewall.rollback_postimage_chain_count", "int", post_counts.get("chain", 0)),
            ("firewall.rollback_postimage_rule_count", "int", post_counts.get("rule", 0)),
        ]
    )
    if foreign_drift or post_sha != ledger["preimage_sha256"] or post_counts != ledger["preimage_counts"]:
        raise BoundaryError("FIREWALL_FOREIGN_STATE_DRIFT")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    install_parser = subparsers.add_parser("install")
    install_parser.add_argument("--ledger", required=True, type=Path)
    install_parser.add_argument("--interface", required=True)
    install_parser.add_argument("--subnet", required=True)
    counter_parser = subparsers.add_parser("counters")
    counter_parser.add_argument("--ledger", required=True, type=Path)
    remove_parser = subparsers.add_parser("remove")
    remove_parser.add_argument("--ledger", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "install":
            install(args.ledger, args.interface, args.subnet)
        elif args.command == "counters":
            counters(args.ledger)
        else:
            remove(args.ledger)
    except (BoundaryError, subprocess.TimeoutExpired) as exc:
        code = exc.code if isinstance(exc, BoundaryError) else "FIREWALL_TOOL_TIMEOUT"
        emit([("firewall.failure_code", "str", code)])
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
