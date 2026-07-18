#!/usr/bin/env python3
"""Install and remove one packet-owned nftables boundary.

Only closed, sanitized TSV state is written to stdout.  The foreign ruleset is
held transiently in memory and reduced to canonical counts and a SHA-256.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from typing import Any


SCHEMA = "fawxzzy.hosted-replay-harness.firewall-boundary.v3"
TABLE = "fp_hosted_replay_ro_001"
INPUT_CHAIN = "packet_input"
FORWARD_CHAIN = "packet_forward"
OUTPUT_CHAIN = "packet_output"
INPUT_COUNTER = "packet_input_deny"
FORWARD_COUNTER = "packet_forward_deny"
OUTPUT_COUNTER = "packet_output_deny"
MARKER_INPUT_CHAIN = "canary_input"
MARKER_FORWARD_CHAIN = "canary_forward"
MARKER_OUTPUT_CHAIN = "canary_output"
MARKER_COUNTERS = {
    "same_network": "marker_same_network",
    "external_dns": "marker_external_dns",
    "literal_ip": "marker_literal_ip",
    "metadata": "marker_metadata",
    "gateway": "marker_gateway",
    "host_listener": "marker_host_listener",
    "foreign_network": "marker_foreign_network",
}
MARKER_CHAINS = {MARKER_INPUT_CHAIN, MARKER_FORWARD_CHAIN, MARKER_OUTPUT_CHAIN}
# DNS question wire identity for the fixed public canary name already frozen in
# the runner.  It is matched only transiently and is never emitted in state.
DNS_QUESTION_HEX = "076578616d706c6503636f6d00"
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
    "markers_installed",
    "marker_sha256",
    "combined_sha256",
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


def _process_uids(status: str) -> tuple[int, int]:
    lines = [line for line in status.splitlines() if line.startswith("Uid:")]
    if len(lines) != 1:
        raise BoundaryError("FIREWALL_DOCKER_DAEMON_IDENTITY_UNAVAILABLE")
    fields = lines[0].split()
    if len(fields) != 5 or any(not field.isdigit() for field in fields[1:]):
        raise BoundaryError("FIREWALL_DOCKER_DAEMON_IDENTITY_UNAVAILABLE")
    return int(fields[1]), int(fields[2])


def process_ownership_preflight(
    proc_root: Path = Path("/proc"), *, runner_euid: int | None = None
) -> tuple[str, bool, bool]:
    if runner_euid is None:
        if not hasattr(os, "geteuid"):
            raise BoundaryError("FIREWALL_RUNNER_IDENTITY_UNAVAILABLE")
        runner_euid = os.geteuid()
    if not isinstance(runner_euid, int) or runner_euid < 0:
        raise BoundaryError("FIREWALL_RUNNER_IDENTITY_UNAVAILABLE")
    if runner_euid == 0:
        raise BoundaryError("FIREWALL_RUNNER_ROOT")

    daemon_uids: list[tuple[int, int]] = []
    try:
        candidates = list(proc_root.iterdir())
    except OSError as exc:
        raise BoundaryError("FIREWALL_DOCKER_DAEMON_IDENTITY_UNAVAILABLE") from exc
    for candidate in candidates:
        if not candidate.name.isdigit():
            continue
        try:
            command_name = (candidate / "comm").read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if command_name != "dockerd":
            continue
        try:
            daemon_uids.append(_process_uids((candidate / "status").read_text(encoding="utf-8")))
        except OSError as exc:
            raise BoundaryError("FIREWALL_DOCKER_DAEMON_IDENTITY_UNAVAILABLE") from exc
    if not daemon_uids:
        raise BoundaryError("FIREWALL_DOCKER_DAEMON_MISSING")
    if len(daemon_uids) != 1:
        raise BoundaryError("FIREWALL_DOCKER_DAEMON_AMBIGUOUS")
    if daemon_uids[0] != (0, 0):
        raise BoundaryError("FIREWALL_DOCKER_DAEMON_NOT_ROOT")
    return "single-root-owned-dockerd", True, True


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
            f"add counter inet {table_name} {OUTPUT_COUNTER}",
            f"add chain inet {table_name} {INPUT_CHAIN} {{ type filter hook input priority -10; policy accept; }}",
            f"add chain inet {table_name} {FORWARD_CHAIN} {{ type filter hook forward priority -10; policy accept; }}",
            f"add chain inet {table_name} {OUTPUT_CHAIN} {{ type filter hook output priority -10; policy accept; }}",
            f'add rule inet {table_name} {INPUT_CHAIN} iifname "{interface}" ip saddr {subnet} ct state established,related accept',
            f'add rule inet {table_name} {INPUT_CHAIN} iifname "{interface}" ip saddr {subnet} counter name {INPUT_COUNTER} drop',
            f'add rule inet {table_name} {FORWARD_CHAIN} iifname "{interface}" oifname "{interface}" ip saddr {subnet} ip daddr {subnet} accept',
            f'add rule inet {table_name} {FORWARD_CHAIN} iifname "{interface}" ip saddr {subnet} ct state established,related accept',
            f'add rule inet {table_name} {FORWARD_CHAIN} iifname "{interface}" ip saddr {subnet} counter name {FORWARD_COUNTER} drop',
            f"add rule inet {table_name} {OUTPUT_CHAIN} meta skuid 0 udp dport 53 counter name {OUTPUT_COUNTER} drop",
            f"add rule inet {table_name} {OUTPUT_CHAIN} meta skuid 0 tcp dport 53 counter name {OUTPUT_COUNTER} drop",
            "",
        )
    )


def _validated_ipv4(value: str, code: str) -> ipaddress.IPv4Address:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise BoundaryError(code) from exc
    if not isinstance(address, ipaddress.IPv4Address):
        raise BoundaryError(code)
    return address


def build_marker_batch(
    table_name: str,
    interface: str,
    subnet: str,
    client_ip: str,
    service_ip: str,
    foreign_ip: str,
    gateway_ip: str,
    host_port: int,
) -> str:
    if not SAFE_NAME_RE.fullmatch(table_name):
        raise BoundaryError("FIREWALL_IDENTITY_INVALID")
    if not SAFE_IFACE_RE.fullmatch(interface):
        raise BoundaryError("FIREWALL_INTERFACE_INVALID")
    try:
        network = ipaddress.ip_network(subnet, strict=True)
    except ValueError as exc:
        raise BoundaryError("FIREWALL_SUBNET_INVALID") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise BoundaryError("FIREWALL_SUBNET_INVALID")
    client = _validated_ipv4(client_ip, "FIREWALL_MARKER_IDENTITY_INVALID")
    service = _validated_ipv4(service_ip, "FIREWALL_MARKER_IDENTITY_INVALID")
    foreign = _validated_ipv4(foreign_ip, "FIREWALL_MARKER_IDENTITY_INVALID")
    gateway = _validated_ipv4(gateway_ip, "FIREWALL_MARKER_IDENTITY_INVALID")
    if (
        client not in network
        or service not in network
        or gateway not in network
        or gateway in {network.network_address, network.broadcast_address}
        or foreign in network
        or len({client, service, gateway}) != 3
        or not isinstance(host_port, int)
        or not 1 <= host_port <= 65535
    ):
        raise BoundaryError("FIREWALL_MARKER_IDENTITY_INVALID")

    counters = tuple(
        f"add counter inet {table_name} {name}" for name in MARKER_COUNTERS.values()
    )
    rules = (
        f'add rule inet {table_name} {MARKER_INPUT_CHAIN} iifname "{interface}" ip saddr {client} ip daddr {gateway} icmp type echo-request counter name {MARKER_COUNTERS["gateway"]}',
        f'add rule inet {table_name} {MARKER_INPUT_CHAIN} iifname "{interface}" ip saddr {client} ip daddr {gateway} tcp dport {host_port} counter name {MARKER_COUNTERS["host_listener"]}',
        f'add rule inet {table_name} {MARKER_FORWARD_CHAIN} iifname "{interface}" oifname "{interface}" ip saddr {client} ip daddr {service} tcp dport 5432 counter name {MARKER_COUNTERS["same_network"]}',
        f'add rule inet {table_name} {MARKER_FORWARD_CHAIN} iifname "{interface}" ip saddr {client} ip daddr 1.1.1.1 tcp dport 443 counter name {MARKER_COUNTERS["literal_ip"]}',
        f'add rule inet {table_name} {MARKER_FORWARD_CHAIN} iifname "{interface}" ip saddr {client} ip daddr 169.254.169.254 tcp dport 80 counter name {MARKER_COUNTERS["metadata"]}',
        f'add rule inet {table_name} {MARKER_FORWARD_CHAIN} iifname "{interface}" ip saddr {client} ip daddr {foreign} tcp dport 5432 counter name {MARKER_COUNTERS["foreign_network"]}',
        f'add rule inet {table_name} {MARKER_OUTPUT_CHAIN} meta skuid 0 udp dport 53 @th,160,104 0x{DNS_QUESTION_HEX} counter name {MARKER_COUNTERS["external_dns"]}',
    )
    return "\n".join(
        (
            *counters,
            f"add chain inet {table_name} {MARKER_INPUT_CHAIN} {{ type filter hook input priority -20; policy accept; }}",
            f"add chain inet {table_name} {MARKER_FORWARD_CHAIN} {{ type filter hook forward priority -20; policy accept; }}",
            f"add chain inet {table_name} {MARKER_OUTPUT_CHAIN} {{ type filter hook output priority -20; policy accept; }}",
            *rules,
            "",
        )
    )


def _match(left: dict[str, Any], right: Any) -> dict[str, Any]:
    return {"match": {"op": "==", "left": left, "right": right}}


def _meta(key: str) -> dict[str, Any]:
    return {"meta": {"key": key}}


def _payload(protocol: str, field: str) -> dict[str, Any]:
    return {"payload": {"protocol": protocol, "field": field}}


def expected_marker_rule_expressions(
    table_name: str,
    interface: str,
    subnet: str,
    client_ip: str,
    service_ip: str,
    foreign_ip: str,
    gateway_ip: str,
    host_port: int,
) -> dict[str, list[list[dict[str, Any]]]]:
    # Reuse the exact batch validator so the semantic readback contract cannot
    # accept an identity that the mutation path itself would reject.
    build_marker_batch(
        table_name,
        interface,
        subnet,
        client_ip,
        service_ip,
        foreign_ip,
        gateway_ip,
        host_port,
    )
    return {
        MARKER_INPUT_CHAIN: [
            [
                _match(_meta("iifname"), interface),
                _match(_payload("ip", "saddr"), client_ip),
                _match(_payload("ip", "daddr"), gateway_ip),
                _match(_payload("icmp", "type"), "echo-request"),
                {"counter": MARKER_COUNTERS["gateway"]},
            ],
            [
                _match(_meta("iifname"), interface),
                _match(_payload("ip", "saddr"), client_ip),
                _match(_payload("ip", "daddr"), gateway_ip),
                _match(_payload("tcp", "dport"), host_port),
                {"counter": MARKER_COUNTERS["host_listener"]},
            ],
        ],
        MARKER_FORWARD_CHAIN: [
            [
                _match(_meta("iifname"), interface),
                _match(_meta("oifname"), interface),
                _match(_payload("ip", "saddr"), client_ip),
                _match(_payload("ip", "daddr"), service_ip),
                _match(_payload("tcp", "dport"), 5432),
                {"counter": MARKER_COUNTERS["same_network"]},
            ],
            [
                _match(_meta("iifname"), interface),
                _match(_payload("ip", "saddr"), client_ip),
                _match(_payload("ip", "daddr"), "1.1.1.1"),
                _match(_payload("tcp", "dport"), 443),
                {"counter": MARKER_COUNTERS["literal_ip"]},
            ],
            [
                _match(_meta("iifname"), interface),
                _match(_payload("ip", "saddr"), client_ip),
                _match(_payload("ip", "daddr"), "169.254.169.254"),
                _match(_payload("tcp", "dport"), 80),
                {"counter": MARKER_COUNTERS["metadata"]},
            ],
            [
                _match(_meta("iifname"), interface),
                _match(_payload("ip", "saddr"), client_ip),
                _match(_payload("ip", "daddr"), foreign_ip),
                _match(_payload("tcp", "dport"), 5432),
                {"counter": MARKER_COUNTERS["foreign_network"]},
            ],
        ],
        MARKER_OUTPUT_CHAIN: [
            [
                _match(_meta("skuid"), 0),
                _match(_payload("udp", "dport"), 53),
                _match(
                    {"payload": {"base": "th", "offset": 160, "len": 104}},
                    f"0x{DNS_QUESTION_HEX}",
                ),
                {"counter": MARKER_COUNTERS["external_dns"]},
            ]
        ],
    }


def validate_marker_rule_expressions(
    entries: list[dict[str, Any]],
    table_name: str,
    interface: str,
    subnet: str,
    client_ip: str,
    service_ip: str,
    foreign_ip: str,
    gateway_ip: str,
    host_port: int,
) -> str:
    expected = expected_marker_rule_expressions(
        table_name,
        interface,
        subnet,
        client_ip,
        service_ip,
        foreign_ip,
        gateway_ip,
        host_port,
    )
    observed: dict[str, list[list[dict[str, Any]]]] = {
        chain: [] for chain in expected
    }
    for entry in owned_entries(entries, table_name):
        rule = entry.get("rule")
        if not isinstance(rule, dict) or rule.get("chain") not in observed:
            continue
        _require_exact_keys(rule, {"family", "table", "chain", "expr"}, {"handle"})
        expressions = rule.get("expr")
        if (
            rule.get("family") != "inet"
            or rule.get("table") != table_name
            or not isinstance(expressions, list)
            or any(not isinstance(expression, dict) for expression in expressions)
        ):
            raise BoundaryError("FIREWALL_MARKER_INSTALLATION_MISMATCH")
        observed[rule["chain"]].append(expressions)
    if observed != expected:
        raise BoundaryError("FIREWALL_MARKER_INSTALLATION_MISMATCH")
    encoded = json.dumps(expected, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_exact_keys(payload: dict[str, Any], required: set[str], optional: set[str]) -> None:
    keys = set(payload)
    if not required.issubset(keys) or not keys.issubset(required | optional):
        raise BoundaryError("FIREWALL_INSTALLATION_MISMATCH")


def marker_entries(entries: list[dict[str, Any]], table_name: str) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    marker_counter_names = set(MARKER_COUNTERS.values())
    for entry in owned_entries(entries, table_name):
        chain = entry.get("chain")
        counter = entry.get("counter")
        rule = entry.get("rule")
        if isinstance(chain, dict) and chain.get("name") in MARKER_CHAINS:
            selected.append(entry)
        elif isinstance(counter, dict) and counter.get("name") in marker_counter_names:
            selected.append(entry)
        elif isinstance(rule, dict) and rule.get("chain") in MARKER_CHAINS:
            selected.append(entry)
    return selected


def validate_owned(
    entries: list[dict[str, Any]], table_name: str, *, markers_installed: bool = False
) -> tuple[str, dict[str, int]]:
    selected = owned_entries(entries, table_name)
    digest, counts = canonical_snapshot(selected)
    expected = (
        {"chain": 6, "counter": 10, "rule": 14, "table": 1}
        if markers_installed
        else {"chain": 3, "counter": 3, "rule": 7, "table": 1}
    )
    if counts != expected:
        raise BoundaryError("FIREWALL_INSTALLATION_MISMATCH")

    by_kind: dict[str, list[dict[str, Any]]] = {kind: [] for kind in expected}
    for entry in selected:
        if len(entry) != 1:
            raise BoundaryError("FIREWALL_INSTALLATION_MISMATCH")
        kind = next(iter(entry))
        payload = entry[kind]
        if kind not in by_kind or not isinstance(payload, dict):
            raise BoundaryError("FIREWALL_INSTALLATION_MISMATCH")
        by_kind[kind].append(payload)

    table = by_kind["table"][0]
    _require_exact_keys(table, {"family", "name"}, {"handle"})
    if table.get("family") != "inet" or table.get("name") != table_name:
        raise BoundaryError("FIREWALL_INSTALLATION_MISMATCH")

    expected_counters = {INPUT_COUNTER, FORWARD_COUNTER, OUTPUT_COUNTER}
    if markers_installed:
        expected_counters.update(MARKER_COUNTERS.values())
    counter_names: list[str] = []
    for counter in by_kind["counter"]:
        _require_exact_keys(
            counter,
            {"family", "table", "name", "packets", "bytes"},
            {"handle"},
        )
        if counter.get("family") != "inet" or counter.get("table") != table_name:
            raise BoundaryError("FIREWALL_INSTALLATION_MISMATCH")
        if any(
            not isinstance(counter.get(field), int) or counter[field] < 0
            for field in ("packets", "bytes")
        ):
            raise BoundaryError("FIREWALL_INSTALLATION_MISMATCH")
        counter_names.append(counter.get("name"))
    if len(counter_names) != len(expected_counters) or set(counter_names) != expected_counters:
        raise BoundaryError("FIREWALL_INSTALLATION_MISMATCH")

    expected_chains = {
        INPUT_CHAIN: ("input", -10),
        FORWARD_CHAIN: ("forward", -10),
        OUTPUT_CHAIN: ("output", -10),
    }
    if markers_installed:
        expected_chains.update(
            {
                MARKER_INPUT_CHAIN: ("input", -20),
                MARKER_FORWARD_CHAIN: ("forward", -20),
                MARKER_OUTPUT_CHAIN: ("output", -20),
            }
        )
    chain_names: list[str] = []
    for chain in by_kind["chain"]:
        _require_exact_keys(
            chain,
            {"family", "table", "name", "type", "hook", "prio", "policy"},
            {"handle"},
        )
        name = chain.get("name")
        if (
            chain.get("family") != "inet"
            or chain.get("table") != table_name
            or name not in expected_chains
            or chain.get("type") != "filter"
            or chain.get("hook") != expected_chains[name][0]
            or chain.get("prio") != expected_chains[name][1]
            or chain.get("policy") != "accept"
        ):
            raise BoundaryError("FIREWALL_INSTALLATION_MISMATCH")
        chain_names.append(name)
    if len(chain_names) != len(expected_chains) or set(chain_names) != set(expected_chains):
        raise BoundaryError("FIREWALL_INSTALLATION_MISMATCH")

    expected_rule_counts = {INPUT_CHAIN: 2, FORWARD_CHAIN: 3, OUTPUT_CHAIN: 2}
    if markers_installed:
        expected_rule_counts.update(
            {MARKER_INPUT_CHAIN: 2, MARKER_FORWARD_CHAIN: 4, MARKER_OUTPUT_CHAIN: 1}
        )
    observed_rule_counts = {name: 0 for name in expected_rule_counts}
    expression_digests: dict[str, set[str]] = {name: set() for name in expected_rule_counts}
    for rule in by_kind["rule"]:
        _require_exact_keys(rule, {"family", "table", "chain", "expr"}, {"handle"})
        chain = rule.get("chain")
        expressions = rule.get("expr")
        if (
            rule.get("family") != "inet"
            or rule.get("table") != table_name
            or chain not in expected_rule_counts
            or not isinstance(expressions, list)
            or not expressions
        ):
            raise BoundaryError("FIREWALL_INSTALLATION_MISMATCH")
        observed_rule_counts[chain] += 1
        expression_digest = hashlib.sha256(
            json.dumps(expressions, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if expression_digest in expression_digests[chain]:
            raise BoundaryError("FIREWALL_INSTALLATION_MISMATCH")
        expression_digests[chain].add(expression_digest)
    if observed_rule_counts != expected_rule_counts:
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
    if not isinstance(ledger.get("installed"), bool) or not isinstance(
        ledger.get("markers_installed"), bool
    ):
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
    for key in ("owned_sha256", "marker_sha256", "combined_sha256"):
        value = ledger.get(key)
        if not isinstance(value, str) or (value and not re.fullmatch(r"[0-9a-f]{64}", value)):
            raise BoundaryError("FIREWALL_LEDGER_INVALID")
    if ledger["installed"] and not ledger["owned_sha256"]:
        raise BoundaryError("FIREWALL_LEDGER_INVALID")
    if ledger["markers_installed"] != bool(
        ledger["marker_sha256"] and ledger["combined_sha256"]
    ):
        raise BoundaryError("FIREWALL_LEDGER_INVALID")
    return ledger


def install(ledger_path: Path, interface: str, subnet: str) -> None:
    if os.path.lexists(ledger_path):
        raise BoundaryError("FIREWALL_LEDGER_COLLISION")
    daemon_class, daemon_root_owned, runner_nonroot = process_ownership_preflight()
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
        "markers_installed": False,
        "marker_sha256": "",
        "combined_sha256": "",
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
            ("firewall.daemon_class", "str", daemon_class),
            ("firewall.docker_daemon_root_owned", "bool", daemon_root_owned),
            ("firewall.runner_nonroot", "bool", runner_nonroot),
            ("firewall.atomic_install", "bool", True),
            ("firewall.preimage_sha256", "str", pre_sha),
            ("firewall.preimage_table_count", "int", pre_counts.get("table", 0)),
            ("firewall.preimage_chain_count", "int", pre_counts.get("chain", 0)),
            ("firewall.preimage_rule_count", "int", pre_counts.get("rule", 0)),
            ("firewall.owned_sha256", "str", owned_sha),
            ("firewall.owned_chain_count", "int", owned_counts["chain"]),
            ("firewall.owned_counter_count", "int", owned_counts["counter"]),
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


def _validated_current_owned(
    entries: list[dict[str, Any]], ledger: dict[str, Any]
) -> tuple[str, dict[str, int]]:
    markers_installed = ledger.get("markers_installed") is True
    digest, counts = validate_owned(
        entries, TABLE, markers_installed=markers_installed
    )
    expected_digest = (
        ledger["combined_sha256"] if markers_installed else ledger["owned_sha256"]
    )
    if digest != expected_digest:
        raise BoundaryError("FIREWALL_INSTALLATION_MISMATCH")
    if markers_installed:
        marker_digest, marker_counts = canonical_snapshot(marker_entries(entries, TABLE))
        if marker_digest != ledger["marker_sha256"] or marker_counts != {
            "chain": 3,
            "counter": 7,
            "rule": 7,
        }:
            raise BoundaryError("FIREWALL_MARKER_INSTALLATION_MISMATCH")
    return digest, counts


def install_markers(
    ledger_path: Path,
    client_ip: str,
    service_ip: str,
    foreign_ip: str,
    gateway_ip: str,
    host_port: int,
) -> None:
    ledger = read_ledger(ledger_path)
    if ledger.get("installed") is not True:
        raise BoundaryError("FIREWALL_LEDGER_INVALID")
    if ledger.get("markers_installed") is True:
        raise BoundaryError("FIREWALL_MARKER_COLLISION")
    prefix, _ = privileged_prefix()
    batch = build_marker_batch(
        TABLE,
        ledger["interface"],
        ledger["subnet"],
        client_ip,
        service_ip,
        foreign_ip,
        gateway_ip,
        host_port,
    )
    checked = _run([*prefix, "--check", "-f", "-"], input_text=batch)
    if checked.returncode != 0:
        raise BoundaryError("FIREWALL_MARKER_ATOMIC_CHECK_FAILED")

    # This is the transaction preimage, not the original installation
    # preimage. Docker may legitimately change foreign nftables state while
    # packet containers are created; only change concurrent with this atomic
    # marker mutation is attributable to the marker transaction.
    before = read_ruleset(prefix)
    digest, _ = validate_owned(before, TABLE, markers_installed=False)
    if digest != ledger["owned_sha256"]:
        raise BoundaryError("FIREWALL_INSTALLATION_MISMATCH")
    foreign_sha, foreign_counts = canonical_snapshot(before, exclude_table=TABLE)
    setup_history_changed = (
        foreign_sha != ledger["preimage_sha256"]
        or foreign_counts != ledger["preimage_counts"]
    )

    applied = _run([*prefix, "-f", "-"], input_text=batch)
    if applied.returncode != 0:
        raise BoundaryError("FIREWALL_MARKER_ATOMIC_INSTALL_FAILED")

    after = read_ruleset(prefix)
    post_foreign_sha, post_foreign_counts = canonical_snapshot(
        after, exclude_table=TABLE
    )
    combined_sha, combined_counts = validate_owned(
        after, TABLE, markers_installed=True
    )
    expression_sha = validate_marker_rule_expressions(
        after,
        TABLE,
        ledger["interface"],
        ledger["subnet"],
        client_ip,
        service_ip,
        foreign_ip,
        gateway_ip,
        host_port,
    )
    marker_sha, marker_counts = canonical_snapshot(marker_entries(after, TABLE))
    if marker_counts != {"chain": 3, "counter": 7, "rule": 7}:
        raise BoundaryError("FIREWALL_MARKER_INSTALLATION_MISMATCH")
    if post_foreign_sha != foreign_sha or post_foreign_counts != foreign_counts:
        raise BoundaryError("FIREWALL_FOREIGN_STATE_DRIFT")
    ledger["markers_installed"] = True
    ledger["marker_sha256"] = marker_sha
    ledger["combined_sha256"] = combined_sha
    write_ledger(ledger_path, ledger)
    emit(
        [
            ("firewall.markers.atomic_install", "bool", True),
            (
                "firewall.markers.original_cleanup_preimage_sha256",
                "str",
                ledger["preimage_sha256"],
            ),
            ("firewall.markers.foreign_pre_sha256", "str", foreign_sha),
            (
                "firewall.markers.foreign_pre_table_count",
                "int",
                foreign_counts.get("table", 0),
            ),
            (
                "firewall.markers.foreign_pre_chain_count",
                "int",
                foreign_counts.get("chain", 0),
            ),
            (
                "firewall.markers.foreign_pre_rule_count",
                "int",
                foreign_counts.get("rule", 0),
            ),
            (
                "firewall.markers.foreign_pre_counter_count",
                "int",
                foreign_counts.get("counter", 0),
            ),
            ("firewall.markers.foreign_post_sha256", "str", post_foreign_sha),
            (
                "firewall.markers.foreign_post_table_count",
                "int",
                post_foreign_counts.get("table", 0),
            ),
            (
                "firewall.markers.foreign_post_chain_count",
                "int",
                post_foreign_counts.get("chain", 0),
            ),
            (
                "firewall.markers.foreign_post_rule_count",
                "int",
                post_foreign_counts.get("rule", 0),
            ),
            (
                "firewall.markers.foreign_post_counter_count",
                "int",
                post_foreign_counts.get("counter", 0),
            ),
            ("firewall.markers.foreign_transaction_unchanged", "bool", True),
            (
                "firewall.markers.setup_history_changed_from_original",
                "bool",
                setup_history_changed,
            ),
            ("firewall.markers.expression_contract_sha256", "str", expression_sha),
            ("firewall.markers.sha256", "str", marker_sha),
            ("firewall.markers.combined_sha256", "str", combined_sha),
            ("firewall.markers.chain_count", "int", marker_counts["chain"]),
            ("firewall.markers.counter_count", "int", marker_counts["counter"]),
            ("firewall.markers.rule_count", "int", marker_counts["rule"]),
            ("firewall.markers.owned_chain_count", "int", combined_counts["chain"]),
            ("firewall.markers.owned_counter_count", "int", combined_counts["counter"]),
            ("firewall.markers.owned_rule_count", "int", combined_counts["rule"]),
        ]
    )


def counters(ledger_path: Path) -> None:
    ledger = read_ledger(ledger_path)
    if ledger.get("installed") is not True:
        raise BoundaryError("FIREWALL_LEDGER_INVALID")
    prefix, _ = privileged_prefix()
    entries = read_ruleset(prefix)
    _validated_current_owned(entries, ledger)
    emit(
        [
            ("firewall.counters.input_deny", "int", counter_packets(entries, INPUT_COUNTER)),
            ("firewall.counters.forward_deny", "int", counter_packets(entries, FORWARD_COUNTER)),
            ("firewall.counters.output_deny", "int", counter_packets(entries, OUTPUT_COUNTER)),
        ]
    )


def marker_counters(ledger_path: Path) -> None:
    ledger = read_ledger(ledger_path)
    if ledger.get("installed") is not True or ledger.get("markers_installed") is not True:
        raise BoundaryError("FIREWALL_MARKER_LEDGER_INVALID")
    prefix, _ = privileged_prefix()
    entries = read_ruleset(prefix)
    _validated_current_owned(entries, ledger)
    emit(
        [
            (
                f"firewall.markers.counters.{key}",
                "int",
                counter_packets(entries, name),
            )
            for key, name in MARKER_COUNTERS.items()
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
    marker_parser = subparsers.add_parser("install-markers")
    marker_parser.add_argument("--ledger", required=True, type=Path)
    marker_parser.add_argument("--client-ip", required=True)
    marker_parser.add_argument("--service-ip", required=True)
    marker_parser.add_argument("--foreign-ip", required=True)
    marker_parser.add_argument("--gateway-ip", required=True)
    marker_parser.add_argument("--host-port", required=True, type=int)
    counter_parser = subparsers.add_parser("counters")
    counter_parser.add_argument("--ledger", required=True, type=Path)
    marker_counter_parser = subparsers.add_parser("marker-counters")
    marker_counter_parser.add_argument("--ledger", required=True, type=Path)
    remove_parser = subparsers.add_parser("remove")
    remove_parser.add_argument("--ledger", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "install":
            install(args.ledger, args.interface, args.subnet)
        elif args.command == "install-markers":
            install_markers(
                args.ledger,
                args.client_ip,
                args.service_ip,
                args.foreign_ip,
                args.gateway_ip,
                args.host_port,
            )
        elif args.command == "counters":
            counters(args.ledger)
        elif args.command == "marker-counters":
            marker_counters(args.ledger)
        else:
            remove(args.ledger)
    except (BoundaryError, subprocess.TimeoutExpired) as exc:
        code = exc.code if isinstance(exc, BoundaryError) else "FIREWALL_TOOL_TIMEOUT"
        emit([("firewall.failure_code", "str", code)])
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
