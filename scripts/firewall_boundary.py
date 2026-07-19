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
import time
from typing import Any


SCHEMA = "fawxzzy.hosted-replay-harness.firewall-boundary.v4"
COMPLETION_SCHEMA = "fawxzzy.hosted-replay-harness.firewall-restoration.v1"
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
MARKER_CHAIN_ORDER = (
    MARKER_INPUT_CHAIN,
    MARKER_FORWARD_CHAIN,
    MARKER_OUTPUT_CHAIN,
)
MARKER_CHAIN_CLASSES = {
    MARKER_INPUT_CHAIN: "INPUT",
    MARKER_FORWARD_CHAIN: "FORWARD",
    MARKER_OUTPUT_CHAIN: "OUTPUT",
}
MARKER_DIAGNOSTIC_SCHEMA = (
    "fawxzzy.hosted-replay-harness.marker-expression-diagnostic.v1"
)
MARKER_INTENT_SCHEMA = (
    "fawxzzy.hosted-replay-harness.marker-transaction-intent.v1"
)
MARKER_INSTALLED_SCHEMA = (
    "fawxzzy.hosted-replay-harness.marker-installed-evidence.v1"
)
MARKER_DIAGNOSTIC_STATE_FILE = (
    Path(__file__).resolve().parents[1] / "artifacts" / ".state.tsv"
)
MARKER_MISMATCH_CLASSES = frozenset(
    {
        "MATCHED_SHAPE",
        "UNSUPPORTED_STRUCTURE",
        "RULE_TYPE",
        "RULE_COUNT",
        "RULE_ORDER",
        "RULE_KEYS",
        "RULE_IDENTITY",
        "EXPRESSION_COLLECTION_TYPE",
        "EXPRESSION_COUNT",
        "EXPRESSION_ORDER",
        "EXPRESSION_TYPE",
        "EXPRESSION_KEYS",
        "EXPRESSION_KIND_OR_ORDER",
        "UNEXPECTED_VERDICT_OR_ACTION",
        "MATCH_KEYS",
        "MATCH_OPERATOR",
        "SELECTOR_TYPE",
        "SELECTOR_KIND_OR_KEYS",
        "SELECTOR_IDENTITY",
        "RIGHT_VALUE_TYPE",
        "RIGHT_VALUE_IDENTITY",
        "COUNTER_REFERENCE_SHAPE",
        "COUNTER_REFERENCE_KEYS",
        "COUNTER_DYNAMIC_FIELDS",
        "COUNTER_REFERENCE_IDENTITY",
    }
)
MARKER_EXPRESSION_KINDS = frozenset(
    {"MATCH", "COUNTER", "ACTION", "UNKNOWN", "MULTIPLE", "NON_OBJECT", "NONE"}
)
MARKER_ACTION_KEYS = frozenset(
    {"accept", "drop", "reject", "jump", "goto", "return", "queue", "masq", "snat", "dnat"}
)
MARKER_DIAGNOSTIC_PREFIX = "firewall.markers.diagnostic."
MARKER_DIAGNOSTIC_MAX_COUNT = 64
MARKER_DIAGNOSTIC_MAX_NODES = 512
MARKER_DIAGNOSTIC_MAX_DEPTH = 16
MARKER_DIAGNOSTIC_KEYS = frozenset(
    {
        "schema",
        "disposition",
        "mismatch_class",
        "chain_class",
        "rule_ordinal",
        "expression_ordinal",
        "expected_expression_kind",
        "observed_expression_kind",
        "expected_shape_sha256",
        "observed_shape_sha256",
        "shape_digests_equal",
        "expected_rule_count",
        "observed_rule_count",
        "expected_expression_count",
        "observed_expression_count",
        "count_truncated",
        "expected_shape_supported",
        "observed_shape_supported",
        "matched_shape",
    }
)
MARKER_INTENT_KEYS = frozenset(
    {
        "schema",
        "table",
        "base_ledger_sha256",
        "client_ip",
        "service_ip",
        "foreign_ip",
        "gateway_ip",
        "host_port",
        "batch_sha256",
        "evidence_sha256",
    }
)
MARKER_INSTALLED_KEYS = frozenset(
    {
        "schema",
        "table",
        "base_ledger_sha256",
        "intent_evidence_sha256",
        "marker_sha256",
        "combined_sha256",
        "diagnostic_sha256",
        "mismatch_class",
        "expected_shape_sha256",
        "observed_shape_sha256",
        "effective_ledger_sha256",
        "evidence_sha256",
    }
)
# DNS question wire identity for the fixed public canary name already frozen in
# the runner.  It is matched only transiently and is never emitted in state.
DNS_QUESTION_HEX = "076578616d706c6503636f6d00"
VERSION_RE = re.compile(r"^nftables v([0-9]+)\.([0-9]+)\.([0-9]+)(?:[ -].*)?$")
SAFE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
SAFE_IFACE_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,15}$")
SAFE_SUBNET_RE = re.compile(r"^[0-9]{1,3}(?:\.[0-9]{1,3}){3}/[0-9]{1,2}$")
RESTORATION_POLL_ATTEMPTS = 20
RESTORATION_POLL_INTERVAL_SECONDS = 0.5
LEDGER_KEYS = {
    "schema",
    "table",
    "interface",
    "subnet",
    "preimage_sha256",
    "preimage_semantic_sha256",
    "preimage_counts",
    "installation_sha256",
    "installation_semantic_sha256",
    "installation_counts",
    "installed",
    "owned_sha256",
    "markers_installed",
    "marker_sha256",
    "combined_sha256",
}
COMPLETION_KEYS = {
    "schema",
    "table",
    "ledger_sha256",
    "preimage_sha256",
    "preimage_counts_sha256",
    "postimage_sha256",
    "postimage_counts_sha256",
    "restored",
    "evidence_sha256",
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
    sys.stdout.flush()
    try:
        os.fsync(sys.stdout.fileno())
    except (AttributeError, OSError, ValueError):
        # Tests and callers may intentionally use an in-memory sanitized sink.
        pass


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


def semantic_snapshot(
    entries: list[dict[str, Any]], *, exclude_table: str | None = None
) -> str:
    """Hash semantic topology while ignoring only safe top-level list ordering.

    Independent nft object records may be serialized in a different top-level
    order. Rule order within each exact chain remains ordered and therefore
    semantic. All object fields continue to use the same narrow volatile-field
    exclusions as ``canonical_snapshot``.
    """

    non_rules: list[str] = []
    rule_groups: dict[str, list[Any]] = {}
    for entry in entries:
        if "metainfo" in entry:
            continue
        if exclude_table and belongs_to_table(entry, exclude_table):
            continue
        canonical = _canonicalize(entry)
        rule = canonical.get("rule") if isinstance(canonical, dict) else None
        if isinstance(rule, dict):
            identity = [rule.get("family"), rule.get("table"), rule.get("chain")]
            identity_key = json.dumps(identity, sort_keys=True, separators=(",", ":"))
            rule_groups.setdefault(identity_key, []).append(canonical)
        else:
            non_rules.append(json.dumps(canonical, sort_keys=True, separators=(",", ":")))
    normalized = {
        "non_rules": sorted(non_rules),
        "rule_groups": [
            {"identity": identity, "rules": rule_groups[identity]}
            for identity in sorted(rule_groups)
        ],
    }
    return canonical_json_sha256(normalized)


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


def _redacted_shape_digest(value: Any) -> tuple[str, bool]:
    remaining = [MARKER_DIAGNOSTIC_MAX_NODES]
    supported = [True]

    def project(current: Any, depth: int, parent_key: str = "") -> Any:
        if depth > MARKER_DIAGNOSTIC_MAX_DEPTH or remaining[0] <= 0:
            supported[0] = False
            return {"$type": "LIMIT"}
        remaining[0] -= 1
        if current is None:
            return {"$type": "NULL"}
        if isinstance(current, bool):
            return {"$type": "BOOL"}
        if isinstance(current, int):
            return {"$type": "INT"}
        if isinstance(current, float):
            return {"$type": "NUMBER"}
        if isinstance(current, str):
            if parent_key == "op":
                return {"$type": "OPERATOR_EQ" if current == "==" else "OPERATOR_OTHER"}
            return {"$type": "STRING"}
        if isinstance(current, list):
            return [project(item, depth + 1) for item in current]
        if isinstance(current, dict):
            if any(not isinstance(key, str) for key in current):
                supported[0] = False
                return {"$type": "NON_STRING_KEY_OBJECT"}
            return {
                key: project(current[key], depth + 1, key)
                for key in sorted(current)
            }
        supported[0] = False
        return {"$type": "UNSUPPORTED"}

    encoded = json.dumps(
        project(value, 0), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest(), supported[0]


def _marker_expression_kind(value: Any) -> str:
    if not isinstance(value, dict):
        return "NON_OBJECT"
    keys = set(value)
    if len(keys) != 1:
        return "MULTIPLE" if keys else "UNKNOWN"
    key = next(iter(keys))
    if key == "match":
        return "MATCH"
    if key == "counter":
        return "COUNTER"
    if key in MARKER_ACTION_KEYS:
        return "ACTION"
    return "UNKNOWN"


def _literal_type_class(value: Any) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "BOOL"
    if isinstance(value, int):
        return "INT"
    if isinstance(value, float):
        return "NUMBER"
    if isinstance(value, str):
        return "STRING"
    if isinstance(value, list):
        return "LIST"
    if isinstance(value, dict):
        return "OBJECT"
    return "UNSUPPORTED"


def _strict_json_equal(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(
            _strict_json_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _strict_json_equal(left_item, right_item)
            for left_item, right_item in zip(left, right)
        )
    return left == right


def _bounded_diagnostic_count(value: int) -> tuple[int, bool]:
    return min(max(value, 0), MARKER_DIAGNOSTIC_MAX_COUNT), value > MARKER_DIAGNOSTIC_MAX_COUNT


def diagnose_marker_rule_expressions(
    entries: list[dict[str, Any]],
    table_name: str,
    interface: str,
    subnet: str,
    client_ip: str,
    service_ip: str,
    foreign_ip: str,
    gateway_ip: str,
    host_port: int,
) -> dict[str, Any]:
    expected_expressions = expected_marker_rule_expressions(
        table_name,
        interface,
        subnet,
        client_ip,
        service_ip,
        foreign_ip,
        gateway_ip,
        host_port,
    )
    expected_rules = {
        chain: [
            {
                "family": "inet",
                "table": table_name,
                "chain": chain,
                "expr": expressions,
            }
            for expressions in expected_expressions[chain]
        ]
        for chain in MARKER_CHAIN_ORDER
    }
    observed_rules: dict[str, list[Any]] = {chain: [] for chain in MARKER_CHAIN_ORDER}
    malformed_rule: Any | None = None
    if not isinstance(entries, list):
        malformed_rule = entries
    else:
        for entry in entries:
            if not isinstance(entry, dict):
                malformed_rule = entry
                break
            rule = entry.get("rule")
            if rule is None:
                continue
            if not isinstance(rule, dict):
                if set(entry) == {"rule"}:
                    malformed_rule = rule
                    break
                continue
            if rule.get("table") == table_name and rule.get("chain") in observed_rules:
                observed_rules[rule["chain"]].append(rule)

    expected_shape_source = {
        chain: [rule["expr"] for rule in expected_rules[chain]]
        for chain in MARKER_CHAIN_ORDER
    }
    observed_shape_source = {
        chain: [
            rule.get("expr")
            if isinstance(rule, dict)
            else rule
            for rule in observed_rules[chain]
        ]
        for chain in MARKER_CHAIN_ORDER
    }
    expected_shape_sha, expected_supported = _redacted_shape_digest(
        expected_shape_source
    )
    observed_shape_sha, observed_supported = _redacted_shape_digest(
        observed_shape_source
        if malformed_rule is None
        else {"malformed_rule": malformed_rule}
    )

    def result(
        mismatch_class: str,
        *,
        chain: str | None = None,
        rule_ordinal: int = 0,
        expression_ordinal: int = 0,
        expected_kind: str = "NONE",
        observed_kind: str = "NONE",
        expected_expression_count: int = 0,
        observed_expression_count: int = 0,
    ) -> dict[str, Any]:
        if mismatch_class not in MARKER_MISMATCH_CLASSES:
            raise BoundaryError("FIREWALL_MARKER_DIAGNOSTIC_INVALID")
        expected_rule_count, expected_rule_truncated = _bounded_diagnostic_count(
            sum(len(rules) for rules in expected_rules.values())
        )
        observed_rule_count, observed_rule_truncated = _bounded_diagnostic_count(
            sum(len(rules) for rules in observed_rules.values())
        )
        expected_expr_count, expected_expr_truncated = _bounded_diagnostic_count(
            expected_expression_count
        )
        observed_expr_count, observed_expr_truncated = _bounded_diagnostic_count(
            observed_expression_count
        )
        matched = mismatch_class == "MATCHED_SHAPE"
        return {
            "schema": MARKER_DIAGNOSTIC_SCHEMA,
            "disposition": (
                "DIAGNOSTIC_STOP_MATCHED_SHAPE"
                if matched
                else "DIAGNOSTIC_STOP_MISMATCH"
            ),
            "mismatch_class": mismatch_class,
            "chain_class": MARKER_CHAIN_CLASSES.get(chain, "NONE"),
            "rule_ordinal": rule_ordinal,
            "expression_ordinal": expression_ordinal,
            "expected_expression_kind": expected_kind,
            "observed_expression_kind": observed_kind,
            "expected_shape_sha256": expected_shape_sha,
            "observed_shape_sha256": observed_shape_sha,
            "shape_digests_equal": expected_shape_sha == observed_shape_sha,
            "expected_rule_count": expected_rule_count,
            "observed_rule_count": observed_rule_count,
            "expected_expression_count": expected_expr_count,
            "observed_expression_count": observed_expr_count,
            "count_truncated": any(
                (
                    expected_rule_truncated,
                    observed_rule_truncated,
                    expected_expr_truncated,
                    observed_expr_truncated,
                )
            ),
            "expected_shape_supported": expected_supported,
            "observed_shape_supported": observed_supported,
            "matched_shape": matched,
        }

    if not expected_supported or not observed_supported:
        return result("UNSUPPORTED_STRUCTURE")
    if malformed_rule is not None:
        return result("RULE_TYPE")

    for chain in MARKER_CHAIN_ORDER:
        expected_chain_rules = expected_rules[chain]
        observed_chain_rules = observed_rules[chain]
        if len(observed_chain_rules) != len(expected_chain_rules):
            return result("RULE_COUNT", chain=chain)
        for rule_index, (expected_rule, observed_rule) in enumerate(
            zip(expected_chain_rules, observed_chain_rules), start=1
        ):
            if not isinstance(observed_rule, dict):
                return result("RULE_TYPE", chain=chain, rule_ordinal=rule_index)
            if not {"family", "table", "chain", "expr"}.issubset(observed_rule) or not set(
                observed_rule
            ).issubset({"family", "table", "chain", "expr", "handle"}):
                return result("RULE_KEYS", chain=chain, rule_ordinal=rule_index)
            if any(
                observed_rule.get(key) != expected_rule[key]
                for key in ("family", "table", "chain")
            ):
                return result("RULE_IDENTITY", chain=chain, rule_ordinal=rule_index)
            expected_items = expected_rule["expr"]
            observed_items = observed_rule.get("expr")
            if (
                isinstance(observed_items, list)
                and not _strict_json_equal(observed_items, expected_items)
                and any(
                    _strict_json_equal(observed_items, candidate["expr"])
                    for candidate_index, candidate in enumerate(
                        expected_chain_rules, start=1
                    )
                    if candidate_index != rule_index
                )
            ):
                return result("RULE_ORDER", chain=chain, rule_ordinal=rule_index)
            if not isinstance(observed_items, list):
                return result(
                    "EXPRESSION_COLLECTION_TYPE",
                    chain=chain,
                    rule_ordinal=rule_index,
                    expected_expression_count=len(expected_items),
                )
            if len(observed_items) != len(expected_items):
                return result(
                    "EXPRESSION_COUNT",
                    chain=chain,
                    rule_ordinal=rule_index,
                    expected_expression_count=len(expected_items),
                    observed_expression_count=len(observed_items),
                )
            if not _strict_json_equal(observed_items, expected_items) and sorted(
                canonical_json_sha256(item) for item in observed_items
            ) == sorted(canonical_json_sha256(item) for item in expected_items):
                return result(
                    "EXPRESSION_ORDER",
                    chain=chain,
                    rule_ordinal=rule_index,
                    expected_expression_count=len(expected_items),
                    observed_expression_count=len(observed_items),
                )
            for expression_index, (expected_item, observed_item) in enumerate(
                zip(expected_items, observed_items), start=1
            ):
                expected_kind = _marker_expression_kind(expected_item)
                observed_kind = _marker_expression_kind(observed_item)
                common = {
                    "chain": chain,
                    "rule_ordinal": rule_index,
                    "expression_ordinal": expression_index,
                    "expected_kind": expected_kind,
                    "observed_kind": observed_kind,
                    "expected_expression_count": len(expected_items),
                    "observed_expression_count": len(observed_items),
                }
                if not isinstance(observed_item, dict):
                    return result("EXPRESSION_TYPE", **common)
                observed_keys = set(observed_item)
                if observed_keys & MARKER_ACTION_KEYS:
                    return result("UNEXPECTED_VERDICT_OR_ACTION", **common)
                if len(observed_keys) != 1:
                    return result("EXPRESSION_KEYS", **common)
                if observed_kind != expected_kind:
                    return result("EXPRESSION_KIND_OR_ORDER", **common)
                if expected_kind == "MATCH":
                    expected_match = expected_item["match"]
                    observed_match = observed_item.get("match")
                    if not isinstance(observed_match, dict) or set(observed_match) != {
                        "op",
                        "left",
                        "right",
                    }:
                        return result("MATCH_KEYS", **common)
                    if observed_match.get("op") != expected_match["op"]:
                        return result("MATCH_OPERATOR", **common)
                    expected_left = expected_match["left"]
                    observed_left = observed_match.get("left")
                    if not isinstance(observed_left, dict):
                        return result("SELECTOR_TYPE", **common)
                    if set(observed_left) != set(expected_left):
                        return result("SELECTOR_KIND_OR_KEYS", **common)
                    selector_key = next(iter(expected_left))
                    expected_selector = expected_left[selector_key]
                    observed_selector = observed_left.get(selector_key)
                    if not isinstance(observed_selector, dict):
                        return result("SELECTOR_TYPE", **common)
                    if set(observed_selector) != set(expected_selector):
                        return result("SELECTOR_KIND_OR_KEYS", **common)
                    if not _strict_json_equal(observed_selector, expected_selector):
                        return result("SELECTOR_IDENTITY", **common)
                    expected_right = expected_match["right"]
                    observed_right = observed_match.get("right")
                    if _literal_type_class(observed_right) != _literal_type_class(
                        expected_right
                    ):
                        return result("RIGHT_VALUE_TYPE", **common)
                    if not _strict_json_equal(observed_right, expected_right):
                        return result("RIGHT_VALUE_IDENTITY", **common)
                elif expected_kind == "COUNTER":
                    expected_counter = expected_item["counter"]
                    observed_counter = observed_item.get("counter")
                    if isinstance(observed_counter, dict):
                        counter_keys = set(observed_counter)
                        if counter_keys & {"packets", "bytes"}:
                            return result("COUNTER_DYNAMIC_FIELDS", **common)
                        if counter_keys != {"name"}:
                            return result("COUNTER_REFERENCE_KEYS", **common)
                        return result("COUNTER_REFERENCE_SHAPE", **common)
                    if not isinstance(observed_counter, str):
                        return result("COUNTER_REFERENCE_SHAPE", **common)
                    if observed_counter != expected_counter:
                        return result("COUNTER_REFERENCE_IDENTITY", **common)
                else:
                    return result("EXPRESSION_KIND_OR_ORDER", **common)
    return result("MATCHED_SHAPE")


def marker_diagnostic_state_rows(
    diagnostic: dict[str, Any],
) -> list[tuple[str, str, Any]]:
    if set(diagnostic) != MARKER_DIAGNOSTIC_KEYS:
        raise BoundaryError("FIREWALL_MARKER_DIAGNOSTIC_INVALID")
    mismatch_class = diagnostic.get("mismatch_class")
    matched = mismatch_class == "MATCHED_SHAPE"
    if (
        diagnostic.get("schema") != MARKER_DIAGNOSTIC_SCHEMA
        or mismatch_class not in MARKER_MISMATCH_CLASSES
        or diagnostic.get("disposition")
        != (
            "DIAGNOSTIC_STOP_MATCHED_SHAPE"
            if matched
            else "DIAGNOSTIC_STOP_MISMATCH"
        )
        or diagnostic.get("chain_class") not in {"INPUT", "FORWARD", "OUTPUT", "NONE"}
        or diagnostic.get("expected_expression_kind") not in MARKER_EXPRESSION_KINDS
        or diagnostic.get("observed_expression_kind") not in MARKER_EXPRESSION_KINDS
        or diagnostic.get("matched_shape") is not matched
        or diagnostic.get("expected_shape_supported") is not True
        or diagnostic.get("shape_digests_equal")
        is not (
            diagnostic.get("expected_shape_sha256")
            == diagnostic.get("observed_shape_sha256")
        )
    ):
        raise BoundaryError("FIREWALL_MARKER_DIAGNOSTIC_INVALID")
    for key in (
        "expected_shape_sha256",
        "observed_shape_sha256",
    ):
        if not isinstance(diagnostic.get(key), str) or not re.fullmatch(
            r"[0-9a-f]{64}", diagnostic[key]
        ):
            raise BoundaryError("FIREWALL_MARKER_DIAGNOSTIC_INVALID")
    for key in (
        "shape_digests_equal",
        "count_truncated",
        "expected_shape_supported",
        "observed_shape_supported",
        "matched_shape",
    ):
        if not isinstance(diagnostic.get(key), bool):
            raise BoundaryError("FIREWALL_MARKER_DIAGNOSTIC_INVALID")
    for key in (
        "rule_ordinal",
        "expression_ordinal",
        "expected_rule_count",
        "observed_rule_count",
        "expected_expression_count",
        "observed_expression_count",
    ):
        value = diagnostic.get(key)
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 0 <= value <= MARKER_DIAGNOSTIC_MAX_COUNT
        ):
            raise BoundaryError("FIREWALL_MARKER_DIAGNOSTIC_INVALID")
    if diagnostic["expected_rule_count"] != 7:
        raise BoundaryError("FIREWALL_MARKER_DIAGNOSTIC_INVALID")
    return [
        (f"{MARKER_DIAGNOSTIC_PREFIX}schema", "str", diagnostic["schema"]),
        (
            f"{MARKER_DIAGNOSTIC_PREFIX}disposition",
            "str",
            diagnostic["disposition"],
        ),
        (
            f"{MARKER_DIAGNOSTIC_PREFIX}mismatch_class",
            "str",
            diagnostic["mismatch_class"],
        ),
        (
            f"{MARKER_DIAGNOSTIC_PREFIX}chain_class",
            "str",
            diagnostic["chain_class"],
        ),
        (
            f"{MARKER_DIAGNOSTIC_PREFIX}rule_ordinal",
            "int",
            diagnostic["rule_ordinal"],
        ),
        (
            f"{MARKER_DIAGNOSTIC_PREFIX}expression_ordinal",
            "int",
            diagnostic["expression_ordinal"],
        ),
        (
            f"{MARKER_DIAGNOSTIC_PREFIX}expected_expression_kind",
            "str",
            diagnostic["expected_expression_kind"],
        ),
        (
            f"{MARKER_DIAGNOSTIC_PREFIX}observed_expression_kind",
            "str",
            diagnostic["observed_expression_kind"],
        ),
        (
            f"{MARKER_DIAGNOSTIC_PREFIX}expected_shape_sha256",
            "str",
            diagnostic["expected_shape_sha256"],
        ),
        (
            f"{MARKER_DIAGNOSTIC_PREFIX}observed_shape_sha256",
            "str",
            diagnostic["observed_shape_sha256"],
        ),
        (
            f"{MARKER_DIAGNOSTIC_PREFIX}shape_digests_equal",
            "bool",
            diagnostic["shape_digests_equal"],
        ),
        (
            f"{MARKER_DIAGNOSTIC_PREFIX}expected_rule_count",
            "int",
            diagnostic["expected_rule_count"],
        ),
        (
            f"{MARKER_DIAGNOSTIC_PREFIX}observed_rule_count",
            "int",
            diagnostic["observed_rule_count"],
        ),
        (
            f"{MARKER_DIAGNOSTIC_PREFIX}expected_expression_count",
            "int",
            diagnostic["expected_expression_count"],
        ),
        (
            f"{MARKER_DIAGNOSTIC_PREFIX}observed_expression_count",
            "int",
            diagnostic["observed_expression_count"],
        ),
        (
            f"{MARKER_DIAGNOSTIC_PREFIX}count_truncated",
            "bool",
            diagnostic["count_truncated"],
        ),
        (
            f"{MARKER_DIAGNOSTIC_PREFIX}expected_shape_supported",
            "bool",
            diagnostic["expected_shape_supported"],
        ),
        (
            f"{MARKER_DIAGNOSTIC_PREFIX}observed_shape_supported",
            "bool",
            diagnostic["observed_shape_supported"],
        ),
        (
            f"{MARKER_DIAGNOSTIC_PREFIX}matched_shape",
            "bool",
            diagnostic["matched_shape"],
        ),
        (f"{MARKER_DIAGNOSTIC_PREFIX}atomic_install", "bool", True),
        (
            f"{MARKER_DIAGNOSTIC_PREFIX}foreign_transaction_unchanged",
            "bool",
            True,
        ),
        (f"{MARKER_DIAGNOSTIC_PREFIX}ledger_recorded", "bool", True),
        (f"{MARKER_DIAGNOSTIC_PREFIX}canaries_reachable", "bool", False),
    ]


def publish_marker_diagnostic_state(
    rows: list[tuple[str, str, Any]],
    state_path: Path | None = None,
) -> None:
    if state_path is None:
        state_path = MARKER_DIAGNOSTIC_STATE_FILE
    expected_keys = {
        f"{MARKER_DIAGNOSTIC_PREFIX}{suffix}"
        for suffix in (
            "schema",
            "disposition",
            "mismatch_class",
            "chain_class",
            "rule_ordinal",
            "expression_ordinal",
            "expected_expression_kind",
            "observed_expression_kind",
            "expected_shape_sha256",
            "observed_shape_sha256",
            "shape_digests_equal",
            "expected_rule_count",
            "observed_rule_count",
            "expected_expression_count",
            "observed_expression_count",
            "count_truncated",
            "expected_shape_supported",
            "observed_shape_supported",
            "matched_shape",
            "atomic_install",
            "foreign_transaction_unchanged",
            "ledger_recorded",
            "canaries_reachable",
        )
    }
    if len(rows) != len(expected_keys) or {row[0] for row in rows} != expected_keys:
        raise BoundaryError("FIREWALL_MARKER_DIAGNOSTIC_INVALID")
    for key, kind, value in rows:
        if kind == "bool" and not isinstance(value, bool):
            raise BoundaryError("FIREWALL_MARKER_DIAGNOSTIC_INVALID")
        if kind == "int" and (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 0 <= value <= MARKER_DIAGNOSTIC_MAX_COUNT
        ):
            raise BoundaryError("FIREWALL_MARKER_DIAGNOSTIC_INVALID")
        if kind == "str" and (
            not isinstance(value, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,96}|[0-9a-f]{64}", value)
        ):
            raise BoundaryError("FIREWALL_MARKER_DIAGNOSTIC_INVALID")
        if kind not in {"bool", "int", "str"} or not key.startswith(
            MARKER_DIAGNOSTIC_PREFIX
        ):
            raise BoundaryError("FIREWALL_MARKER_DIAGNOSTIC_INVALID")
    payload = ("\n".join(state_line(*row) for row in rows) + "\n").encode("utf-8")
    if len(payload) > 4096:
        raise BoundaryError("FIREWALL_MARKER_DIAGNOSTIC_INVALID")
    try:
        before = os.lstat(state_path)
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
            raise BoundaryError("FIREWALL_DIAGNOSTIC_STATE_PUBLICATION_FAILED")
        if os.name != "nt" and before.st_mode & 0o077:
            raise BoundaryError("FIREWALL_DIAGNOSTIC_STATE_PUBLICATION_FAILED")
        existing = state_path.read_bytes()
        if len(existing) > 1024 * 1024 or MARKER_DIAGNOSTIC_PREFIX.encode() in existing:
            raise BoundaryError("FIREWALL_DIAGNOSTIC_STATE_PUBLICATION_FAILED")
        flags = os.O_WRONLY | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(state_path, flags)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise BoundaryError("FIREWALL_DIAGNOSTIC_STATE_PUBLICATION_FAILED")
            if os.write(descriptor, payload) != len(payload):
                raise BoundaryError("FIREWALL_DIAGNOSTIC_STATE_PUBLICATION_FAILED")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except BoundaryError:
        raise
    except (OSError, ValueError) as exc:
        raise BoundaryError("FIREWALL_DIAGNOSTIC_STATE_PUBLICATION_FAILED") from exc


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
    diagnostic = diagnose_marker_rule_expressions(
        entries,
        table_name,
        interface,
        subnet,
        client_ip,
        service_ip,
        foreign_ip,
        gateway_ip,
        host_port,
    )
    if diagnostic["mismatch_class"] != "MATCHED_SHAPE":
        raise BoundaryError("FIREWALL_MARKER_INSTALLATION_MISMATCH")
    return diagnostic["expected_shape_sha256"]


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


def canonical_json_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def restoration_completion_path(ledger_path: Path) -> Path:
    return ledger_path.with_name(f"{ledger_path.name}.restoration-complete")


def restoration_stage_path(completion_path: Path) -> Path:
    return completion_path.with_name(f".{completion_path.name}.stage")


def ledger_sha256(ledger: dict[str, Any]) -> str:
    return canonical_json_sha256(ledger)


def marker_intent_path(ledger_path: Path) -> Path:
    return ledger_path.with_name(f"{ledger_path.name}.marker-intent")


def marker_installed_path(ledger_path: Path) -> Path:
    return ledger_path.with_name(f"{ledger_path.name}.marker-installed")


def marker_evidence_stage_path(path: Path) -> Path:
    return path.with_name(f".{path.name}.stage")


def marker_evidence_sha256(evidence: dict[str, Any]) -> str:
    return canonical_json_sha256(
        {key: value for key, value in evidence.items() if key != "evidence_sha256"}
    )


def _validate_sha256(value: Any, failure_code: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise BoundaryError(failure_code)
    return value


def validate_marker_intent(
    intent: Any, ledger: dict[str, Any] | None = None
) -> dict[str, Any]:
    failure = "FIREWALL_MARKER_STATE_INVALID"
    if not isinstance(intent, dict) or set(intent) != MARKER_INTENT_KEYS:
        raise BoundaryError(failure)
    if intent.get("schema") != MARKER_INTENT_SCHEMA or intent.get("table") != TABLE:
        raise BoundaryError(failure)
    for key in ("base_ledger_sha256", "batch_sha256", "evidence_sha256"):
        _validate_sha256(intent.get(key), failure)
    for key in ("client_ip", "service_ip", "foreign_ip", "gateway_ip"):
        value = intent.get(key)
        try:
            parsed = ipaddress.ip_address(value)
        except (TypeError, ValueError) as exc:
            raise BoundaryError(failure) from exc
        if parsed.version != 4 or str(parsed) != value:
            raise BoundaryError(failure)
    host_port = intent.get("host_port")
    if (
        not isinstance(host_port, int)
        or isinstance(host_port, bool)
        or not 1 <= host_port <= 65535
    ):
        raise BoundaryError(failure)
    if intent["evidence_sha256"] != marker_evidence_sha256(intent):
        raise BoundaryError(failure)
    if ledger is not None:
        if (
            ledger.get("installed") is not True
            or ledger.get("markers_installed") is not False
            or intent["base_ledger_sha256"] != ledger_sha256(ledger)
        ):
            raise BoundaryError(failure)
        batch = build_marker_batch(
            TABLE,
            ledger["interface"],
            ledger["subnet"],
            intent["client_ip"],
            intent["service_ip"],
            intent["foreign_ip"],
            intent["gateway_ip"],
            intent["host_port"],
        )
        if intent["batch_sha256"] != hashlib.sha256(batch.encode("utf-8")).hexdigest():
            raise BoundaryError(failure)
    return intent


def build_marker_intent(
    ledger: dict[str, Any],
    client_ip: str,
    service_ip: str,
    foreign_ip: str,
    gateway_ip: str,
    host_port: int,
    batch: str,
) -> dict[str, Any]:
    intent = {
        "schema": MARKER_INTENT_SCHEMA,
        "table": TABLE,
        "base_ledger_sha256": ledger_sha256(ledger),
        "client_ip": client_ip,
        "service_ip": service_ip,
        "foreign_ip": foreign_ip,
        "gateway_ip": gateway_ip,
        "host_port": host_port,
        "batch_sha256": hashlib.sha256(batch.encode("utf-8")).hexdigest(),
        "evidence_sha256": "",
    }
    intent["evidence_sha256"] = marker_evidence_sha256(intent)
    return validate_marker_intent(intent, ledger)


def overlay_marker_ledger(
    ledger: dict[str, Any], marker_sha256: str, combined_sha256: str
) -> dict[str, Any]:
    if ledger.get("markers_installed") is not False:
        raise BoundaryError("FIREWALL_MARKER_STATE_INVALID")
    _validate_sha256(marker_sha256, "FIREWALL_MARKER_STATE_INVALID")
    _validate_sha256(combined_sha256, "FIREWALL_MARKER_STATE_INVALID")
    effective = dict(ledger)
    effective["markers_installed"] = True
    effective["marker_sha256"] = marker_sha256
    effective["combined_sha256"] = combined_sha256
    return effective


def validate_marker_installed(
    installed: Any,
    ledger: dict[str, Any] | None = None,
    intent: dict[str, Any] | None = None,
) -> dict[str, Any]:
    failure = "FIREWALL_MARKER_STATE_INVALID"
    if not isinstance(installed, dict) or set(installed) != MARKER_INSTALLED_KEYS:
        raise BoundaryError(failure)
    if installed.get("schema") != MARKER_INSTALLED_SCHEMA or installed.get("table") != TABLE:
        raise BoundaryError(failure)
    for key in (
        "base_ledger_sha256",
        "intent_evidence_sha256",
        "marker_sha256",
        "combined_sha256",
        "diagnostic_sha256",
        "expected_shape_sha256",
        "observed_shape_sha256",
        "effective_ledger_sha256",
        "evidence_sha256",
    ):
        _validate_sha256(installed.get(key), failure)
    if installed.get("mismatch_class") not in MARKER_MISMATCH_CLASSES:
        raise BoundaryError(failure)
    if installed["evidence_sha256"] != marker_evidence_sha256(installed):
        raise BoundaryError(failure)
    if ledger is not None:
        if installed["base_ledger_sha256"] != ledger_sha256(ledger):
            raise BoundaryError(failure)
        effective = overlay_marker_ledger(
            ledger, installed["marker_sha256"], installed["combined_sha256"]
        )
        if installed["effective_ledger_sha256"] != ledger_sha256(effective):
            raise BoundaryError(failure)
    if intent is not None:
        validate_marker_intent(intent, ledger)
        if (
            installed["intent_evidence_sha256"] != intent["evidence_sha256"]
            or installed["base_ledger_sha256"] != intent["base_ledger_sha256"]
        ):
            raise BoundaryError(failure)
    return installed


def build_marker_installed(
    ledger: dict[str, Any],
    intent: dict[str, Any],
    marker_sha256: str,
    combined_sha256: str,
    diagnostic: dict[str, Any],
) -> dict[str, Any]:
    validate_marker_intent(intent, ledger)
    marker_diagnostic_state_rows(diagnostic)
    effective = overlay_marker_ledger(ledger, marker_sha256, combined_sha256)
    installed = {
        "schema": MARKER_INSTALLED_SCHEMA,
        "table": TABLE,
        "base_ledger_sha256": ledger_sha256(ledger),
        "intent_evidence_sha256": intent["evidence_sha256"],
        "marker_sha256": marker_sha256,
        "combined_sha256": combined_sha256,
        "diagnostic_sha256": canonical_json_sha256(diagnostic),
        "mismatch_class": diagnostic["mismatch_class"],
        "expected_shape_sha256": diagnostic["expected_shape_sha256"],
        "observed_shape_sha256": diagnostic["observed_shape_sha256"],
        "effective_ledger_sha256": ledger_sha256(effective),
        "evidence_sha256": "",
    }
    installed["evidence_sha256"] = marker_evidence_sha256(installed)
    return validate_marker_installed(installed, ledger, intent)


def _read_private_marker_evidence(path: Path) -> dict[str, Any]:
    failure = "FIREWALL_MARKER_STATE_INVALID"
    try:
        observed = path.lstat()
    except OSError as exc:
        raise BoundaryError(failure) from exc
    if not stat.S_ISREG(observed.st_mode) or stat.S_ISLNK(observed.st_mode):
        raise BoundaryError(failure)
    if os.name != "nt" and observed.st_mode & 0o077:
        raise BoundaryError(failure)
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_strict_json_object
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise BoundaryError(failure) from exc
    if not isinstance(value, dict):
        raise BoundaryError(failure)
    return value


def read_marker_intent(path: Path, ledger: dict[str, Any] | None = None) -> dict[str, Any]:
    return validate_marker_intent(_read_private_marker_evidence(path), ledger)


def read_marker_installed(
    path: Path,
    ledger: dict[str, Any] | None = None,
    intent: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return validate_marker_installed(
        _read_private_marker_evidence(path), ledger, intent
    )


def _reconcile_marker_evidence_stage(path: Path) -> None:
    stage_path = marker_evidence_stage_path(path)
    if not os.path.lexists(stage_path):
        return
    try:
        observed = stage_path.lstat()
    except OSError as exc:
        raise BoundaryError("FIREWALL_MARKER_STATE_INVALID") from exc
    if not stat.S_ISREG(observed.st_mode) or stat.S_ISLNK(observed.st_mode):
        raise BoundaryError("FIREWALL_MARKER_STATE_INVALID")
    if os.name != "nt" and observed.st_mode & 0o077:
        raise BoundaryError("FIREWALL_MARKER_STATE_INVALID")
    if os.path.lexists(path):
        try:
            if not os.path.samefile(stage_path, path):
                raise BoundaryError("FIREWALL_MARKER_STATE_INVALID")
        except OSError as exc:
            raise BoundaryError("FIREWALL_MARKER_STATE_INVALID") from exc
    _retire_private_path(stage_path, "FIREWALL_MARKER_STATE_PERSISTENCE_FAILED")


def _write_marker_evidence(
    path: Path, evidence: dict[str, Any], validator: Any
) -> None:
    validator(evidence)
    _reconcile_marker_evidence_stage(path)
    if os.path.lexists(path):
        raise BoundaryError("FIREWALL_MARKER_STATE_COLLISION")
    path.parent.mkdir(parents=True, exist_ok=True)
    stage_path = marker_evidence_stage_path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(stage_path, flags, 0o600)
        payload = (
            json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        if os.write(descriptor, payload) != len(payload):
            raise OSError("partial marker evidence write")
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.chmod(stage_path, 0o600)
        os.link(stage_path, path)
        _fsync_parent(path)
    except (BoundaryError, OSError) as exc:
        if isinstance(exc, BoundaryError):
            raise
        raise BoundaryError("FIREWALL_MARKER_STATE_PERSISTENCE_FAILED") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if os.path.lexists(stage_path):
            try:
                stage_path.unlink()
            except OSError as exc:
                raise BoundaryError("FIREWALL_MARKER_STATE_PERSISTENCE_FAILED") from exc


def write_marker_intent(path: Path, intent: dict[str, Any]) -> None:
    _write_marker_evidence(path, intent, validate_marker_intent)


def write_marker_installed(path: Path, installed: dict[str, Any]) -> None:
    _write_marker_evidence(path, installed, validate_marker_installed)


def counts_sha256(counts: dict[str, int]) -> str:
    return canonical_json_sha256(counts)


def completion_evidence_sha256(completion: dict[str, Any]) -> str:
    return canonical_json_sha256(
        {key: value for key, value in completion.items() if key != "evidence_sha256"}
    )


def validate_completion(completion: Any) -> dict[str, Any]:
    if not isinstance(completion, dict) or set(completion) != COMPLETION_KEYS:
        raise BoundaryError("FIREWALL_RESTORATION_EVIDENCE_INVALID")
    if completion.get("schema") != COMPLETION_SCHEMA or completion.get("table") != TABLE:
        raise BoundaryError("FIREWALL_RESTORATION_EVIDENCE_INVALID")
    if completion.get("restored") is not True:
        raise BoundaryError("FIREWALL_RESTORATION_EVIDENCE_INVALID")
    for key in (
        "ledger_sha256",
        "preimage_sha256",
        "preimage_counts_sha256",
        "postimage_sha256",
        "postimage_counts_sha256",
        "evidence_sha256",
    ):
        value = completion.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise BoundaryError("FIREWALL_RESTORATION_EVIDENCE_INVALID")
    if completion["preimage_sha256"] != completion["postimage_sha256"]:
        raise BoundaryError("FIREWALL_RESTORATION_EVIDENCE_INVALID")
    if completion["preimage_counts_sha256"] != completion["postimage_counts_sha256"]:
        raise BoundaryError("FIREWALL_RESTORATION_EVIDENCE_INVALID")
    if completion["evidence_sha256"] != completion_evidence_sha256(completion):
        raise BoundaryError("FIREWALL_RESTORATION_EVIDENCE_INVALID")
    return completion


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def read_completion(path: Path) -> dict[str, Any]:
    try:
        observed = path.lstat()
    except OSError as exc:
        raise BoundaryError("FIREWALL_RESTORATION_EVIDENCE_INVALID") from exc
    if not stat.S_ISREG(observed.st_mode) or stat.S_ISLNK(observed.st_mode):
        raise BoundaryError("FIREWALL_RESTORATION_EVIDENCE_INVALID")
    try:
        completion = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_strict_json_object
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise BoundaryError("FIREWALL_RESTORATION_EVIDENCE_INVALID") from exc
    return validate_completion(completion)


def build_completion(
    ledger: dict[str, Any], postimage_sha256: str, postimage_counts: dict[str, int]
) -> dict[str, Any]:
    completion = {
        "schema": COMPLETION_SCHEMA,
        "table": TABLE,
        "ledger_sha256": ledger_sha256(ledger),
        "preimage_sha256": ledger["preimage_sha256"],
        "preimage_counts_sha256": counts_sha256(ledger["preimage_counts"]),
        "postimage_sha256": postimage_sha256,
        "postimage_counts_sha256": counts_sha256(postimage_counts),
        "restored": True,
        "evidence_sha256": "",
    }
    completion["evidence_sha256"] = completion_evidence_sha256(completion)
    return validate_completion(completion)


def _retire_private_path(path: Path, failure_code: str) -> None:
    try:
        path.unlink()
    except OSError as exc:
        raise BoundaryError(failure_code) from exc


def _fsync_parent(path: Path) -> None:
    if os.name == "nt" or not hasattr(os, "O_DIRECTORY"):
        return
    descriptor: int | None = None
    try:
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        os.fsync(descriptor)
    except OSError as exc:
        raise BoundaryError("FIREWALL_RESTORATION_COMPLETION_FAILED") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _reconcile_completion_stage(completion_path: Path) -> None:
    stage_path = restoration_stage_path(completion_path)
    if not os.path.lexists(stage_path):
        return
    try:
        observed = stage_path.lstat()
    except OSError as exc:
        raise BoundaryError("FIREWALL_RESTORATION_EVIDENCE_INVALID") from exc
    if not stat.S_ISREG(observed.st_mode) or stat.S_ISLNK(observed.st_mode):
        raise BoundaryError("FIREWALL_RESTORATION_EVIDENCE_INVALID")
    if os.path.lexists(completion_path):
        try:
            same_file = os.path.samefile(stage_path, completion_path)
        except OSError as exc:
            raise BoundaryError("FIREWALL_RESTORATION_EVIDENCE_INVALID") from exc
        if not same_file:
            raise BoundaryError("FIREWALL_RESTORATION_EVIDENCE_INVALID")
    _retire_private_path(stage_path, "FIREWALL_RESTORATION_COMPLETION_FAILED")


def write_completion(path: Path, completion: dict[str, Any]) -> None:
    validate_completion(completion)
    _reconcile_completion_stage(path)
    if os.path.lexists(path):
        raise BoundaryError("FIREWALL_RESTORATION_EVIDENCE_COLLISION")
    path.parent.mkdir(parents=True, exist_ok=True)
    stage_path = restoration_stage_path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    linked = False
    try:
        descriptor = os.open(stage_path, flags, 0o600)
        payload = (json.dumps(completion, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )
        os.write(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.chmod(stage_path, 0o600)
        os.link(stage_path, path)
        linked = True
        _fsync_parent(path)
    except OSError as exc:
        raise BoundaryError("FIREWALL_RESTORATION_COMPLETION_FAILED") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if os.path.lexists(stage_path):
            try:
                stage_path.unlink()
            except OSError as exc:
                raise BoundaryError("FIREWALL_RESTORATION_COMPLETION_FAILED") from exc
    if not linked:
        raise BoundaryError("FIREWALL_RESTORATION_COMPLETION_FAILED")


def validate_completion_against_ledger(
    completion: dict[str, Any],
    ledger: dict[str, Any],
    current_sha256: str,
    current_counts: dict[str, int],
) -> None:
    validate_completion(completion)
    if (
        completion["ledger_sha256"] != ledger_sha256(ledger)
        or completion["preimage_sha256"] != ledger["preimage_sha256"]
        or completion["preimage_counts_sha256"] != counts_sha256(ledger["preimage_counts"])
        or completion["postimage_sha256"] != current_sha256
        or completion["postimage_counts_sha256"] != counts_sha256(current_counts)
    ):
        raise BoundaryError("FIREWALL_RESTORATION_EVIDENCE_INVALID")


def validate_completion_against_current(
    completion: dict[str, Any], current_sha256: str, current_counts: dict[str, int]
) -> None:
    validate_completion(completion)
    if (
        completion["postimage_sha256"] != current_sha256
        or completion["postimage_counts_sha256"] != counts_sha256(current_counts)
    ):
        raise BoundaryError("FIREWALL_RESTORATION_EVIDENCE_INVALID")


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
    for key in ("preimage_counts", "installation_counts"):
        counts = ledger.get(key)
        if not isinstance(counts, dict) or any(
            not isinstance(kind, str) or not isinstance(value, int) or value < 0
            for kind, value in counts.items()
        ):
            raise BoundaryError("FIREWALL_LEDGER_INVALID")
    for key in ("preimage_sha256", "preimage_semantic_sha256"):
        value = ledger.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise BoundaryError("FIREWALL_LEDGER_INVALID")
    for key in (
        "installation_sha256",
        "installation_semantic_sha256",
        "owned_sha256",
        "marker_sha256",
        "combined_sha256",
    ):
        value = ledger.get(key)
        if not isinstance(value, str) or (value and not re.fullmatch(r"[0-9a-f]{64}", value)):
            raise BoundaryError("FIREWALL_LEDGER_INVALID")
    installation_recorded = bool(
        ledger["installation_sha256"]
        and ledger["installation_semantic_sha256"]
    )
    if ledger["installed"] != installation_recorded or (
        ledger["installed"] and not ledger["owned_sha256"]
    ) or (not ledger["installed"] and ledger["installation_counts"]):
        raise BoundaryError("FIREWALL_LEDGER_INVALID")
    if ledger["markers_installed"] != bool(
        ledger["marker_sha256"] and ledger["combined_sha256"]
    ):
        raise BoundaryError("FIREWALL_LEDGER_INVALID")
    return ledger


def _marker_evidence_paths(ledger_path: Path) -> tuple[Path, Path]:
    return marker_intent_path(ledger_path), marker_installed_path(ledger_path)


def _reconcile_marker_evidence_stages(ledger_path: Path) -> None:
    for path in _marker_evidence_paths(ledger_path):
        _reconcile_marker_evidence_stage(path)


def read_effective_ledger(ledger_path: Path) -> dict[str, Any]:
    ledger = read_ledger(ledger_path)
    _reconcile_marker_evidence_stages(ledger_path)
    intent_path, installed_path = _marker_evidence_paths(ledger_path)
    has_intent = os.path.lexists(intent_path)
    has_installed = os.path.lexists(installed_path)
    if has_installed and not has_intent:
        raise BoundaryError("FIREWALL_MARKER_STATE_INVALID")
    if not has_installed:
        if has_intent:
            read_marker_intent(intent_path, ledger)
            raise BoundaryError("FIREWALL_MARKER_STATE_PENDING")
        return ledger
    intent = read_marker_intent(intent_path, ledger)
    installed = read_marker_installed(installed_path, ledger, intent)
    return overlay_marker_ledger(
        ledger, installed["marker_sha256"], installed["combined_sha256"]
    )


def reconcile_marker_state_for_cleanup(
    ledger_path: Path, ledger: dict[str, Any], entries: list[dict[str, Any]]
) -> dict[str, Any]:
    _reconcile_marker_evidence_stages(ledger_path)
    intent_path, installed_path = _marker_evidence_paths(ledger_path)
    has_intent = os.path.lexists(intent_path)
    has_installed = os.path.lexists(installed_path)
    if has_installed and not has_intent:
        raise BoundaryError("FIREWALL_MARKER_STATE_INVALID")
    if has_installed:
        intent = read_marker_intent(intent_path, ledger)
        installed = read_marker_installed(installed_path, ledger, intent)
        return overlay_marker_ledger(
            ledger, installed["marker_sha256"], installed["combined_sha256"]
        )
    if not has_intent:
        return ledger

    intent = read_marker_intent(intent_path, ledger)
    selected = owned_entries(entries, TABLE)
    if not selected:
        return ledger
    try:
        base_sha, _ = validate_owned(entries, TABLE, markers_installed=False)
        if base_sha != ledger["owned_sha256"]:
            raise BoundaryError("FIREWALL_INSTALLATION_MISMATCH")
        return ledger
    except BoundaryError:
        pass

    try:
        diagnostic = diagnose_marker_rule_expressions(
            entries,
            TABLE,
            ledger["interface"],
            ledger["subnet"],
            intent["client_ip"],
            intent["service_ip"],
            intent["foreign_ip"],
            intent["gateway_ip"],
            intent["host_port"],
        )
        combined_sha, _ = validate_owned(entries, TABLE, markers_installed=True)
        marker_sha, marker_counts = canonical_snapshot(marker_entries(entries, TABLE))
        if marker_counts != {"chain": 3, "counter": 7, "rule": 7}:
            raise BoundaryError("FIREWALL_MARKER_RECOVERY_FAILED")
        installed = build_marker_installed(
            ledger, intent, marker_sha, combined_sha, diagnostic
        )
        write_marker_installed(installed_path, installed)
        return overlay_marker_ledger(ledger, marker_sha, combined_sha)
    except BoundaryError as exc:
        if exc.code in {
            "FIREWALL_MARKER_STATE_PERSISTENCE_FAILED",
            "FIREWALL_MARKER_STATE_COLLISION",
        }:
            raise
        raise BoundaryError("FIREWALL_MARKER_RECOVERY_FAILED") from exc


def validate_orphan_marker_evidence(
    ledger_path: Path, completion: dict[str, Any]
) -> None:
    _reconcile_marker_evidence_stages(ledger_path)
    intent_path, installed_path = _marker_evidence_paths(ledger_path)
    has_intent = os.path.lexists(intent_path)
    has_installed = os.path.lexists(installed_path)
    intent = read_marker_intent(intent_path) if has_intent else None
    installed = (
        read_marker_installed(installed_path, None, intent)
        if has_installed
        else None
    )
    if installed is not None:
        if installed["effective_ledger_sha256"] != completion["ledger_sha256"]:
            raise BoundaryError("FIREWALL_MARKER_STATE_INVALID")
    elif intent is not None and intent["base_ledger_sha256"] != completion["ledger_sha256"]:
        raise BoundaryError("FIREWALL_MARKER_STATE_INVALID")


def retire_marker_evidence(ledger_path: Path) -> None:
    intent_path, installed_path = _marker_evidence_paths(ledger_path)
    for path in (intent_path, installed_path):
        if os.path.lexists(path):
            _retire_private_path(path, "FIREWALL_MARKER_STATE_RETIREMENT_FAILED")


def prepare(ledger_path: Path, interface: str, subnet: str) -> None:
    completion_path = restoration_completion_path(ledger_path)
    marker_paths = _marker_evidence_paths(ledger_path)
    if (
        os.path.lexists(ledger_path)
        or os.path.lexists(completion_path)
        or os.path.lexists(restoration_stage_path(completion_path))
        or any(
            os.path.lexists(path) or os.path.lexists(marker_evidence_stage_path(path))
            for path in marker_paths
        )
    ):
        raise BoundaryError("FIREWALL_LEDGER_COLLISION")
    daemon_class, daemon_root_owned, runner_nonroot = process_ownership_preflight()
    prefix, backend_class = privileged_prefix()
    entries = read_ruleset(prefix)
    if owned_entries(entries, TABLE):
        raise BoundaryError("FIREWALL_TABLE_COLLISION")
    pre_sha, pre_counts = canonical_snapshot(entries, exclude_table=TABLE)
    pre_semantic_sha = semantic_snapshot(entries, exclude_table=TABLE)
    ledger = {
        "schema": SCHEMA,
        "table": TABLE,
        "interface": interface,
        "subnet": subnet,
        "preimage_sha256": pre_sha,
        "preimage_semantic_sha256": pre_semantic_sha,
        "preimage_counts": pre_counts,
        "installation_sha256": "",
        "installation_semantic_sha256": "",
        "installation_counts": {},
        "installed": False,
        "owned_sha256": "",
        "markers_installed": False,
        "marker_sha256": "",
        "combined_sha256": "",
    }
    write_ledger(ledger_path, ledger)
    emit(
        [
            ("firewall.backend_class", "str", backend_class),
            ("firewall.daemon_class", "str", daemon_class),
            ("firewall.docker_daemon_root_owned", "bool", daemon_root_owned),
            ("firewall.runner_nonroot", "bool", runner_nonroot),
            ("firewall.prepared_before_network", "bool", True),
            ("firewall.preimage_sha256", "str", pre_sha),
            ("firewall.preimage_semantic_sha256", "str", pre_semantic_sha),
            ("firewall.preimage_table_count", "int", pre_counts.get("table", 0)),
            ("firewall.preimage_chain_count", "int", pre_counts.get("chain", 0)),
            ("firewall.preimage_rule_count", "int", pre_counts.get("rule", 0)),
        ]
    )


def install(ledger_path: Path, interface: str, subnet: str) -> None:
    completion_path = restoration_completion_path(ledger_path)
    if os.path.lexists(completion_path) or os.path.lexists(
        restoration_stage_path(completion_path)
    ) or any(
        os.path.lexists(path) or os.path.lexists(marker_evidence_stage_path(path))
        for path in _marker_evidence_paths(ledger_path)
    ):
        raise BoundaryError("FIREWALL_LEDGER_COLLISION")
    ledger = read_ledger(ledger_path)
    if (
        ledger["interface"] != interface
        or ledger["subnet"] != subnet
        or ledger["installed"] is not False
        or ledger["markers_installed"] is not False
        or ledger["owned_sha256"]
        or ledger["installation_sha256"]
        or ledger["installation_semantic_sha256"]
        or ledger["installation_counts"]
        or ledger["marker_sha256"]
        or ledger["combined_sha256"]
    ):
        raise BoundaryError("FIREWALL_LEDGER_INVALID")
    process_ownership_preflight()
    prefix, _ = privileged_prefix()
    entries = read_ruleset(prefix)
    if owned_entries(entries, TABLE):
        raise BoundaryError("FIREWALL_TABLE_COLLISION")
    install_pre_sha, install_pre_counts = canonical_snapshot(entries, exclude_table=TABLE)
    install_pre_semantic_sha = semantic_snapshot(entries, exclude_table=TABLE)
    batch = build_batch(TABLE, interface, subnet)
    checked = _run([*prefix, "--check", "-f", "-"], input_text=batch)
    if checked.returncode != 0:
        raise BoundaryError("FIREWALL_ATOMIC_CHECK_FAILED")
    applied = _run([*prefix, "-f", "-"], input_text=batch)
    if applied.returncode != 0:
        raise BoundaryError("FIREWALL_ATOMIC_INSTALL_FAILED")
    after = read_ruleset(prefix)
    owned_sha, owned_counts = validate_owned(after, TABLE)
    foreign_sha, foreign_counts = canonical_snapshot(after, exclude_table=TABLE)
    if foreign_sha != install_pre_sha or foreign_counts != install_pre_counts:
        raise BoundaryError("FIREWALL_FOREIGN_STATE_DRIFT")
    ledger["installed"] = True
    ledger["installation_sha256"] = install_pre_sha
    ledger["installation_semantic_sha256"] = install_pre_semantic_sha
    ledger["installation_counts"] = install_pre_counts
    ledger["owned_sha256"] = owned_sha
    write_ledger(ledger_path, ledger)
    emit(
        [
            ("firewall.atomic_install", "bool", True),
            ("firewall.install_foreign_unchanged", "bool", True),
            ("firewall.install_preimage_sha256", "str", install_pre_sha),
            (
                "firewall.install_preimage_semantic_sha256",
                "str",
                install_pre_semantic_sha,
            ),
            ("firewall.install_postimage_sha256", "str", foreign_sha),
            (
                "firewall.install_preimage_table_count",
                "int",
                install_pre_counts.get("table", 0),
            ),
            (
                "firewall.install_preimage_chain_count",
                "int",
                install_pre_counts.get("chain", 0),
            ),
            (
                "firewall.install_preimage_rule_count",
                "int",
                install_pre_counts.get("rule", 0),
            ),
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
    intent_path, installed_path = _marker_evidence_paths(ledger_path)
    if any(
        os.path.lexists(path) or os.path.lexists(marker_evidence_stage_path(path))
        for path in (intent_path, installed_path)
    ):
        raise BoundaryError("FIREWALL_MARKER_STATE_COLLISION")
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
    # Publish retry-capable intent before apply; it never claims markers exist.
    intent = build_marker_intent(
        ledger,
        client_ip,
        service_ip,
        foreign_ip,
        gateway_ip,
        host_port,
        batch,
    )
    write_marker_intent(intent_path, intent)
    applied = _run([*prefix, "-f", "-"], input_text=batch)
    if applied.returncode != 0:
        raise BoundaryError("FIREWALL_MARKER_ATOMIC_INSTALL_FAILED")

    after = read_ruleset(prefix)
    post_foreign_sha, post_foreign_counts = canonical_snapshot(
        after, exclude_table=TABLE
    )
    diagnostic = diagnose_marker_rule_expressions(
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
    combined_sha, _ = validate_owned(
        after, TABLE, markers_installed=True
    )
    marker_sha, marker_counts = canonical_snapshot(marker_entries(after, TABLE))
    if marker_counts != {"chain": 3, "counter": 7, "rule": 7}:
        raise BoundaryError("FIREWALL_MARKER_INSTALLATION_MISMATCH")
    # Exact readback now proved the owned shape. Persist it before any later
    # foreign-state comparison can fail and hand control to always-cleanup.
    installed = build_marker_installed(
        ledger, intent, marker_sha, combined_sha, diagnostic
    )
    write_marker_installed(installed_path, installed)
    if post_foreign_sha != foreign_sha or post_foreign_counts != foreign_counts:
        raise BoundaryError("FIREWALL_FOREIGN_STATE_DRIFT")
    rows = marker_diagnostic_state_rows(diagnostic)
    publish_marker_diagnostic_state(rows)
    if diagnostic["mismatch_class"] == "MATCHED_SHAPE":
        raise BoundaryError("FIREWALL_DIAGNOSTIC_STOP_MATCHED_SHAPE")
    raise BoundaryError("FIREWALL_MARKER_INSTALLATION_MISMATCH")


def counters(ledger_path: Path) -> None:
    ledger = read_effective_ledger(ledger_path)
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
    ledger = read_effective_ledger(ledger_path)
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


def _restoration_observation_values(observation: dict[str, Any]) -> list[tuple[str, str, Any]]:
    ordinal = int(observation["ordinal"])
    prefix = f"firewall.restoration.observations.{ordinal:02d}"
    return [
        (f"{prefix}.ordinal", "int", ordinal),
        (f"{prefix}.total", "int", RESTORATION_POLL_ATTEMPTS),
        (f"{prefix}.query_succeeded", "bool", observation["query_succeeded"]),
        (f"{prefix}.owned_shape_valid", "bool", observation["owned_shape_valid"]),
        (f"{prefix}.owned_table_present", "bool", observation["owned_table_present"]),
        (f"{prefix}.classification", "str", observation["classification"]),
        (f"{prefix}.foreign_sha256", "str", observation["foreign_sha256"]),
        (f"{prefix}.foreign_semantic_sha256", "str", observation["foreign_semantic_sha256"]),
        (f"{prefix}.foreign_counts", "json", json.dumps(observation["foreign_counts"], sort_keys=True, separators=(",", ":"))),
        (f"{prefix}.foreign_counts_sha256", "str", counts_sha256(observation["foreign_counts"])),
        (f"{prefix}.equals_pre_network", "bool", observation["equals_pre_network"]),
        (f"{prefix}.semantic_equals_pre_network", "bool", observation["semantic_equals_pre_network"]),
        (f"{prefix}.equals_installation", "bool", observation["equals_installation"]),
        (f"{prefix}.semantic_equals_installation", "bool", observation["semantic_equals_installation"]),
        (f"{prefix}.equals_prior", "bool", observation["equals_prior"]),
        (f"{prefix}.semantic_equals_prior", "bool", observation["semantic_equals_prior"]),
        (f"{prefix}.error_class", "str", observation["error_class"]),
    ]


def _emit_restoration_summary(observations: list[dict[str, Any]], classification: str) -> None:
    emit(
        [
            ("firewall.restoration_observation_count", "int", len(observations)),
            ("firewall.restoration_observation_total", "int", RESTORATION_POLL_ATTEMPTS),
            ("firewall.restoration_classification", "str", classification),
            (
                "firewall.restoration_observation_manifest_sha256",
                "str",
                canonical_json_sha256(observations),
            ),
        ]
    )


def wait_for_restoration_preimage(
    prefix: list[str], ledger: dict[str, Any], entries: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Wait boundedly for Docker teardown to restore the immutable preimage.

    The helper never adopts a different foreign state.  It also revalidates the
    exact packet-owned table on every observation so the wait cannot hide owned
    drift before the atomic deletion transaction.
    """

    observations: list[dict[str, Any]] = []
    prior_sha = ""
    prior_semantic_sha = ""
    prior_counts: dict[str, int] | None = None
    for attempt in range(RESTORATION_POLL_ATTEMPTS):
        ordinal = attempt + 1
        selected = owned_entries(entries, TABLE)
        try:
            if selected:
                if ledger.get("markers_installed") is True:
                    _validated_current_owned(entries, ledger)
                else:
                    validate_owned(entries, TABLE, markers_installed=False)
        except BoundaryError as exc:
            observation = {
                "ordinal": ordinal,
                "query_succeeded": True,
                "owned_shape_valid": False,
                "owned_table_present": bool(selected),
                "classification": "OWNED_SHAPE_FAILED",
                "foreign_sha256": "0" * 64,
                "foreign_semantic_sha256": "0" * 64,
                "foreign_counts": {},
                "equals_pre_network": False,
                "semantic_equals_pre_network": False,
                "equals_installation": False,
                "semantic_equals_installation": False,
                "equals_prior": False,
                "semantic_equals_prior": False,
                "error_class": exc.code,
            }
            observations.append(observation)
            emit(_restoration_observation_values(observation))
            _emit_restoration_summary(observations, "OWNED_SHAPE_FAILED")
            raise
        foreign_sha, foreign_counts = canonical_snapshot(entries, exclude_table=TABLE)
        foreign_semantic_sha = semantic_snapshot(entries, exclude_table=TABLE)
        equals_pre = (
            foreign_sha == ledger["preimage_sha256"]
            and foreign_counts == ledger["preimage_counts"]
        )
        semantic_equals_pre = (
            foreign_semantic_sha == ledger["preimage_semantic_sha256"]
            and foreign_counts == ledger["preimage_counts"]
        )
        equals_installation = (
            foreign_sha == ledger["installation_sha256"]
            and foreign_counts == ledger["installation_counts"]
        )
        semantic_equals_installation = (
            foreign_semantic_sha == ledger["installation_semantic_sha256"]
            and foreign_counts == ledger["installation_counts"]
        )
        equals_prior = bool(
            observations and foreign_sha == prior_sha and foreign_counts == prior_counts
        )
        semantic_equals_prior = bool(
            observations
            and foreign_semantic_sha == prior_semantic_sha
            and foreign_counts == prior_counts
        )
        if equals_pre:
            classification = "PRE_NETWORK_IDENTITY"
        elif equals_installation:
            classification = "PERSISTENT_INSTALLATION_IDENTITY"
        elif semantic_equals_pre or semantic_equals_installation or (
            semantic_equals_prior and not equals_prior
        ):
            classification = "LIST_ORDER_SERIALIZATION_VARIANCE"
        elif equals_prior:
            classification = "STABLE_UNRELATED_FOREIGN_DRIFT"
        else:
            classification = "UNSTABLE_FOREIGN_DRIFT"
        observation = {
            "ordinal": ordinal,
            "query_succeeded": True,
            "owned_shape_valid": True,
            "owned_table_present": bool(selected),
            "classification": classification,
            "foreign_sha256": foreign_sha,
            "foreign_semantic_sha256": foreign_semantic_sha,
            "foreign_counts": foreign_counts,
            "equals_pre_network": equals_pre,
            "semantic_equals_pre_network": semantic_equals_pre,
            "equals_installation": equals_installation,
            "semantic_equals_installation": semantic_equals_installation,
            "equals_prior": equals_prior,
            "semantic_equals_prior": semantic_equals_prior,
            "error_class": "NONE",
        }
        observations.append(observation)
        emit(_restoration_observation_values(observation))
        prior_sha = foreign_sha
        prior_semantic_sha = foreign_semantic_sha
        prior_counts = foreign_counts
        if equals_pre:
            _emit_restoration_summary(observations, "PRE_NETWORK_IDENTITY")
            return entries, selected
        if attempt + 1 == RESTORATION_POLL_ATTEMPTS:
            break
        time.sleep(RESTORATION_POLL_INTERVAL_SECONDS)
        try:
            entries = read_ruleset(prefix)
        except BoundaryError as exc:
            failed = {
                "ordinal": ordinal + 1,
                "query_succeeded": False,
                "owned_shape_valid": False,
                "owned_table_present": False,
                "classification": "OBSERVATION_QUERY_FAILED",
                "foreign_sha256": "0" * 64,
                "foreign_semantic_sha256": "0" * 64,
                "foreign_counts": {},
                "equals_pre_network": False,
                "semantic_equals_pre_network": False,
                "equals_installation": False,
                "semantic_equals_installation": False,
                "equals_prior": False,
                "semantic_equals_prior": False,
                "error_class": exc.code,
            }
            observations.append(failed)
            emit(_restoration_observation_values(failed))
            _emit_restoration_summary(observations, "OBSERVATION_QUERY_FAILED")
            raise
    if all(item["equals_installation"] for item in observations):
        terminal_class = "PERSISTENT_INSTALLATION_IDENTITY"
    elif all(
        item["semantic_equals_pre_network"]
        or item["semantic_equals_installation"]
        for item in observations
    ):
        terminal_class = "LIST_ORDER_SERIALIZATION_VARIANCE"
    elif all(item["semantic_equals_prior"] for item in observations[1:]) and any(
        not item["equals_prior"] for item in observations[1:]
    ):
        terminal_class = "LIST_ORDER_SERIALIZATION_VARIANCE"
    elif all(item["equals_prior"] for item in observations[1:]):
        terminal_class = "STABLE_UNRELATED_FOREIGN_DRIFT"
    else:
        terminal_class = "UNSTABLE_FOREIGN_DRIFT"
    _emit_restoration_summary(observations, terminal_class)
    raise BoundaryError("FIREWALL_FOREIGN_STATE_DRIFT")


def remove(ledger_path: Path) -> None:
    prefix, _ = privileged_prefix()
    entries = read_ruleset(prefix)
    selected = owned_entries(entries, TABLE)
    completion_path = restoration_completion_path(ledger_path)
    _reconcile_completion_stage(completion_path)
    _reconcile_marker_evidence_stages(ledger_path)
    if not os.path.lexists(ledger_path):
        if selected:
            raise BoundaryError("FIREWALL_LEDGER_MISSING")
        if not os.path.lexists(completion_path):
            raise BoundaryError("FIREWALL_RESTORATION_EVIDENCE_MISSING")
        completion = read_completion(completion_path)
        post_sha, post_counts = canonical_snapshot(entries, exclude_table=TABLE)
        validate_completion_against_current(completion, post_sha, post_counts)
        validate_orphan_marker_evidence(ledger_path, completion)
        retire_marker_evidence(ledger_path)
        _retire_private_path(
            completion_path, "FIREWALL_RESTORATION_COMPLETION_RETIREMENT_FAILED"
        )
        emit(
            [
                ("firewall.rollback_idempotent", "bool", True),
                ("firewall.rollback_completion_validated", "bool", True),
                (
                    "firewall.rollback_completion_evidence_sha256",
                    "str",
                    completion["evidence_sha256"],
                ),
                ("firewall.rollback_completion_retired", "bool", True),
                ("firewall.rollback_foreign_preimage_restored", "bool", True),
                ("firewall.rollback_postimage_sha256", "str", post_sha),
                (
                    "firewall.rollback_postimage_table_count",
                    "int",
                    post_counts.get("table", 0),
                ),
                (
                    "firewall.rollback_postimage_chain_count",
                    "int",
                    post_counts.get("chain", 0),
                ),
                (
                    "firewall.rollback_postimage_rule_count",
                    "int",
                    post_counts.get("rule", 0),
                ),
            ]
        )
        return
    ledger = reconcile_marker_state_for_cleanup(
        ledger_path, read_ledger(ledger_path), entries
    )
    if os.path.lexists(completion_path):
        if selected:
            raise BoundaryError("FIREWALL_RESTORATION_EVIDENCE_INVALID")
        completion = read_completion(completion_path)
        post_sha, post_counts = canonical_snapshot(entries, exclude_table=TABLE)
        validate_completion_against_ledger(completion, ledger, post_sha, post_counts)
        _retire_private_path(ledger_path, "FIREWALL_LEDGER_RETIREMENT_FAILED")
        retire_marker_evidence(ledger_path)
        _retire_private_path(
            completion_path, "FIREWALL_RESTORATION_COMPLETION_RETIREMENT_FAILED"
        )
        emit(
            [
                ("firewall.rollback_idempotent", "bool", True),
                ("firewall.rollback_completion_validated", "bool", True),
                (
                    "firewall.rollback_completion_evidence_sha256",
                    "str",
                    completion["evidence_sha256"],
                ),
                ("firewall.rollback_ledger_retired", "bool", True),
                ("firewall.rollback_completion_retired", "bool", True),
                ("firewall.rollback_foreign_preimage_restored", "bool", True),
                ("firewall.rollback_postimage_sha256", "str", post_sha),
                (
                    "firewall.rollback_postimage_table_count",
                    "int",
                    post_counts.get("table", 0),
                ),
                (
                    "firewall.rollback_postimage_chain_count",
                    "int",
                    post_counts.get("chain", 0),
                ),
                (
                    "firewall.rollback_postimage_rule_count",
                    "int",
                    post_counts.get("rule", 0),
                ),
            ]
        )
        return
    entries, selected = wait_for_restoration_preimage(prefix, ledger, entries)
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
    if post_sha != ledger["preimage_sha256"] or post_counts != ledger["preimage_counts"]:
        raise BoundaryError("FIREWALL_FOREIGN_STATE_DRIFT")
    completion = build_completion(ledger, post_sha, post_counts)
    write_completion(completion_path, completion)
    _retire_private_path(ledger_path, "FIREWALL_LEDGER_RETIREMENT_FAILED")
    retire_marker_evidence(ledger_path)
    emit(
        [
            ("firewall.rollback_idempotent", "bool", False),
            ("firewall.rollback_removed_table_count", "int", 1 if selected else 0),
            ("firewall.rollback_foreign_preimage_restored", "bool", True),
            ("firewall.rollback_completion_published", "bool", True),
            (
                "firewall.rollback_completion_evidence_sha256",
                "str",
                completion["evidence_sha256"],
            ),
            ("firewall.rollback_ledger_retired", "bool", True),
            ("firewall.rollback_postimage_sha256", "str", post_sha),
            ("firewall.rollback_postimage_table_count", "int", post_counts.get("table", 0)),
            ("firewall.rollback_postimage_chain_count", "int", post_counts.get("chain", 0)),
            ("firewall.rollback_postimage_rule_count", "int", post_counts.get("rule", 0)),
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--ledger", required=True, type=Path)
    prepare_parser.add_argument("--interface", required=True)
    prepare_parser.add_argument("--subnet", required=True)
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
        if args.command == "prepare":
            prepare(args.ledger, args.interface, args.subnet)
        elif args.command == "install":
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
