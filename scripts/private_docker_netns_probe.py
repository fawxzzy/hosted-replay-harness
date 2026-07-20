#!/usr/bin/env python3
"""Synthetic, fail-closed private Docker network-namespace capability probe.

The helper emits only a fixed TSV receipt. Command output, Docker objects,
network identities, firewall rules, paths, and process details stay private.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Any, Iterable


SCHEMA = "fawxzzy.hosted-replay-harness.private-netns-probe.v2"
PASS_CLASS = "STANDARD_RUNNER_PRIVATE_NETNS_PASS"
REJECT_CLASS = "STANDARD_RUNNER_REJECTED_JIT_REQUIRED"
ZERO_SHA256 = "0" * 64
NS_NAME = "fp-hosted-replay-netns-probe"
NETWORK_NAME = "fp-hosted-replay-netns-probe-net"
BRIDGE_NAME = "br-fpnetns01"
PRIVATE_SUBNET = "172.30.251.0/24"
PRIVATE_GATEWAY = "172.30.251.1"
SERVICE_NAME = "fp-hosted-replay-netns-postgres"
CLIENT_NAME = "fp-hosted-replay-netns-client"
CGROUP_NAME = "fp-hosted-replay-netns-probe"
CONTAINERD_NAMESPACE = "fp-hosted-replay-netns-moby"
CONTAINERD_PLUGINS_NAMESPACE = "fp-hosted-replay-netns-plugins"
PRIVATE_TABLE = "fp_private_netns_probe"
OUTPUT_LIMIT = 8 * 1024 * 1024
MINIMUM_EXTRA_DISK = 4 * 1024 * 1024 * 1024
DOCKER_CLEANUP_ACTION_ORDER = (
    "REMOVE_CLIENT",
    "REMOVE_SERVICE",
    "REMOVE_NETWORK",
    "REMOVE_IMAGE",
)
DOCKER_CLEANUP_QUERY_SPECS = (
    ("QUERY_CONTAINERS", "containers_remaining", ("ps", "-aq")),
    ("QUERY_VOLUMES", "volumes_remaining", ("volume", "ls", "-q")),
    ("QUERY_NETWORKS", "networks_remaining", ("network", "ls", "-q", "--filter", "type=custom")),
    ("QUERY_IMAGES", "images_remaining", ("image", "ls", "-q")),
)

STARTUP_SUBSTAGES = frozenset(
    {
        "PROCESS_EXIT_BEFORE_SOCKET",
        "SOCKET_READINESS_TIMEOUT",
        "NAMESPACE_CREATE_INITIAL_FAILED",
        "NAMESPACE_CREATE_RETRY_FAILED",
        "NAMESPACE_READBACK_FAILED",
        "READY",
        "UNKNOWN_SANITIZED",
    }
)

FAILURE_CODES = frozenset(
    {
        "PASS",
        "ARGUMENT_CONTRACT_INVALID",
        "ROOT_PRIVILEGE_UNAVAILABLE",
        "RUNNER_IDENTITY_INVALID",
        "CAPABILITY_TOOL_MISSING",
        "PACKET_PATH_INVALID",
        "PACKET_PATH_COLLISION",
        "HOST_DOCKER_UNAVAILABLE",
        "HOST_IMAGE_IDENTITY_MISMATCH",
        "HOST_IMAGE_SAVE_FAILED",
        "DISK_MARGIN_INADEQUATE",
        "HOST_FIREWALL_QUERY_FAILED",
        "HOST_FIREWALL_DRIFT",
        "HOST_LINK_STATE_DRIFT",
        "CGROUP_V2_UNAVAILABLE",
        "CGROUP_CREATE_FAILED",
        "NETNS_CREATE_FAILED",
        "NETNS_ROUTE_INVALID",
        "PRIVATE_CONTAINERD_START_FAILED",
        "PRIVATE_DOCKERD_START_FAILED",
        "PRIVATE_DAEMON_ARGUMENT_REJECTED",
        "SYSTEM_CONTAINERD_COUPLING",
        "PRIVATE_IMAGE_LOAD_FAILED",
        "PRIVATE_IMAGE_IDENTITY_MISMATCH",
        "PRIVATE_NETWORK_CREATE_FAILED",
        "PRIVATE_FIREWALL_INSTALL_FAILED",
        "PRIVATE_CONTAINER_CREATE_FAILED",
        "PRIVATE_CONTAINER_CONTRACT_INVALID",
        "PRIVATE_SERVICE_HEALTH_FAILED",
        "PRIVATE_NAMESPACE_IDENTITY_FAILED",
        "PRIVATE_CGROUP_OWNERSHIP_FAILED",
        "PRIVATE_INTERCONTAINER_FAILED",
        "PRIVATE_CANARY_TOOL_MISSING",
        "PRIVATE_CANARY_RUNTIME_FAILED",
        "PRIVATE_CANARY_EVIDENCE_INVALID",
        "PRIVATE_DEFAULT_ROUTE_PRESENT",
        "PRIVATE_EXTERNAL_DNS_SUCCEEDED",
        "PRIVATE_LITERAL_IP_EGRESS_SUCCEEDED",
        "PRIVATE_METADATA_EGRESS_SUCCEEDED",
        "PRIVATE_GATEWAY_REACHABLE",
        "PRIVATE_REGISTRY_ACCESS_SUCCEEDED",
        "PRIVATE_LOOPBACK_PROXY_FAILED",
        "PRIVATE_NONLOOPBACK_REACHABLE",
        "PRIVATE_CLEANUP_FAILED",
        "PRIVATE_RESIDUE",
        "PROBE_INTERNAL_ERROR",
    }
)

FIELD_SPECS: tuple[tuple[str, str], ...] = (
    ("diagnostic.private_netns.schema", "str"),
    ("diagnostic.private_netns.classification", "str"),
    ("diagnostic.private_netns.failure_code", "str"),
    ("diagnostic.private_netns.runner.rootful", "bool"),
    ("diagnostic.private_netns.runner.runner_nonroot", "bool"),
    ("diagnostic.private_netns.runner.sudo_boundary", "bool"),
    ("diagnostic.private_netns.runner.tool_count", "int"),
    ("diagnostic.private_netns.runner.tool_manifest_sha256", "str"),
    ("diagnostic.private_netns.runner.cgroup_v2", "bool"),
    ("diagnostic.private_netns.runner.no_forbidden_host_change", "bool"),
    ("diagnostic.private_netns.runner.disk_free_bytes", "int"),
    ("diagnostic.private_netns.runner.disk_required_bytes", "int"),
    ("diagnostic.private_netns.runner.disk_margin_ok", "bool"),
    ("diagnostic.private_netns.startup.terminal_substage", "str"),
    ("diagnostic.private_netns.startup.proof_complete", "bool"),
    ("diagnostic.private_netns.startup.process_started", "bool"),
    ("diagnostic.private_netns.startup.process_exit_observed", "bool"),
    ("diagnostic.private_netns.startup.socket_observed", "bool"),
    ("diagnostic.private_netns.startup.socket_wait_timeout", "bool"),
    ("diagnostic.private_netns.startup.namespace_create_attempted_count", "int"),
    ("diagnostic.private_netns.startup.namespace_create_succeeded_count", "int"),
    ("diagnostic.private_netns.startup.namespace_readback_attempted", "bool"),
    ("diagnostic.private_netns.startup.namespace_readback_succeeded", "bool"),
    ("diagnostic.private_netns.startup.namespace_expected_count", "int"),
    ("diagnostic.private_netns.startup.namespace_observed_count", "int"),
    ("diagnostic.private_netns.host_image.source_id_sha256", "str"),
    ("diagnostic.private_netns.host_image.archive_sha256", "str"),
    ("diagnostic.private_netns.host_image.archive_size", "int"),
    ("diagnostic.private_netns.host_image.private_id_sha256", "str"),
    ("diagnostic.private_netns.host_image.identity_match", "bool"),
    ("diagnostic.private_netns.isolation.netns_created", "bool"),
    ("diagnostic.private_netns.isolation.no_default_route", "bool"),
    ("diagnostic.private_netns.isolation.private_containerd_socket", "bool"),
    ("diagnostic.private_netns.isolation.private_dockerd_socket", "bool"),
    ("diagnostic.private_netns.isolation.system_containerd_coupled", "bool"),
    ("diagnostic.private_netns.isolation.daemon_namespace_match", "bool"),
    ("diagnostic.private_netns.isolation.containerd_namespace_match", "bool"),
    ("diagnostic.private_netns.isolation.shim_namespace_match", "bool"),
    ("diagnostic.private_netns.isolation.containers_namespace_isolated", "bool"),
    ("diagnostic.private_netns.isolation.namespace_identity_sha256", "str"),
    ("diagnostic.private_netns.isolation.cgroup_owned", "bool"),
    ("diagnostic.private_netns.isolation.cgroup_identity_sha256", "str"),
    ("diagnostic.private_netns.isolation.private_firewall_present", "bool"),
    ("diagnostic.private_netns.network.private_network_count", "int"),
    ("diagnostic.private_netns.network.container_count", "int"),
    ("diagnostic.private_netns.network.exact_attachment", "bool"),
    ("diagnostic.private_netns.network.container_security", "bool"),
    ("diagnostic.private_netns.network.same_network", "bool"),
    ("diagnostic.private_netns.network.external_dns_failed", "bool"),
    ("diagnostic.private_netns.network.literal_ip_failed", "bool"),
    ("diagnostic.private_netns.network.metadata_failed", "bool"),
    ("diagnostic.private_netns.network.gateway_failed", "bool"),
    ("diagnostic.private_netns.network.registry_failed", "bool"),
    ("diagnostic.private_netns.network.loopback_proxy", "bool"),
    ("diagnostic.private_netns.network.nonloopback_denied", "bool"),
    ("diagnostic.private_netns.host_firewall.observation_count", "int"),
    ("diagnostic.private_netns.host_firewall.preimage_sha256", "str"),
    ("diagnostic.private_netns.host_firewall.final_sha256", "str"),
    ("diagnostic.private_netns.host_firewall.preimage_semantic_sha256", "str"),
    ("diagnostic.private_netns.host_firewall.final_semantic_sha256", "str"),
    ("diagnostic.private_netns.host_firewall.canonical_restored", "bool"),
    ("diagnostic.private_netns.host_firewall.semantic_restored", "bool"),
    ("diagnostic.private_netns.host_firewall.table_count", "int"),
    ("diagnostic.private_netns.host_firewall.chain_count", "int"),
    ("diagnostic.private_netns.host_firewall.rule_count", "int"),
    ("diagnostic.private_netns.host_firewall.phase_manifest_sha256", "str"),
    ("diagnostic.private_netns.host_links.preimage_sha256", "str"),
    ("diagnostic.private_netns.host_links.final_sha256", "str"),
    ("diagnostic.private_netns.host_links.restored", "bool"),
    ("diagnostic.private_netns.host_links.veth_created", "bool"),
    ("diagnostic.private_netns.cleanup.attempted", "bool"),
    ("diagnostic.private_netns.cleanup.succeeded", "bool"),
    ("diagnostic.private_netns.cleanup.command_failure_count", "int"),
    ("diagnostic.private_netns.cleanup.failure_manifest_sha256", "str"),
    ("diagnostic.private_netns.cleanup.query_required_count", "int"),
    ("diagnostic.private_netns.cleanup.query_attempted_count", "int"),
    ("diagnostic.private_netns.cleanup.query_succeeded_count", "int"),
    ("diagnostic.private_netns.cleanup.query_failure_count", "int"),
    ("diagnostic.private_netns.cleanup.query_complete", "bool"),
    ("diagnostic.private_netns.cleanup.action_required_count", "int"),
    ("diagnostic.private_netns.cleanup.action_attempted_count", "int"),
    ("diagnostic.private_netns.cleanup.action_succeeded_count", "int"),
    ("diagnostic.private_netns.cleanup.action_failure_count", "int"),
    ("diagnostic.private_netns.cleanup.action_complete", "bool"),
    ("diagnostic.private_netns.cleanup.completeness_finalized", "bool"),
    ("diagnostic.private_netns.cleanup.proof_complete", "bool"),
    ("diagnostic.private_netns.cleanup.containers_remaining", "int"),
    ("diagnostic.private_netns.cleanup.images_remaining", "int"),
    ("diagnostic.private_netns.cleanup.volumes_remaining", "int"),
    ("diagnostic.private_netns.cleanup.networks_remaining", "int"),
    ("diagnostic.private_netns.cleanup.listeners_remaining", "int"),
    ("diagnostic.private_netns.cleanup.processes_remaining", "int"),
    ("diagnostic.private_netns.cleanup.namespaces_remaining", "int"),
    ("diagnostic.private_netns.cleanup.veths_remaining", "int"),
    ("diagnostic.private_netns.cleanup.sockets_remaining", "int"),
    ("diagnostic.private_netns.cleanup.pidfiles_remaining", "int"),
    ("diagnostic.private_netns.cleanup.cgroups_remaining", "int"),
    ("diagnostic.private_netns.cleanup.roots_remaining", "int"),
    ("diagnostic.private_netns.cleanup.scratch_remaining", "int"),
    ("diagnostic.private_netns.receipt_sha256", "str"),
)


class ProbeFailure(RuntimeError):
    def __init__(self, code: str):
        if code not in FAILURE_CODES:
            code = "PROBE_INTERNAL_ERROR"
        super().__init__(code)
        self.code = code


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def parse_json_object(raw: bytes) -> dict[str, Any]:
    value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=strict_object)
    if not isinstance(value, dict):
        raise ValueError("top level must be object")
    return value


def canonicalize_firewall(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: canonicalize_firewall(item)
            for key, item in sorted(value.items())
            if key not in {"handle", "packets", "bytes"}
        }
    if isinstance(value, list):
        return [canonicalize_firewall(item) for item in value]
    return value


def firewall_snapshot_from_json(raw: bytes) -> tuple[str, str, dict[str, int]]:
    value = parse_json_object(raw)
    entries = value.get("nftables")
    if not isinstance(entries, list) or not all(isinstance(item, dict) for item in entries):
        raise ValueError("invalid nftables collection")
    retained: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    for entry in entries:
        if "metainfo" in entry:
            continue
        retained.append(canonicalize_firewall(entry))
        for kind in entry:
            counts[kind] = counts.get(kind, 0) + 1
    canonical = json.dumps(retained, sort_keys=True, separators=(",", ":")).encode()
    non_rules: list[str] = []
    rule_groups: dict[str, list[Any]] = {}
    for entry in retained:
        rule = entry.get("rule")
        if isinstance(rule, dict):
            identity = json.dumps(
                [rule.get("family"), rule.get("table"), rule.get("chain")],
                separators=(",", ":"),
            )
            rule_groups.setdefault(identity, []).append(entry)
        else:
            non_rules.append(json.dumps(entry, sort_keys=True, separators=(",", ":")))
    semantic = {
        "non_rules": sorted(non_rules),
        "rule_groups": [
            {"identity": identity, "rules": rule_groups[identity]}
            for identity in sorted(rule_groups)
        ],
    }
    return (
        sha256_bytes(canonical),
        sha256_bytes(json.dumps(semantic, sort_keys=True, separators=(",", ":")).encode()),
        dict(sorted(counts.items())),
    )


def host_link_digest(raw: bytes) -> str:
    value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=strict_object)
    if not isinstance(value, list):
        raise ValueError("invalid link collection")
    admitted: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("invalid link entry")
        admitted.append(
            {
                "ifname": item.get("ifname"),
                "link_type": item.get("link_type"),
                "master": item.get("master"),
                "flags": sorted(item.get("flags", [])) if isinstance(item.get("flags", []), list) else None,
                "address_class": "present" if item.get("address") else "absent",
            }
        )
    return sha256_bytes(json.dumps(admitted, sort_keys=True, separators=(",", ":")).encode())


def default_receipt() -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, kind in FIELD_SPECS:
        if kind == "bool":
            result[key] = False
        elif kind == "int":
            result[key] = 0
        else:
            result[key] = ZERO_SHA256 if key.endswith("sha256") else "UNSET"
    result["diagnostic.private_netns.schema"] = SCHEMA
    result["diagnostic.private_netns.classification"] = REJECT_CLASS
    result["diagnostic.private_netns.failure_code"] = "PROBE_INTERNAL_ERROR"
    result["diagnostic.private_netns.runner.no_forbidden_host_change"] = True
    result["diagnostic.private_netns.startup.terminal_substage"] = "UNKNOWN_SANITIZED"
    result["diagnostic.private_netns.startup.namespace_expected_count"] = 2
    return result


def receipt_payload_lines(receipt: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    for key, kind in FIELD_SPECS:
        if key.endswith("receipt_sha256"):
            continue
        value = receipt[key]
        if kind == "bool":
            rendered = "true" if value else "false"
        else:
            rendered = str(value)
        lines.append(f"{key}\t{kind}\t{rendered}")
    return lines


def finalize_receipt(receipt: dict[str, Any]) -> None:
    payload = "\n".join(receipt_payload_lines(receipt)) + "\n"
    receipt["diagnostic.private_netns.receipt_sha256"] = sha256_bytes(payload.encode())


def validate_startup_diagnostic(receipt: dict[str, Any]) -> None:
    prefix = "diagnostic.private_netns.startup."
    substage = receipt[f"{prefix}terminal_substage"]
    proof_complete = receipt[f"{prefix}proof_complete"]
    process_started = receipt[f"{prefix}process_started"]
    process_exit = receipt[f"{prefix}process_exit_observed"]
    socket_observed = receipt[f"{prefix}socket_observed"]
    socket_timeout = receipt[f"{prefix}socket_wait_timeout"]
    create_attempted = receipt[f"{prefix}namespace_create_attempted_count"]
    create_succeeded = receipt[f"{prefix}namespace_create_succeeded_count"]
    readback_attempted = receipt[f"{prefix}namespace_readback_attempted"]
    readback_succeeded = receipt[f"{prefix}namespace_readback_succeeded"]
    namespace_expected = receipt[f"{prefix}namespace_expected_count"]
    namespace_observed = receipt[f"{prefix}namespace_observed_count"]
    if substage not in STARTUP_SUBSTAGES or namespace_expected != 2:
        raise ValueError("startup enum mismatch")
    if create_succeeded > create_attempted or create_attempted > namespace_expected or namespace_observed > namespace_expected:
        raise ValueError("startup count mismatch")
    if not proof_complete:
        if substage != "UNKNOWN_SANITIZED":
            raise ValueError("startup incomplete mismatch")
        return
    expected_shapes = {
        "PROCESS_EXIT_BEFORE_SOCKET": (True, True, False, False, 0, 0, False, False, 0),
        "SOCKET_READINESS_TIMEOUT": (True, False, False, True, 0, 0, False, False, 0),
        "NAMESPACE_CREATE_INITIAL_FAILED": (True, False, True, False, 1, 0, False, False, 0),
        "NAMESPACE_CREATE_RETRY_FAILED": (True, False, True, False, 2, 1, False, False, 0),
        "NAMESPACE_READBACK_FAILED": (True, False, True, False, 2, 2, True, False, namespace_observed),
        "READY": (True, False, True, False, 2, 2, True, True, 2),
    }
    observed_shape = (
        process_started,
        process_exit,
        socket_observed,
        socket_timeout,
        create_attempted,
        create_succeeded,
        readback_attempted,
        readback_succeeded,
        namespace_observed,
    )
    if substage not in expected_shapes or observed_shape != expected_shapes[substage]:
        raise ValueError("startup shape mismatch")


def validate_cleanup_completeness(receipt: dict[str, Any]) -> None:
    prefix = "diagnostic.private_netns.cleanup."
    cleanup_attempted = receipt[f"{prefix}attempted"]
    command_failures = receipt[f"{prefix}command_failure_count"]
    query_required = receipt[f"{prefix}query_required_count"]
    query_attempted = receipt[f"{prefix}query_attempted_count"]
    query_succeeded = receipt[f"{prefix}query_succeeded_count"]
    query_failures = receipt[f"{prefix}query_failure_count"]
    query_complete = receipt[f"{prefix}query_complete"]
    action_required = receipt[f"{prefix}action_required_count"]
    action_attempted = receipt[f"{prefix}action_attempted_count"]
    action_succeeded = receipt[f"{prefix}action_succeeded_count"]
    action_failures = receipt[f"{prefix}action_failure_count"]
    action_complete = receipt[f"{prefix}action_complete"]
    completeness_finalized = receipt[f"{prefix}completeness_finalized"]
    proof_complete = receipt[f"{prefix}proof_complete"]
    if not completeness_finalized:
        denominator_values = (
            query_required,
            query_attempted,
            query_succeeded,
            query_failures,
            action_required,
            action_attempted,
            action_succeeded,
            action_failures,
        )
        if (
            query_complete
            or action_complete
            or proof_complete
            or receipt[f"{prefix}succeeded"]
            or any(denominator_values)
        ):
            raise ValueError("cleanup incomplete contradiction")
        return
    for required, attempted, succeeded, failures, complete in (
        (query_required, query_attempted, query_succeeded, query_failures, query_complete),
        (action_required, action_attempted, action_succeeded, action_failures, action_complete),
    ):
        if succeeded > attempted or attempted > required or failures != attempted - succeeded:
            raise ValueError("cleanup completeness count mismatch")
        if complete != (cleanup_attempted and required == attempted == succeeded and failures == 0):
            raise ValueError("cleanup completeness boolean mismatch")
    if command_failures < query_failures + action_failures:
        raise ValueError("cleanup failure denominator mismatch")
    if receipt[f"{prefix}succeeded"] != proof_complete:
        raise ValueError("cleanup proof mismatch")
    if proof_complete and (
        receipt[f"{prefix}attempted"] is not True
        or query_complete is not True
        or action_complete is not True
        or command_failures != 0
    ):
        raise ValueError("cleanup proof contradiction")
    if proof_complete:
        residue_keys = (
            "containers_remaining",
            "images_remaining",
            "volumes_remaining",
            "networks_remaining",
            "listeners_remaining",
            "processes_remaining",
            "namespaces_remaining",
            "veths_remaining",
            "sockets_remaining",
            "pidfiles_remaining",
            "cgroups_remaining",
            "roots_remaining",
            "scratch_remaining",
        )
        if any(receipt[f"{prefix}{key}"] != 0 for key in residue_keys):
            raise ValueError("cleanup residue proof contradiction")
        if (
            receipt["diagnostic.private_netns.host_firewall.semantic_restored"] is not True
            or receipt["diagnostic.private_netns.host_firewall.canonical_restored"] is not True
            or receipt["diagnostic.private_netns.host_links.restored"] is not True
        ):
            raise ValueError("cleanup host proof contradiction")


def validate_receipt(receipt: dict[str, Any]) -> None:
    expected = {key for key, _ in FIELD_SPECS}
    if set(receipt) != expected:
        raise ValueError("receipt key mismatch")
    if receipt["diagnostic.private_netns.schema"] != SCHEMA:
        raise ValueError("schema mismatch")
    classification = receipt["diagnostic.private_netns.classification"]
    failure_code = receipt["diagnostic.private_netns.failure_code"]
    if classification not in {PASS_CLASS, REJECT_CLASS} or failure_code not in FAILURE_CODES:
        raise ValueError("classification mismatch")
    if classification == PASS_CLASS and failure_code != "PASS":
        raise ValueError("pass mismatch")
    if classification == REJECT_CLASS and failure_code == "PASS":
        raise ValueError("reject mismatch")
    for key, kind in FIELD_SPECS:
        value = receipt[key]
        if kind == "bool" and not isinstance(value, bool):
            raise ValueError("bool mismatch")
        if kind == "int" and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
            raise ValueError("int mismatch")
        if kind == "str" and not isinstance(value, str):
            raise ValueError("str mismatch")
        if key.endswith("sha256") and not re.fullmatch(r"[0-9a-f]{64}", str(value)):
            raise ValueError("digest mismatch")
    validate_startup_diagnostic(receipt)
    validate_cleanup_completeness(receipt)
    startup_substage = receipt["diagnostic.private_netns.startup.terminal_substage"]
    if failure_code == "PRIVATE_CONTAINERD_START_FAILED" and startup_substage not in {
        "PROCESS_EXIT_BEFORE_SOCKET",
        "SOCKET_READINESS_TIMEOUT",
        "NAMESPACE_CREATE_INITIAL_FAILED",
        "NAMESPACE_CREATE_RETRY_FAILED",
        "NAMESPACE_READBACK_FAILED",
    }:
        raise ValueError("containerd failure diagnostic mismatch")
    if failure_code == "PASS" and startup_substage != "READY":
        raise ValueError("pass startup diagnostic mismatch")
    observed = receipt["diagnostic.private_netns.receipt_sha256"]
    payload = "\n".join(receipt_payload_lines(receipt)) + "\n"
    if observed != sha256_bytes(payload.encode()):
        raise ValueError("receipt digest mismatch")


def format_receipt(receipt: dict[str, Any]) -> str:
    validate_receipt(receipt)
    lines: list[str] = []
    for key, kind in FIELD_SPECS:
        value = receipt[key]
        rendered = "true" if kind == "bool" and value else "false" if kind == "bool" else str(value)
        lines.append(f"{key}\t{kind}\t{rendered}")
    return "\n".join(lines) + "\n"


def parse_receipt(raw: bytes) -> dict[str, Any]:
    text = raw.decode("utf-8", "strict")
    if not text.endswith("\n") or "\r" in text or "\x00" in text:
        raise ValueError("framing mismatch")
    result: dict[str, Any] = {}
    type_map = dict(FIELD_SPECS)
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            raise ValueError("line mismatch")
        key, kind, raw_value = parts
        if key in result or type_map.get(key) != kind:
            raise ValueError("field mismatch")
        if kind == "bool":
            if raw_value not in {"true", "false"}:
                raise ValueError("bool mismatch")
            value: Any = raw_value == "true"
        elif kind == "int":
            if not re.fullmatch(r"0|[1-9][0-9]*", raw_value):
                raise ValueError("int mismatch")
            value = int(raw_value)
        else:
            if not re.fullmatch(r"[A-Za-z0-9_.:-]+", raw_value):
                raise ValueError("string mismatch")
            value = raw_value
        result[key] = value
    validate_receipt(result)
    return result


def run_command(
    command: list[str],
    *,
    timeout: float = 30,
    input_bytes: bytes | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        command,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
        env=env,
    )
    if len(result.stdout) > OUTPUT_LIMIT or len(result.stderr) > OUTPUT_LIMIT:
        raise ProbeFailure("PROBE_INTERNAL_ERROR")
    return result


def build_containerd_command(binary: str, runtime: Path) -> list[str]:
    runtime_path = runtime.as_posix()
    return [
        "ip",
        "netns",
        "exec",
        NS_NAME,
        binary,
        "--config",
        f"{runtime_path}/containerd.toml",
        "--address",
        f"{runtime_path}/containerd.sock",
        "--state",
        f"{runtime_path}/containerd-state",
        "--root",
        f"{runtime_path}/containerd-root",
        "--log-level",
        "error",
    ]


def build_dockerd_command(binary: str, runtime: Path) -> list[str]:
    runtime_path = runtime.as_posix()
    return [
        "ip",
        "netns",
        "exec",
        NS_NAME,
        binary,
        f"--config-file={runtime_path}/daemon.json",
        f"--host=unix://{runtime_path}/docker.sock",
        f"--pidfile={runtime_path}/dockerd.pid",
        f"--data-root={runtime_path}/docker-data",
        f"--exec-root={runtime_path}/docker-exec",
        "--bridge=none",
        "--iptables=true",
        "--ip6tables=false",
        "--ip-forward=true",
        "--ip-masq=true",
        "--firewall-backend=iptables",
        "--userland-proxy=false",
        f"--containerd={runtime_path}/containerd.sock",
        f"--containerd-namespace={CONTAINERD_NAMESPACE}",
        f"--containerd-plugins-namespace={CONTAINERD_PLUGINS_NAMESPACE}",
        "--default-cgroupns-mode=private",
        "--exec-opt=native.cgroupdriver=cgroupfs",
        f"--cgroup-parent=/{CGROUP_NAME}",
        "--default-address-pool=base=172.30.0.0/16,size=24",
        "--log-level=error",
    ]


def build_private_firewall_batch() -> bytes:
    return ("\n".join(
        (
            f"add table inet {PRIVATE_TABLE}",
            f"add chain inet {PRIVATE_TABLE} input {{ type filter hook input priority -20; policy accept; }}",
            f"add chain inet {PRIVATE_TABLE} forward {{ type filter hook forward priority -20; policy accept; }}",
            f"add chain inet {PRIVATE_TABLE} output {{ type filter hook output priority -20; policy accept; }}",
            f'add rule inet {PRIVATE_TABLE} input iifname "{BRIDGE_NAME}" ct state established,related accept',
            f'add rule inet {PRIVATE_TABLE} input iifname "{BRIDGE_NAME}" drop',
            f'add rule inet {PRIVATE_TABLE} forward iifname "{BRIDGE_NAME}" oifname "{BRIDGE_NAME}" accept',
            f'add rule inet {PRIVATE_TABLE} forward iifname "{BRIDGE_NAME}" drop',
            "",
        )
    )).encode()


class LoopbackProxy:
    def __init__(self, namespace_path: Path, backend_host: str, backend_port: int, listen_port: int):
        self.namespace_path = namespace_path
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.stop_event = threading.Event()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", listen_port))
        self.listener.listen(8)
        self.listener.settimeout(0.2)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.workers: list[threading.Thread] = []

    def start(self) -> None:
        self.thread.start()

    def _serve(self) -> None:
        while not self.stop_event.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            worker = threading.Thread(target=self._proxy_once, args=(client,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def _proxy_once(self, client: socket.socket) -> None:
        backend: socket.socket | None = None
        try:
            namespace_fd = os.open(self.namespace_path, os.O_RDONLY)
            try:
                libc = ctypes.CDLL(None, use_errno=True)
                if libc.setns(namespace_fd, 0x40000000) != 0:
                    raise OSError(ctypes.get_errno(), "setns")
            finally:
                os.close(namespace_fd)
            backend = socket.create_connection((self.backend_host, self.backend_port), timeout=3)
            client.settimeout(3)
            backend.settimeout(3)
            request = client.recv(4096)
            if request:
                backend.sendall(request)
                response = backend.recv(4096)
                if response:
                    client.sendall(response)
        except OSError:
            pass
        finally:
            if backend is not None:
                backend.close()
            client.close()

    def close(self) -> None:
        self.stop_event.set()
        self.listener.close()
        self.thread.join(timeout=2)
        for worker in self.workers:
            worker.join(timeout=2)


class Probe:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.receipt = default_receipt()
        self.runtime = args.runtime
        self.workspace = args.workspace_root
        self.private_env = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": str(self.runtime / "home"),
            "DOCKER_CONFIG": str(self.runtime / "docker-config"),
            "DOCKER_TMPDIR": str(self.runtime / "docker-tmp"),
            "XDG_RUNTIME_DIR": str(self.runtime / "xdg-runtime"),
        }
        self.processes: list[subprocess.Popen[bytes]] = []
        self.containerd_process: subprocess.Popen[bytes] | None = None
        self.dockerd_process: subprocess.Popen[bytes] | None = None
        self.proxy: LoopbackProxy | None = None
        self.netns_created = False
        self.cgroup_created = False
        self.host_firewall_pre: tuple[str, str, dict[str, int]] | None = None
        self.host_firewall_phases: list[tuple[str, str, str]] = []
        self.host_link_pre = ZERO_SHA256
        self.service_id = ""
        self.client_id = ""
        self.private_image_id = ""
        self.cleanup_failures: list[str] = []
        self.cleanup_query_required: list[str] = []
        self.cleanup_query_attempted: list[str] = []
        self.cleanup_query_succeeded: list[str] = []
        self.cleanup_action_required: list[str] = []
        self.cleanup_action_attempted: list[str] = []
        self.cleanup_action_succeeded: list[str] = []
        self.private_docker_cleanup_latched = False
        self.private_docker_action_obligations: set[str] = set()

    @property
    def docker_host(self) -> str:
        return f"unix://{self.runtime / 'docker.sock'}"

    @property
    def docker(self) -> list[str]:
        return ["docker", "--host", self.docker_host]

    @property
    def cgroup_path(self) -> Path:
        return Path("/sys/fs/cgroup") / CGROUP_NAME

    def fail(self, code: str) -> None:
        raise ProbeFailure(code)

    def validate_arguments(self) -> None:
        if os.geteuid() != 0:
            self.fail("ROOT_PRIVILEGE_UNAVAILABLE")
        self.receipt["diagnostic.private_netns.runner.rootful"] = True
        if self.args.runner_uid <= 0:
            self.fail("RUNNER_IDENTITY_INVALID")
        self.receipt["diagnostic.private_netns.runner.runner_nonroot"] = True
        self.receipt["diagnostic.private_netns.runner.sudo_boundary"] = True
        try:
            workspace = self.workspace.resolve(strict=True)
            runtime_parent = self.runtime.parent.resolve(strict=True)
            if runtime_parent != workspace / ".smoke-runtime" or self.runtime.name != "private-netns":
                self.fail("PACKET_PATH_INVALID")
            if self.runtime.exists() or self.runtime.is_symlink():
                self.fail("PACKET_PATH_COLLISION")
            if any(parent.is_symlink() for parent in (workspace, runtime_parent)):
                self.fail("PACKET_PATH_INVALID")
        except (OSError, RuntimeError):
            self.fail("PACKET_PATH_INVALID")
        tools = ("containerd", "ctr", "docker", "dockerd", "ip", "nft", "ss")
        locations: list[str] = []
        for tool in tools:
            location = shutil.which(tool)
            if not location:
                self.fail("CAPABILITY_TOOL_MISSING")
            locations.append(f"{tool}:{Path(location).name}")
        self.receipt["diagnostic.private_netns.runner.tool_count"] = len(tools)
        self.receipt["diagnostic.private_netns.runner.tool_manifest_sha256"] = sha256_bytes(
            ("\n".join(locations) + "\n").encode()
        )
        if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
            self.fail("CGROUP_V2_UNAVAILABLE")
        self.receipt["diagnostic.private_netns.runner.cgroup_v2"] = True

    def host_firewall_snapshot(self, phase: str) -> tuple[str, str, dict[str, int]]:
        result = run_command(["nft", "-j", "list", "ruleset"], timeout=10, env=self.private_env)
        if result.returncode != 0:
            self.fail("HOST_FIREWALL_QUERY_FAILED")
        try:
            snapshot = firewall_snapshot_from_json(result.stdout)
        except (UnicodeError, ValueError, json.JSONDecodeError):
            self.fail("HOST_FIREWALL_QUERY_FAILED")
        self.host_firewall_phases.append((phase, snapshot[0], snapshot[1]))
        if self.host_firewall_pre is not None and snapshot != self.host_firewall_pre:
            self.fail("HOST_FIREWALL_DRIFT")
        return snapshot

    def host_links(self) -> str:
        result = run_command(["ip", "-j", "link", "show"], timeout=10, env=self.private_env)
        if result.returncode != 0:
            self.fail("HOST_LINK_STATE_DRIFT")
        try:
            return host_link_digest(result.stdout)
        except (UnicodeError, ValueError, json.JSONDecodeError):
            self.fail("HOST_LINK_STATE_DRIFT")

    def prepare_host_image(self) -> None:
        self.runtime.mkdir(mode=0o700)
        (self.runtime / "home").mkdir(mode=0o700)
        (self.runtime / "docker-config").mkdir(mode=0o700)
        (self.runtime / "docker-tmp").mkdir(mode=0o700)
        (self.runtime / "xdg-runtime").mkdir(mode=0o700)
        (self.runtime / "daemon.json").write_text("{}\n", encoding="ascii")
        (self.runtime / "containerd.toml").write_text(
            'version = 2\ndisabled_plugins = ["io.containerd.grpc.v1.cri"]\n',
            encoding="ascii",
        )
        inspect = run_command(
            ["docker", "--host", "unix:///var/run/docker.sock", "image", "inspect", "--format", "{{.Id}}", self.args.image],
            env=self.private_env,
        )
        if inspect.returncode != 0:
            self.fail("HOST_DOCKER_UNAVAILABLE")
        image_id = inspect.stdout.decode("utf-8", "strict").strip()
        if image_id != self.args.expected_image_id:
            self.fail("HOST_IMAGE_IDENTITY_MISMATCH")
        self.receipt["diagnostic.private_netns.host_image.source_id_sha256"] = sha256_bytes(image_id.encode())
        archive = self.runtime / "image.tar"
        saved = run_command(
            ["docker", "--host", "unix:///var/run/docker.sock", "image", "save", "--output", str(archive), self.args.image],
            timeout=180,
            env=self.private_env,
        )
        if saved.returncode != 0 or not archive.is_file() or archive.is_symlink():
            self.fail("HOST_IMAGE_SAVE_FAILED")
        archive_size = archive.stat().st_size
        self.receipt["diagnostic.private_netns.host_image.archive_size"] = archive_size
        self.receipt["diagnostic.private_netns.host_image.archive_sha256"] = sha256_file(archive)
        free = shutil.disk_usage(self.runtime).free
        required = max(MINIMUM_EXTRA_DISK, archive_size * 4)
        self.receipt["diagnostic.private_netns.runner.disk_free_bytes"] = free
        self.receipt["diagnostic.private_netns.runner.disk_required_bytes"] = required
        self.receipt["diagnostic.private_netns.runner.disk_margin_ok"] = free >= required
        if free < required:
            self.fail("DISK_MARGIN_INADEQUATE")
        self.host_firewall_pre = self.host_firewall_snapshot("preimage")
        self.host_link_pre = self.host_links()
        self.receipt["diagnostic.private_netns.host_links.preimage_sha256"] = self.host_link_pre
        self.receipt["diagnostic.private_netns.host_firewall.preimage_sha256"] = self.host_firewall_pre[0]
        self.receipt["diagnostic.private_netns.host_firewall.preimage_semantic_sha256"] = self.host_firewall_pre[1]
        self.receipt["diagnostic.private_netns.host_firewall.table_count"] = self.host_firewall_pre[2].get("table", 0)
        self.receipt["diagnostic.private_netns.host_firewall.chain_count"] = self.host_firewall_pre[2].get("chain", 0)
        self.receipt["diagnostic.private_netns.host_firewall.rule_count"] = self.host_firewall_pre[2].get("rule", 0)

    def create_cgroup(self) -> None:
        try:
            self.cgroup_path.mkdir(mode=0o755)
            self.cgroup_created = True
        except OSError:
            self.fail("CGROUP_CREATE_FAILED")

    def create_netns(self) -> None:
        existing = run_command(["ip", "netns", "list"], env=self.private_env)
        if existing.returncode != 0 or NS_NAME.encode() in existing.stdout:
            self.fail("PACKET_PATH_COLLISION")
        created = run_command(["ip", "netns", "add", NS_NAME], env=self.private_env)
        if created.returncode != 0:
            self.fail("NETNS_CREATE_FAILED")
        self.netns_created = True
        self.receipt["diagnostic.private_netns.isolation.netns_created"] = True
        if run_command(["ip", "-n", NS_NAME, "link", "set", "lo", "up"], env=self.private_env).returncode != 0:
            self.fail("NETNS_CREATE_FAILED")
        routes = run_command(["ip", "-n", NS_NAME, "route", "show", "default"], env=self.private_env)
        if routes.returncode != 0 or routes.stdout.strip():
            self.fail("NETNS_ROUTE_INVALID")
        self.receipt["diagnostic.private_netns.isolation.no_default_route"] = True
        self.host_firewall_snapshot("netns_created")

    def move_to_cgroup(self, pid: int) -> None:
        try:
            (self.cgroup_path / "cgroup.procs").write_text(f"{pid}\n", encoding="ascii")
        except OSError:
            self.fail("CGROUP_CREATE_FAILED")

    def wait_for_socket(self, path: Path, process: subprocess.Popen[bytes], code: str, seconds: int = 30) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if process.poll() is not None:
                self.fail(code)
            if path.is_socket():
                return
            time.sleep(0.1)
        self.fail(code)

    def set_startup_substage(self, substage: str) -> None:
        if substage not in STARTUP_SUBSTAGES or substage == "UNKNOWN_SANITIZED":
            self.fail("PROBE_INTERNAL_ERROR")
        self.receipt["diagnostic.private_netns.startup.terminal_substage"] = substage
        self.receipt["diagnostic.private_netns.startup.proof_complete"] = True

    def wait_for_containerd_socket(self) -> None:
        assert self.containerd_process is not None
        path = self.runtime / "containerd.sock"
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.containerd_process.poll() is not None:
                self.receipt["diagnostic.private_netns.startup.process_exit_observed"] = True
                self.set_startup_substage("PROCESS_EXIT_BEFORE_SOCKET")
                self.fail("PRIVATE_CONTAINERD_START_FAILED")
            if path.is_socket():
                self.receipt["diagnostic.private_netns.startup.socket_observed"] = True
                return
            time.sleep(0.1)
        self.receipt["diagnostic.private_netns.startup.socket_wait_timeout"] = True
        self.set_startup_substage("SOCKET_READINESS_TIMEOUT")
        self.fail("PRIVATE_CONTAINERD_START_FAILED")

    def verify_private_containerd_namespaces(self) -> None:
        self.receipt["diagnostic.private_netns.startup.namespace_readback_attempted"] = True
        try:
            result = run_command(
                [
                    "ctr",
                    "--address",
                    str(self.runtime / "containerd.sock"),
                    "namespaces",
                    "list",
                    "--quiet",
                ],
                env=self.private_env,
            )
        except (OSError, subprocess.TimeoutExpired, ProbeFailure):
            self.set_startup_substage("NAMESPACE_READBACK_FAILED")
            self.fail("PRIVATE_CONTAINERD_START_FAILED")
        expected = {CONTAINERD_NAMESPACE.encode(), CONTAINERD_PLUGINS_NAMESPACE.encode()}
        observed = set(result.stdout.splitlines()) if result.returncode == 0 else set()
        observed_count = len(expected.intersection(observed))
        self.receipt["diagnostic.private_netns.startup.namespace_observed_count"] = observed_count
        if result.returncode != 0 or observed_count != len(expected):
            self.set_startup_substage("NAMESPACE_READBACK_FAILED")
            self.fail("PRIVATE_CONTAINERD_START_FAILED")
        self.receipt["diagnostic.private_netns.startup.namespace_readback_succeeded"] = True
        self.set_startup_substage("READY")

    def create_private_containerd_namespaces(self) -> None:
        for index, namespace in enumerate((CONTAINERD_NAMESPACE, CONTAINERD_PLUGINS_NAMESPACE)):
            self.receipt["diagnostic.private_netns.startup.namespace_create_attempted_count"] = index + 1
            try:
                created = run_command(
                    [
                        "ctr",
                        "--address",
                        str(self.runtime / "containerd.sock"),
                        "namespaces",
                        "create",
                        namespace,
                    ],
                    env=self.private_env,
                )
            except (OSError, subprocess.TimeoutExpired, ProbeFailure):
                self.set_startup_substage(
                    "NAMESPACE_CREATE_INITIAL_FAILED" if index == 0 else "NAMESPACE_CREATE_RETRY_FAILED"
                )
                self.fail("PRIVATE_CONTAINERD_START_FAILED")
            if created.returncode != 0:
                self.set_startup_substage(
                    "NAMESPACE_CREATE_INITIAL_FAILED" if index == 0 else "NAMESPACE_CREATE_RETRY_FAILED"
                )
                self.fail("PRIVATE_CONTAINERD_START_FAILED")
            self.receipt["diagnostic.private_netns.startup.namespace_create_succeeded_count"] = index + 1

    def start_daemons(self) -> None:
        devnull = subprocess.DEVNULL
        self.containerd_process = subprocess.Popen(
            build_containerd_command(shutil.which("containerd") or "containerd", self.runtime),
            stdin=devnull,
            stdout=devnull,
            stderr=devnull,
            env=self.private_env,
        )
        self.processes.append(self.containerd_process)
        self.receipt["diagnostic.private_netns.startup.process_started"] = True
        self.move_to_cgroup(self.containerd_process.pid)
        self.wait_for_containerd_socket()
        self.receipt["diagnostic.private_netns.isolation.private_containerd_socket"] = True
        self.create_private_containerd_namespaces()
        self.verify_private_containerd_namespaces()
        self.dockerd_process = subprocess.Popen(
            build_dockerd_command(shutil.which("dockerd") or "dockerd", self.runtime),
            stdin=devnull,
            stdout=devnull,
            stderr=devnull,
            env=self.private_env,
        )
        self.processes.append(self.dockerd_process)
        self.latch_private_docker_runtime_cleanup()
        self.move_to_cgroup(self.dockerd_process.pid)
        self.wait_for_socket(self.runtime / "docker.sock", self.dockerd_process, "PRIVATE_DOCKERD_START_FAILED", 45)
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            probe = run_command([*self.docker, "version", "--format", "{{.Server.Version}}"], timeout=5, env=self.private_env)
            if probe.returncode == 0 and probe.stdout.strip():
                break
            if self.dockerd_process.poll() is not None:
                self.fail("PRIVATE_DOCKERD_START_FAILED")
            time.sleep(0.2)
        else:
            self.fail("PRIVATE_DOCKERD_START_FAILED")
        self.receipt["diagnostic.private_netns.isolation.private_dockerd_socket"] = True
        self.verify_daemon_arguments()
        self.verify_process_boundaries(before_containers=True)
        self.host_firewall_snapshot("daemons_started")

    def verify_daemon_arguments(self) -> None:
        assert self.dockerd_process is not None
        try:
            raw = Path(f"/proc/{self.dockerd_process.pid}/cmdline").read_bytes()
        except OSError:
            self.fail("PRIVATE_DAEMON_ARGUMENT_REJECTED")
        arguments = raw.rstrip(b"\0").split(b"\0")
        required = [
            b"--bridge=none",
            b"--iptables=true",
            b"--firewall-backend=iptables",
            f"--containerd={self.runtime / 'containerd.sock'}".encode(),
            f"--containerd-namespace={CONTAINERD_NAMESPACE}".encode(),
            f"--containerd-plugins-namespace={CONTAINERD_PLUGINS_NAMESPACE}".encode(),
            f"--cgroup-parent=/{CGROUP_NAME}".encode(),
        ]
        if any(item not in arguments for item in required) or any(item.startswith(b"--host=tcp") for item in arguments):
            self.fail("PRIVATE_DAEMON_ARGUMENT_REJECTED")
        system_socket = Path("/run/containerd/containerd.sock")
        coupled = False
        if system_socket.exists():
            system_namespaces = run_command(["ctr", "--address", str(system_socket), "namespaces", "list", "--quiet"], env=self.private_env)
            if system_namespaces.returncode != 0:
                self.fail("SYSTEM_CONTAINERD_COUPLING")
            coupled = CONTAINERD_NAMESPACE.encode() in system_namespaces.stdout.splitlines()
        self.receipt["diagnostic.private_netns.isolation.system_containerd_coupled"] = coupled
        if coupled:
            self.fail("SYSTEM_CONTAINERD_COUPLING")

    @staticmethod
    def namespace_identity(pid: int) -> str:
        identity = os.stat(f"/proc/{pid}/ns/net")
        return f"{identity.st_dev}:{identity.st_ino}"

    @staticmethod
    def namespace_path_identity(path: Path) -> str:
        identity = path.stat()
        return f"{identity.st_dev}:{identity.st_ino}"

    @staticmethod
    def cgroup_owned(pid: int) -> bool:
        try:
            return CGROUP_NAME in Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8")
        except OSError:
            return False

    def verify_process_boundaries(self, *, before_containers: bool) -> None:
        assert self.containerd_process is not None and self.dockerd_process is not None
        try:
            private_identity = self.namespace_path_identity(Path("/var/run/netns") / NS_NAME)
            host_identity = self.namespace_path_identity(Path("/proc/self/ns/net"))
            containerd_identity = self.namespace_identity(self.containerd_process.pid)
            dockerd_identity = self.namespace_identity(self.dockerd_process.pid)
        except OSError:
            self.fail("PRIVATE_NAMESPACE_IDENTITY_FAILED")
        daemon_match = dockerd_identity == private_identity != host_identity
        containerd_match = containerd_identity == private_identity != host_identity
        self.receipt["diagnostic.private_netns.isolation.daemon_namespace_match"] = daemon_match
        self.receipt["diagnostic.private_netns.isolation.containerd_namespace_match"] = containerd_match
        if not daemon_match or not containerd_match:
            self.fail("PRIVATE_NAMESPACE_IDENTITY_FAILED")
        cgroup_ok = self.cgroup_owned(self.containerd_process.pid) and self.cgroup_owned(self.dockerd_process.pid)
        identities = [host_identity, private_identity, containerd_identity, dockerd_identity]
        if not before_containers:
            container_pids: list[int] = []
            for identity in (self.service_id, self.client_id):
                result = run_command([*self.docker, "inspect", "--format", "{{.State.Pid}}", identity], env=self.private_env)
                if result.returncode != 0:
                    self.fail("PRIVATE_NAMESPACE_IDENTITY_FAILED")
                container_pids.append(int(result.stdout.strip()))
            container_namespaces = [self.namespace_identity(pid) for pid in container_pids]
            isolated = all(item not in {host_identity, private_identity} for item in container_namespaces) and len(set(container_namespaces)) == 2
            self.receipt["diagnostic.private_netns.isolation.containers_namespace_isolated"] = isolated
            if not isolated:
                self.fail("PRIVATE_NAMESPACE_IDENTITY_FAILED")
            cgroup_ok = cgroup_ok and all(self.cgroup_owned(pid) for pid in container_pids)
            shim_pids: list[int] = []
            for item in Path("/proc").iterdir():
                if not item.name.isdigit():
                    continue
                try:
                    if (item / "comm").read_text(encoding="utf-8").strip().startswith("containerd-shim") and self.namespace_identity(int(item.name)) == private_identity:
                        shim_pids.append(int(item.name))
                except (OSError, ValueError):
                    continue
            shim_match = len(shim_pids) >= 2 and all(self.cgroup_owned(pid) for pid in shim_pids)
            self.receipt["diagnostic.private_netns.isolation.shim_namespace_match"] = shim_match
            if not shim_match:
                self.fail("PRIVATE_NAMESPACE_IDENTITY_FAILED")
            identities.extend(container_namespaces)
        self.receipt["diagnostic.private_netns.isolation.cgroup_owned"] = cgroup_ok
        self.receipt["diagnostic.private_netns.isolation.namespace_identity_sha256"] = sha256_bytes(("\n".join(sorted(identities)) + "\n").encode())
        self.receipt["diagnostic.private_netns.isolation.cgroup_identity_sha256"] = sha256_bytes(CGROUP_NAME.encode())
        if not cgroup_ok:
            self.fail("PRIVATE_CGROUP_OWNERSHIP_FAILED")

    def load_image(self) -> None:
        loaded = run_command([*self.docker, "image", "load", "--input", str(self.runtime / "image.tar")], timeout=180, env=self.private_env)
        if loaded.returncode != 0:
            self.fail("PRIVATE_IMAGE_LOAD_FAILED")
        self.latch_private_docker_action("REMOVE_IMAGE")
        inspected = run_command([*self.docker, "image", "inspect", "--format", "{{.Id}}", self.args.image], env=self.private_env)
        if inspected.returncode != 0:
            self.fail("PRIVATE_IMAGE_LOAD_FAILED")
        self.private_image_id = inspected.stdout.decode("utf-8", "strict").strip()
        self.receipt["diagnostic.private_netns.host_image.private_id_sha256"] = sha256_bytes(self.private_image_id.encode())
        matches = self.private_image_id == self.args.expected_image_id
        self.receipt["diagnostic.private_netns.host_image.identity_match"] = matches
        if not matches:
            self.fail("PRIVATE_IMAGE_IDENTITY_MISMATCH")

    def create_private_network(self) -> None:
        command = [
            *self.docker,
            "network",
            "create",
            "--driver",
            "bridge",
            "--internal",
            "--ipv6=false",
            "--subnet",
            PRIVATE_SUBNET,
            "--gateway",
            PRIVATE_GATEWAY,
            "--opt",
            f"com.docker.network.bridge.name={BRIDGE_NAME}",
            "--label",
            f"io.fawxzzy.packet={self.args.packet}",
            NETWORK_NAME,
        ]
        created = run_command(command, env=self.private_env)
        if created.returncode != 0 or not created.stdout.strip():
            self.fail("PRIVATE_NETWORK_CREATE_FAILED")
        self.latch_private_docker_action("REMOVE_NETWORK")
        firewall = run_command(
            ["ip", "netns", "exec", NS_NAME, "nft", "-f", "-"],
            input_bytes=build_private_firewall_batch(),
            env=self.private_env,
        )
        if firewall.returncode != 0:
            self.fail("PRIVATE_FIREWALL_INSTALL_FAILED")
        readback = run_command(["ip", "netns", "exec", NS_NAME, "nft", "-j", "list", "table", "inet", PRIVATE_TABLE], env=self.private_env)
        if readback.returncode != 0:
            self.fail("PRIVATE_FIREWALL_INSTALL_FAILED")
        self.receipt["diagnostic.private_netns.isolation.private_firewall_present"] = True
        networks = run_command([*self.docker, "network", "ls", "--filter", f"label=io.fawxzzy.packet={self.args.packet}", "--format", "{{.ID}}"], env=self.private_env)
        if networks.returncode != 0 or len([line for line in networks.stdout.splitlines() if line]) != 1:
            self.fail("PRIVATE_NETWORK_CREATE_FAILED")
        self.receipt["diagnostic.private_netns.network.private_network_count"] = 1
        self.host_firewall_snapshot("private_network_created")

    def start_containers(self) -> None:
        service = run_command(
            [
                *self.docker,
                "run",
                "-d",
                "--pull=never",
                "--name",
                SERVICE_NAME,
                "--label",
                f"io.fawxzzy.packet={self.args.packet}",
                "--label",
                "io.fawxzzy.role=private-netns-service",
                "--network",
                NETWORK_NAME,
                "--tmpfs",
                "/var/lib/postgresql/data:rw,nosuid,nodev,noexec,size=512m",
                "--restart=no",
                "--security-opt=no-new-privileges",
                "--health-cmd=pg_isready -U postgres -h 127.0.0.1",
                "--health-interval=1s",
                "--health-timeout=2s",
                "--health-start-period=30s",
                "--health-retries=30",
                "--env",
                "POSTGRES_HOST_AUTH_METHOD=trust",
                self.args.image,
            ],
            timeout=45,
            env=self.private_env,
        )
        if service.returncode != 0 or not service.stdout.strip():
            self.fail("PRIVATE_CONTAINER_CREATE_FAILED")
        self.latch_private_docker_action("REMOVE_SERVICE")
        self.service_id = service.stdout.decode("utf-8", "strict").strip()
        client = run_command(
            [
                *self.docker,
                "run",
                "-d",
                "--pull=never",
                "--name",
                CLIENT_NAME,
                "--label",
                f"io.fawxzzy.packet={self.args.packet}",
                "--label",
                "io.fawxzzy.role=private-netns-client",
                "--network",
                NETWORK_NAME,
                "--tmpfs",
                "/var/lib/postgresql/data:rw,nosuid,nodev,noexec,size=64m",
                "--restart=no",
                "--security-opt=no-new-privileges",
                "--entrypoint",
                "sleep",
                self.args.image,
                "infinity",
            ],
            timeout=45,
            env=self.private_env,
        )
        if client.returncode != 0 or not client.stdout.strip():
            self.fail("PRIVATE_CONTAINER_CREATE_FAILED")
        self.latch_private_docker_action("REMOVE_CLIENT")
        self.client_id = client.stdout.decode("utf-8", "strict").strip()
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            health = run_command([*self.docker, "inspect", "--format", "{{.State.Health.Status}}", self.service_id], env=self.private_env)
            if health.returncode == 0 and health.stdout.strip() == b"healthy":
                break
            if health.returncode != 0 or health.stdout.strip() == b"unhealthy":
                self.fail("PRIVATE_SERVICE_HEALTH_FAILED")
            time.sleep(1)
        else:
            self.fail("PRIVATE_SERVICE_HEALTH_FAILED")
        same = run_command([*self.docker, "exec", self.client_id, "pg_isready", "-h", SERVICE_NAME, "-p", "5432", "-U", "postgres"], timeout=10, env=self.private_env)
        if same.returncode != 0:
            self.fail("PRIVATE_INTERCONTAINER_FAILED")
        self.verify_container_contract()
        self.receipt["diagnostic.private_netns.network.same_network"] = True
        self.receipt["diagnostic.private_netns.network.container_count"] = 2
        self.verify_process_boundaries(before_containers=False)
        self.host_firewall_snapshot("containers_started")

    def verify_container_contract(self) -> None:
        inspected = run_command([*self.docker, "inspect", self.service_id, self.client_id], env=self.private_env)
        if inspected.returncode != 0:
            self.fail("PRIVATE_CONTAINER_CONTRACT_INVALID")
        try:
            values = json.loads(inspected.stdout.decode("utf-8", "strict"), object_pairs_hook=strict_object)
        except (UnicodeError, ValueError, json.JSONDecodeError):
            self.fail("PRIVATE_CONTAINER_CONTRACT_INVALID")
        if not isinstance(values, list) or len(values) != 2 or any(not isinstance(value, dict) for value in values):
            self.fail("PRIVATE_CONTAINER_CONTRACT_INVALID")
        expected_roles = {"private-netns-service", "private-netns-client"}
        observed_roles: set[str] = set()
        for value in values:
            config = value.get("Config")
            host = value.get("HostConfig")
            network_settings = value.get("NetworkSettings")
            if not all(isinstance(item, dict) for item in (config, host, network_settings)):
                self.fail("PRIVATE_CONTAINER_CONTRACT_INVALID")
            labels = config.get("Labels")
            networks = network_settings.get("Networks")
            if not isinstance(labels, dict) or not isinstance(networks, dict):
                self.fail("PRIVATE_CONTAINER_CONTRACT_INVALID")
            role = labels.get("io.fawxzzy.role")
            if labels.get("io.fawxzzy.packet") != self.args.packet or role not in expected_roles:
                self.fail("PRIVATE_CONTAINER_CONTRACT_INVALID")
            observed_roles.add(role)
            tmpfs = host.get("Tmpfs")
            if not isinstance(tmpfs, dict) or set(tmpfs) != {"/var/lib/postgresql/data"}:
                self.fail("PRIVATE_CONTAINER_CONTRACT_INVALID")
            tmpfs_options = tmpfs["/var/lib/postgresql/data"]
            if not isinstance(tmpfs_options, str) or set(tmpfs_options.split(",")) != {
                "rw", "nosuid", "nodev", "noexec", "size=64m" if role == "private-netns-client" else "size=512m"
            }:
                self.fail("PRIVATE_CONTAINER_CONTRACT_INVALID")
            if host.get("NetworkMode") != NETWORK_NAME or set(networks) != {NETWORK_NAME}:
                self.fail("PRIVATE_CONTAINER_CONTRACT_INVALID")
            if host.get("Privileged") is not False or host.get("PublishAllPorts") is not False:
                self.fail("PRIVATE_CONTAINER_CONTRACT_INVALID")
            if host.get("PidMode") not in {"", "private"} or host.get("IpcMode") not in {"", "private"}:
                self.fail("PRIVATE_CONTAINER_CONTRACT_INVALID")
            for field in ("Binds", "Mounts", "CapAdd", "Devices", "PortBindings"):
                if host.get(field) not in (None, [], {}):
                    self.fail("PRIVATE_CONTAINER_CONTRACT_INVALID")
            security_options = host.get("SecurityOpt")
            if not isinstance(security_options, list) or "no-new-privileges" not in security_options:
                self.fail("PRIVATE_CONTAINER_CONTRACT_INVALID")
            ports = network_settings.get("Ports")
            if not isinstance(ports, dict) or any(binding not in (None, []) for binding in ports.values()):
                self.fail("PRIVATE_CONTAINER_CONTRACT_INVALID")
            mounts = value.get("Mounts")
            if mounts not in (None, []):
                self.fail("PRIVATE_CONTAINER_CONTRACT_INVALID")
        if observed_roles != expected_roles:
            self.fail("PRIVATE_CONTAINER_CONTRACT_INVALID")
        network = run_command([*self.docker, "network", "inspect", NETWORK_NAME], env=self.private_env)
        if network.returncode != 0:
            self.fail("PRIVATE_CONTAINER_CONTRACT_INVALID")
        try:
            network_values = json.loads(network.stdout.decode("utf-8", "strict"), object_pairs_hook=strict_object)
        except (UnicodeError, ValueError, json.JSONDecodeError):
            self.fail("PRIVATE_CONTAINER_CONTRACT_INVALID")
        if not isinstance(network_values, list) or len(network_values) != 1 or not isinstance(network_values[0], dict):
            self.fail("PRIVATE_CONTAINER_CONTRACT_INVALID")
        item = network_values[0]
        options = item.get("Options")
        ipam = item.get("IPAM")
        containers = item.get("Containers")
        if (
            item.get("Driver") != "bridge"
            or item.get("Internal") is not True
            or item.get("EnableIPv6") is not False
            or not isinstance(options, dict)
            or options.get("com.docker.network.bridge.name") != BRIDGE_NAME
            or not isinstance(ipam, dict)
            or ipam.get("Config") != [{"Subnet": PRIVATE_SUBNET, "Gateway": PRIVATE_GATEWAY}]
            or not isinstance(containers, dict)
            or set(containers) != {self.service_id, self.client_id}
        ):
            self.fail("PRIVATE_CONTAINER_CONTRACT_INVALID")
        self.receipt["diagnostic.private_netns.network.exact_attachment"] = True
        self.receipt["diagnostic.private_netns.network.container_security"] = True

    def preflight_canary_tools(self) -> None:
        script = "for tool in timeout getent ip ping pg_isready; do command -v \"$tool\" >/dev/null || exit 127; done"
        try:
            result = run_command(
                [*self.docker, "exec", self.client_id, "bash", "-ceu", script],
                timeout=10,
                env=self.private_env,
            )
        except (OSError, subprocess.TimeoutExpired, ProbeFailure):
            self.fail("PRIVATE_CANARY_RUNTIME_FAILED")
        if result.returncode == 127:
            self.fail("PRIVATE_CANARY_TOOL_MISSING")
        if result.returncode != 0 or result.stdout or result.stderr:
            self.fail("PRIVATE_CANARY_RUNTIME_FAILED")
        try:
            internal_dns = run_command(
                [
                    *self.docker,
                    "exec",
                    self.client_id,
                    "bash",
                    "-ceu",
                    (
                        f"getent hosts {SERVICE_NAME} >/dev/null"
                        f" && timeout 3 bash -c '</dev/tcp/{SERVICE_NAME}/5432'"
                        f" && timeout 3 ping -c 1 -W 1 {SERVICE_NAME} >/dev/null"
                    ),
                ],
                timeout=10,
                env=self.private_env,
            )
        except (OSError, subprocess.TimeoutExpired, ProbeFailure):
            self.fail("PRIVATE_CANARY_RUNTIME_FAILED")
        if internal_dns.returncode != 0 or internal_dns.stdout or internal_dns.stderr:
            self.fail("PRIVATE_INTERCONTAINER_FAILED")

    def exec_network_denial(self, command: str, denied_codes: frozenset[int], reachable_code: str) -> None:
        script = (
            "printf 'FP_CANARY_ATTEMPTED\\n'; set +e; "
            f"{command} >/dev/null 2>&1; canary_rc=$?; set -e; "
            "printf 'FP_CANARY_RESULT:%s\\n' \"$canary_rc\""
        )
        try:
            result = run_command(
                [*self.docker, "exec", self.client_id, "bash", "-ceu", script],
                timeout=10,
                env=self.private_env,
            )
        except (OSError, subprocess.TimeoutExpired, ProbeFailure):
            self.fail("PRIVATE_CANARY_RUNTIME_FAILED")
        if result.returncode != 0 or result.stderr:
            self.fail("PRIVATE_CANARY_RUNTIME_FAILED")
        matched = re.fullmatch(rb"FP_CANARY_ATTEMPTED\nFP_CANARY_RESULT:([0-9]{1,3})\n", result.stdout)
        if matched is None:
            self.fail("PRIVATE_CANARY_EVIDENCE_INVALID")
        command_rc = int(matched.group(1))
        if command_rc == 0:
            self.fail(reachable_code)
        if command_rc not in denied_codes:
            self.fail("PRIVATE_CANARY_RUNTIME_FAILED")

    def run_network_canaries(self) -> None:
        self.preflight_canary_tools()
        try:
            route = run_command(
                [*self.docker, "exec", self.client_id, "bash", "-ceu", 'test -z "$(ip -4 route show default)"'],
                timeout=10,
                env=self.private_env,
            )
        except (OSError, subprocess.TimeoutExpired, ProbeFailure):
            self.fail("PRIVATE_CANARY_RUNTIME_FAILED")
        if route.returncode == 1 and not route.stdout and not route.stderr:
            self.fail("PRIVATE_DEFAULT_ROUTE_PRESENT")
        if route.returncode != 0 or route.stdout or route.stderr:
            self.fail("PRIVATE_CANARY_RUNTIME_FAILED")
        self.receipt["diagnostic.private_netns.isolation.no_default_route"] = True
        self.exec_network_denial(
            "timeout 5 getent ahostsv4 example.com",
            frozenset({2, 124}),
            "PRIVATE_EXTERNAL_DNS_SUCCEEDED",
        )
        self.receipt["diagnostic.private_netns.network.external_dns_failed"] = True
        self.exec_network_denial(
            "timeout 3 bash -c '</dev/tcp/1.1.1.1/443'",
            frozenset({1, 124}),
            "PRIVATE_LITERAL_IP_EGRESS_SUCCEEDED",
        )
        self.receipt["diagnostic.private_netns.network.literal_ip_failed"] = True
        self.exec_network_denial(
            "timeout 3 bash -c '</dev/tcp/169.254.169.254/80'",
            frozenset({1, 124}),
            "PRIVATE_METADATA_EGRESS_SUCCEEDED",
        )
        self.receipt["diagnostic.private_netns.network.metadata_failed"] = True
        self.exec_network_denial(
            f"timeout 3 ping -c 1 -W 1 {PRIVATE_GATEWAY}",
            frozenset({1, 124}),
            "PRIVATE_GATEWAY_REACHABLE",
        )
        self.receipt["diagnostic.private_netns.network.gateway_failed"] = True
        self.exec_network_denial(
            "timeout 5 bash -c '</dev/tcp/registry-1.docker.io/443'",
            frozenset({1, 124}),
            "PRIVATE_REGISTRY_ACCESS_SUCCEEDED",
        )
        self.receipt["diagnostic.private_netns.network.registry_failed"] = True

    def service_ip(self) -> str:
        inspected = run_command(
            [*self.docker, "inspect", "--format", f"{{{{(index .NetworkSettings.Networks \"{NETWORK_NAME}\").IPAddress}}}}", self.service_id],
            env=self.private_env,
        )
        if inspected.returncode != 0:
            self.fail("PRIVATE_LOOPBACK_PROXY_FAILED")
        value = inspected.stdout.decode("utf-8", "strict").strip()
        try:
            address = ipaddress.ip_address(value)
            network = ipaddress.ip_network(PRIVATE_SUBNET)
        except ValueError:
            self.fail("PRIVATE_LOOPBACK_PROXY_FAILED")
        if address not in network or address in {network.network_address, network.broadcast_address}:
            self.fail("PRIVATE_LOOPBACK_PROXY_FAILED")
        return value

    def host_nonloopback_addresses(self) -> list[str]:
        result = run_command(["ip", "-j", "address", "show"], env=self.private_env)
        if result.returncode != 0:
            self.fail("PRIVATE_NONLOOPBACK_REACHABLE")
        value = json.loads(result.stdout.decode("utf-8", "strict"), object_pairs_hook=strict_object)
        addresses: list[str] = []
        for interface in value:
            for info in interface.get("addr_info", []):
                if info.get("family") in {"inet", "inet6"} and info.get("scope") != "host":
                    address = info.get("local")
                    if isinstance(address, str) and not ipaddress.ip_address(address).is_loopback:
                        addresses.append(address)
        return addresses

    def verify_loopback_proxy(self) -> None:
        namespace_path = Path("/var/run/netns") / NS_NAME
        self.proxy = LoopbackProxy(namespace_path, self.service_ip(), 5432, self.args.listen_port)
        self.proxy.start()
        time.sleep(0.2)
        try:
            with socket.create_connection(("127.0.0.1", self.args.listen_port), timeout=3) as connection:
                connection.sendall(struct.pack("!II", 8, 80877103))
                response = connection.recv(1)
                if response not in {b"S", b"N"}:
                    self.fail("PRIVATE_LOOPBACK_PROXY_FAILED")
        except OSError:
            self.fail("PRIVATE_LOOPBACK_PROXY_FAILED")
        self.receipt["diagnostic.private_netns.network.loopback_proxy"] = True
        for address in self.host_nonloopback_addresses():
            try:
                connection = socket.create_connection((address, self.args.listen_port), timeout=0.3)
            except (OSError, RuntimeError):
                continue
            connection.close()
            self.fail("PRIVATE_NONLOOPBACK_REACHABLE")
        listeners = run_command(["ss", "-H", "-ltn", f"sport = :{self.args.listen_port}"], env=self.private_env)
        if listeners.returncode != 0:
            self.fail("PRIVATE_LOOPBACK_PROXY_FAILED")
        lines = [line for line in listeners.stdout.decode("utf-8", "strict").splitlines() if line.strip()]
        if len(lines) != 1 or "127.0.0.1:" not in lines[0] or "0.0.0.0:" in lines[0] or "[::]:" in lines[0]:
            self.fail("PRIVATE_LOOPBACK_PROXY_FAILED")
        self.receipt["diagnostic.private_netns.network.nonloopback_denied"] = True
        self.host_firewall_snapshot("canaries_complete")

    def execute(self) -> None:
        self.validate_arguments()
        self.prepare_host_image()
        self.create_cgroup()
        self.create_netns()
        self.start_daemons()
        self.load_image()
        self.create_private_network()
        self.start_containers()
        self.run_network_canaries()
        self.verify_loopback_proxy()

    def latch_private_docker_runtime_cleanup(self) -> None:
        self.private_docker_cleanup_latched = True

    def latch_private_docker_action(self, action: str) -> None:
        if action not in DOCKER_CLEANUP_ACTION_ORDER:
            self.fail("PROBE_INTERNAL_ERROR")
        self.private_docker_cleanup_latched = True
        self.private_docker_action_obligations.add(action)

    def synchronize_private_docker_cleanup_obligations(self) -> None:
        if (
            self.dockerd_process is not None
            or self.receipt["diagnostic.private_netns.isolation.private_dockerd_socket"] is True
            or self.private_image_id
            or self.service_id
            or self.client_id
            or self.receipt["diagnostic.private_netns.network.private_network_count"] > 0
        ):
            self.latch_private_docker_runtime_cleanup()
        if self.private_image_id:
            self.latch_private_docker_action("REMOVE_IMAGE")
        if (
            self.receipt["diagnostic.private_netns.network.private_network_count"] > 0
            or self.service_id
            or self.client_id
        ):
            self.latch_private_docker_action("REMOVE_NETWORK")
        if self.service_id:
            self.latch_private_docker_action("REMOVE_SERVICE")
        if self.client_id:
            self.latch_private_docker_action("REMOVE_CLIENT")

    def private_docker_action_command(self, action: str) -> list[str] | None:
        if action == "REMOVE_CLIENT" and self.client_id:
            return [*self.docker, "rm", "-f", self.client_id]
        if action == "REMOVE_SERVICE" and self.service_id:
            return [*self.docker, "rm", "-f", self.service_id]
        if action == "REMOVE_NETWORK":
            return [*self.docker, "network", "rm", NETWORK_NAME]
        if action == "REMOVE_IMAGE" and self.private_image_id:
            return [*self.docker, "image", "rm", "-f", self.private_image_id]
        return None

    def record_cleanup_failure(self, action: str) -> None:
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", action):
            action = "UNEXPECTED_CLEANUP"
        self.cleanup_failures.append(action)

    def cleanup_evidence_list(self, category: str, phase: str) -> list[str]:
        if category not in {"query", "action"} or phase not in {"required", "attempted", "succeeded"}:
            self.fail("PROBE_INTERNAL_ERROR")
        return getattr(self, f"cleanup_{category}_{phase}")

    def record_cleanup_evidence(self, category: str, phase: str, operation: str) -> None:
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", operation):
            self.fail("PROBE_INTERNAL_ERROR")
        ledger = self.cleanup_evidence_list(category, phase)
        if operation in ledger:
            self.fail("PROBE_INTERNAL_ERROR")
        ledger.append(operation)

    def record_unavailable_cleanup_obligation(self, category: str, operation: str) -> None:
        self.record_cleanup_evidence(category, "required", operation)
        self.record_cleanup_failure(operation)

    def cleanup_command(
        self,
        action: str,
        command: list[str],
        *,
        timeout: float = 10,
        category: str = "action",
    ) -> subprocess.CompletedProcess[bytes] | None:
        self.record_cleanup_evidence(category, "required", action)
        self.record_cleanup_evidence(category, "attempted", action)
        try:
            result = run_command(command, timeout=timeout, env=self.private_env)
        except (OSError, subprocess.TimeoutExpired, ProbeFailure):
            self.record_cleanup_failure(action)
            return None
        if result.returncode != 0:
            self.record_cleanup_failure(action)
            return None
        self.record_cleanup_evidence(category, "succeeded", action)
        return result

    def private_query_count(self, action: str, command: list[str]) -> int:
        result = self.cleanup_command(action, [*self.docker, *command], category="query")
        if result is None:
            return 1
        return len([line for line in result.stdout.splitlines() if line])

    def stop_process(self, action: str, process: subprocess.Popen[bytes] | None) -> bool:
        if process is None or process.poll() is not None:
            return True
        self.record_cleanup_evidence("action", "required", action)
        self.record_cleanup_evidence("action", "attempted", action)
        try:
            process.send_signal(signal.SIGTERM)
            process.wait(timeout=10)
            self.record_cleanup_evidence("action", "succeeded", action)
            return True
        except (OSError, subprocess.TimeoutExpired):
            self.record_cleanup_failure(action)
            try:
                process.kill()
                process.wait(timeout=5)
                return False
            except (OSError, subprocess.TimeoutExpired):
                return False

    def finalize_cleanup_failures(self) -> None:
        payload = ("\n".join(self.cleanup_failures) + ("\n" if self.cleanup_failures else "")).encode()
        self.receipt["diagnostic.private_netns.cleanup.command_failure_count"] = len(self.cleanup_failures)
        self.receipt["diagnostic.private_netns.cleanup.failure_manifest_sha256"] = sha256_bytes(payload)

    def finalize_cleanup_completeness(self) -> tuple[bool, bool]:
        prefix = "diagnostic.private_netns.cleanup."
        for category in ("query", "action"):
            required = self.cleanup_evidence_list(category, "required")
            attempted = self.cleanup_evidence_list(category, "attempted")
            succeeded = self.cleanup_evidence_list(category, "succeeded")
            if len(set(required)) != len(required) or len(set(attempted)) != len(attempted) or len(set(succeeded)) != len(succeeded):
                self.fail("PROBE_INTERNAL_ERROR")
            failure_count = len(attempted) - len(succeeded)
            complete = required == attempted and len(required) == len(succeeded) and failure_count == 0
            self.receipt[f"{prefix}{category}_required_count"] = len(required)
            self.receipt[f"{prefix}{category}_attempted_count"] = len(attempted)
            self.receipt[f"{prefix}{category}_succeeded_count"] = len(succeeded)
            self.receipt[f"{prefix}{category}_failure_count"] = failure_count
            self.receipt[f"{prefix}{category}_complete"] = complete
        self.receipt[f"{prefix}completeness_finalized"] = True
        return (
            self.receipt[f"{prefix}query_complete"],
            self.receipt[f"{prefix}action_complete"],
        )

    def cleanup(self) -> bool:
        self.receipt["diagnostic.private_netns.cleanup.attempted"] = True
        self.synchronize_private_docker_cleanup_obligations()
        cleanup_ok = True
        if self.proxy is not None:
            self.record_cleanup_evidence("action", "required", "STOP_PROXY")
            self.record_cleanup_evidence("action", "attempted", "STOP_PROXY")
            try:
                self.proxy.close()
                self.record_cleanup_evidence("action", "succeeded", "STOP_PROXY")
            except OSError:
                self.record_cleanup_failure("STOP_PROXY")
                cleanup_ok = False
            self.proxy = None
        docker_socket_available = (self.runtime / "docker.sock").is_socket()
        if self.private_docker_cleanup_latched:
            for action in DOCKER_CLEANUP_ACTION_ORDER:
                if action not in self.private_docker_action_obligations:
                    continue
                command = self.private_docker_action_command(action)
                if not docker_socket_available or command is None:
                    self.record_unavailable_cleanup_obligation("action", action)
                    cleanup_ok = False
                    continue
                timeout = 30 if action == "REMOVE_IMAGE" else 20
                if self.cleanup_command(action, command, timeout=timeout) is None:
                    cleanup_ok = False
            for action, receipt_name, command in DOCKER_CLEANUP_QUERY_SPECS:
                if not docker_socket_available:
                    self.record_unavailable_cleanup_obligation("query", action)
                    cleanup_ok = False
                    continue
                self.receipt[f"diagnostic.private_netns.cleanup.{receipt_name}"] = self.private_query_count(
                    action, list(command)
                )
        cleanup_ok = self.stop_process("STOP_DOCKERD", self.dockerd_process) and cleanup_ok
        cleanup_ok = self.stop_process("STOP_CONTAINERD", self.containerd_process) and cleanup_ok
        process_count = sum(1 for process in self.processes if process.poll() is None)
        self.receipt["diagnostic.private_netns.cleanup.processes_remaining"] = process_count
        cleanup_ok = cleanup_ok and process_count == 0
        if self.netns_created:
            removed = self.cleanup_command("DELETE_NETNS", ["ip", "netns", "delete", NS_NAME])
            cleanup_ok = cleanup_ok and removed is not None
        listed = self.cleanup_command("QUERY_NETNS", ["ip", "netns", "list"], category="query")
        namespace_count = 1 if listed is None or NS_NAME.encode() in listed.stdout else 0
        self.receipt["diagnostic.private_netns.cleanup.namespaces_remaining"] = namespace_count
        cleanup_ok = cleanup_ok and namespace_count == 0
        if self.cgroup_created:
            self.record_cleanup_evidence("action", "required", "REMOVE_CGROUP")
            self.record_cleanup_evidence("action", "attempted", "REMOVE_CGROUP")
            try:
                for directory in sorted(
                    (item for item in self.cgroup_path.rglob("*") if item.is_dir()),
                    key=lambda item: len(item.parts),
                    reverse=True,
                ):
                    directory.rmdir()
                self.cgroup_path.rmdir()
                self.record_cleanup_evidence("action", "succeeded", "REMOVE_CGROUP")
            except OSError:
                self.record_cleanup_failure("REMOVE_CGROUP")
                cleanup_ok = False
        cgroup_count = 1 if self.cgroup_path.exists() else 0
        self.receipt["diagnostic.private_netns.cleanup.cgroups_remaining"] = cgroup_count
        cleanup_ok = cleanup_ok and cgroup_count == 0
        runtime_present = self.runtime.exists() and not self.runtime.is_symlink()
        if runtime_present:
            self.record_cleanup_evidence("action", "required", "REMOVE_RUNTIME_ROOT")
            self.record_cleanup_evidence("action", "attempted", "REMOVE_RUNTIME_ROOT")
        try:
            if runtime_present:
                shutil.rmtree(self.runtime)
                self.record_cleanup_evidence("action", "succeeded", "REMOVE_RUNTIME_ROOT")
        except OSError:
            self.record_cleanup_failure("REMOVE_RUNTIME_ROOT")
            cleanup_ok = False
        root_count = 1 if os.path.lexists(self.runtime) else 0
        socket_paths = (self.runtime / "docker.sock", self.runtime / "containerd.sock")
        pid_paths = (self.runtime / "dockerd.pid", self.runtime / "containerd-state" / "containerd.pid")
        self.receipt["diagnostic.private_netns.cleanup.sockets_remaining"] = sum(os.path.lexists(path) for path in socket_paths)
        self.receipt["diagnostic.private_netns.cleanup.pidfiles_remaining"] = sum(os.path.lexists(path) for path in pid_paths)
        self.receipt["diagnostic.private_netns.cleanup.roots_remaining"] = root_count
        self.receipt["diagnostic.private_netns.cleanup.scratch_remaining"] = root_count
        cleanup_ok = cleanup_ok and root_count == 0
        self.record_cleanup_evidence("query", "required", "QUERY_LISTENER")
        self.record_cleanup_evidence("query", "attempted", "QUERY_LISTENER")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.settimeout(0.2)
                listener.bind(("127.0.0.1", self.args.listen_port))
            listener_count = 0
        except OSError:
            listener_count = 1
        self.record_cleanup_evidence("query", "succeeded", "QUERY_LISTENER")
        self.receipt["diagnostic.private_netns.cleanup.listeners_remaining"] = listener_count
        cleanup_ok = cleanup_ok and listener_count == 0
        self.record_cleanup_evidence("query", "required", "QUERY_HOST_FIREWALL")
        self.record_cleanup_evidence("query", "attempted", "QUERY_HOST_FIREWALL")
        try:
            final_firewall = self.host_firewall_snapshot("final")
            self.record_cleanup_evidence("query", "succeeded", "QUERY_HOST_FIREWALL")
        except (OSError, ProbeFailure, subprocess.TimeoutExpired):
            self.record_cleanup_failure("QUERY_HOST_FIREWALL")
            final_firewall = (ZERO_SHA256, ZERO_SHA256, {})
            cleanup_ok = False
        self.record_cleanup_evidence("query", "required", "QUERY_HOST_LINKS")
        self.record_cleanup_evidence("query", "attempted", "QUERY_HOST_LINKS")
        try:
            final_links = self.host_links()
            self.record_cleanup_evidence("query", "succeeded", "QUERY_HOST_LINKS")
        except (OSError, ProbeFailure, subprocess.TimeoutExpired):
            self.record_cleanup_failure("QUERY_HOST_LINKS")
            final_links = ZERO_SHA256
            cleanup_ok = False
        self.receipt["diagnostic.private_netns.host_firewall.observation_count"] = len(self.host_firewall_phases)
        self.receipt["diagnostic.private_netns.host_firewall.final_sha256"] = final_firewall[0]
        self.receipt["diagnostic.private_netns.host_firewall.final_semantic_sha256"] = final_firewall[1]
        canonical_restored = self.host_firewall_pre is not None and final_firewall[0] == self.host_firewall_pre[0] and final_firewall[2] == self.host_firewall_pre[2]
        semantic_restored = self.host_firewall_pre is not None and final_firewall[1] == self.host_firewall_pre[1]
        self.receipt["diagnostic.private_netns.host_firewall.canonical_restored"] = canonical_restored
        self.receipt["diagnostic.private_netns.host_firewall.semantic_restored"] = semantic_restored
        phase_payload = "\n".join(f"{phase}:{canonical}:{semantic}" for phase, canonical, semantic in self.host_firewall_phases) + "\n"
        self.receipt["diagnostic.private_netns.host_firewall.phase_manifest_sha256"] = sha256_bytes(phase_payload.encode())
        self.receipt["diagnostic.private_netns.host_links.final_sha256"] = final_links
        links_restored = final_links == self.host_link_pre != ZERO_SHA256
        self.receipt["diagnostic.private_netns.host_links.restored"] = links_restored
        self.receipt["diagnostic.private_netns.host_links.veth_created"] = False
        self.receipt["diagnostic.private_netns.cleanup.veths_remaining"] = 0 if links_restored and namespace_count == 0 else 1
        self.finalize_cleanup_failures()
        query_complete, action_complete = self.finalize_cleanup_completeness()
        residue_is_zero = all(
            self.receipt[key] == 0
            for key in (
                "diagnostic.private_netns.cleanup.containers_remaining",
                "diagnostic.private_netns.cleanup.images_remaining",
                "diagnostic.private_netns.cleanup.volumes_remaining",
                "diagnostic.private_netns.cleanup.networks_remaining",
                "diagnostic.private_netns.cleanup.listeners_remaining",
                "diagnostic.private_netns.cleanup.processes_remaining",
                "diagnostic.private_netns.cleanup.namespaces_remaining",
                "diagnostic.private_netns.cleanup.veths_remaining",
                "diagnostic.private_netns.cleanup.sockets_remaining",
                "diagnostic.private_netns.cleanup.pidfiles_remaining",
                "diagnostic.private_netns.cleanup.cgroups_remaining",
                "diagnostic.private_netns.cleanup.roots_remaining",
                "diagnostic.private_netns.cleanup.scratch_remaining",
            )
        )
        cleanup_ok = (
            cleanup_ok
            and canonical_restored
            and semantic_restored
            and links_restored
            and residue_is_zero
            and not self.cleanup_failures
            and query_complete
            and action_complete
        )
        self.receipt["diagnostic.private_netns.cleanup.proof_complete"] = cleanup_ok
        self.receipt["diagnostic.private_netns.cleanup.succeeded"] = cleanup_ok
        return cleanup_ok


def run_probe(args: argparse.Namespace) -> int:
    probe = Probe(args)
    failure_code = "PASS"
    try:
        probe.execute()
    except ProbeFailure as exc:
        failure_code = exc.code
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError, subprocess.TimeoutExpired):
        failure_code = "PROBE_INTERNAL_ERROR"
    try:
        cleanup_ok = probe.cleanup()
    except Exception:
        probe.record_cleanup_failure("UNEXPECTED_CLEANUP")
        probe.finalize_cleanup_failures()
        probe.receipt["diagnostic.private_netns.cleanup.attempted"] = True
        probe.receipt["diagnostic.private_netns.cleanup.succeeded"] = False
        cleanup_ok = False
    cleanup_telemetry_complete = all(
        probe.receipt[key] is True
        for key in (
            "diagnostic.private_netns.cleanup.completeness_finalized",
            "diagnostic.private_netns.cleanup.query_complete",
            "diagnostic.private_netns.cleanup.action_complete",
            "diagnostic.private_netns.cleanup.proof_complete",
        )
    )
    if cleanup_ok and not cleanup_telemetry_complete:
        cleanup_ok = False
        probe.receipt["diagnostic.private_netns.cleanup.succeeded"] = False
        probe.receipt["diagnostic.private_netns.cleanup.proof_complete"] = False
    if not cleanup_ok and failure_code == "PASS":
        failure_code = "PRIVATE_CLEANUP_FAILED"
    if failure_code == "PASS":
        required_bools = (
            "diagnostic.private_netns.host_image.identity_match",
            "diagnostic.private_netns.isolation.daemon_namespace_match",
            "diagnostic.private_netns.isolation.containerd_namespace_match",
            "diagnostic.private_netns.isolation.shim_namespace_match",
            "diagnostic.private_netns.isolation.containers_namespace_isolated",
            "diagnostic.private_netns.isolation.cgroup_owned",
            "diagnostic.private_netns.isolation.private_firewall_present",
            "diagnostic.private_netns.network.same_network",
            "diagnostic.private_netns.network.exact_attachment",
            "diagnostic.private_netns.network.container_security",
            "diagnostic.private_netns.network.external_dns_failed",
            "diagnostic.private_netns.network.literal_ip_failed",
            "diagnostic.private_netns.network.metadata_failed",
            "diagnostic.private_netns.network.gateway_failed",
            "diagnostic.private_netns.network.registry_failed",
            "diagnostic.private_netns.network.loopback_proxy",
            "diagnostic.private_netns.network.nonloopback_denied",
            "diagnostic.private_netns.host_firewall.canonical_restored",
            "diagnostic.private_netns.host_firewall.semantic_restored",
            "diagnostic.private_netns.host_links.restored",
            "diagnostic.private_netns.cleanup.succeeded",
        )
        if not all(probe.receipt[key] is True for key in required_bools):
            failure_code = "PRIVATE_RESIDUE"
    probe.receipt["diagnostic.private_netns.failure_code"] = failure_code
    probe.receipt["diagnostic.private_netns.classification"] = PASS_CLASS if failure_code == "PASS" else REJECT_CLASS
    finalize_receipt(probe.receipt)
    try:
        sys.stdout.write(format_receipt(probe.receipt))
    except (ValueError, OSError):
        return 2
    return 0 if failure_code == "PASS" else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    probe_parser = subparsers.add_parser("probe")
    probe_parser.add_argument("--workspace-root", type=Path, required=True)
    probe_parser.add_argument("--runtime", type=Path, required=True)
    probe_parser.add_argument("--image", required=True)
    probe_parser.add_argument("--expected-image-id", required=True)
    probe_parser.add_argument("--packet", required=True)
    probe_parser.add_argument("--runner-uid", type=int, required=True)
    probe_parser.add_argument("--listen-port", type=int, default=56422)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "validate":
        try:
            parse_receipt(args.input.read_bytes())
        except (OSError, UnicodeError, ValueError):
            return 1
        return 0
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.:/@-]{1,255}", args.image):
        return 2
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.expected_image_id):
        return 2
    if not re.fullmatch(r"FP-[A-Z0-9-]+", args.packet) or not 1024 <= args.listen_port <= 65535:
        return 2
    return run_probe(args)


if __name__ == "__main__":
    sys.exit(main())
