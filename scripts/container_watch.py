#!/usr/bin/env python3
"""Observe and fail closed on Supabase CLI container lifecycle events.

The Docker inspection templates deliberately exclude Config.Env so local-only
credentials and connection material are never read or written by this harness.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


PROJECT = "fp-hosted-replay-ro-001"
DB_NAME = f"supabase_db_{PROJECT}"
DB_VOLUME = DB_NAME
DB_PORT = "56422"
DB_DESTINATION = "/var/lib/postgresql/data"
PROJECT_LABELS = {
    "com.supabase.cli.project": PROJECT,
    "com.docker.compose.project": PROJECT,
}
EXPECTED_EXTRA_HOSTS = ["host.docker.internal:host-gateway"]

ALLOWED_VIOLATIONS = frozenset(
    {
        "ADDED_CAPABILITY_REJECTED",
        "CONTAINER_INSPECTION_MISSED",
        "DATABASE_BIND_MISMATCH",
        "DATABASE_MOUNT_MISMATCH",
        "DATABASE_PORT_BINDING_MISMATCH",
        "DATABASE_PORT_REQUEST_MISMATCH",
        "DATABASE_RESTART_POLICY_MISMATCH",
        "DEVICE_ACCESS_REJECTED",
        "DOCKER_SOCKET_REJECTED",
        "EXTRA_HOST_CONTRACT_MISMATCH",
        "GOTRUE_MOUNT_REJECTED",
        "GOTRUE_PORT_REJECTED",
        "GOTRUE_RESTART_POLICY_MISMATCH",
        "IPC_MODE_REJECTED",
        "NETWORK_ATTACHMENT_MISMATCH",
        "NETWORK_DRIVER_MISMATCH",
        "NETWORK_GATEWAY_MODE_MISMATCH",
        "NETWORK_HOST_BINDING_MISMATCH",
        "NETWORK_IPV6_ENABLED",
        "NETWORK_LABEL_MISMATCH",
        "NETWORK_NAME_ID_MAPPING_FAILED",
        "NETWORK_NOT_INTERNAL",
        "NETWORK_SCOPE_MISMATCH",
        "NETWORK_SUBNET_MISMATCH",
        "OBSERVER_FAILURE_UNCLASSIFIED",
        "PACKET_LABEL_MISMATCH",
        "PID_MODE_REJECTED",
        "PRIVILEGED_MODE_REJECTED",
        "SECOND_PACKET_NETWORK_DETECTED",
        "SECURITY_OPTION_REJECTED",
        "UNEXPECTED_PACKET_CONTAINER",
    }
)

INSPECT_TEMPLATE = json.dumps(
    {
        "id": "{{.Id}}",
        "name": "{{.Name}}",
        "image_id": "{{.Image}}",
        "config_image": "__CONFIG_IMAGE__",
        "cmd": "__CMD__",
        "labels": "__LABELS__",
        "network_mode": "__NETWORK_MODE__",
        "privileged": "__PRIVILEGED__",
        "pid_mode": "__PID_MODE__",
        "ipc_mode": "__IPC_MODE__",
        "binds": "__BINDS__",
        "devices": "__DEVICES__",
        "device_requests": "__DEVICE_REQUESTS__",
        "cap_add": "__CAP_ADD__",
        "security_opt": "__SECURITY_OPT__",
        "extra_hosts": "__EXTRA_HOSTS__",
        "port_bindings": "__PORT_BINDINGS__",
        "restart_policy": "__RESTART_POLICY__",
        "mounts": "__MOUNTS__",
        "networks": "__NETWORKS__",
        "published_ports": "__PUBLISHED_PORTS__",
    },
    separators=(",", ":"),
)

for placeholder, expression in {
    '"__CONFIG_IMAGE__"': "{{json .Config.Image}}",
    '"__CMD__"': "{{json .Config.Cmd}}",
    '"__LABELS__"': "{{json .Config.Labels}}",
    '"__NETWORK_MODE__"': "{{json .HostConfig.NetworkMode}}",
    '"__PRIVILEGED__"': "{{json .HostConfig.Privileged}}",
    '"__PID_MODE__"': "{{json .HostConfig.PidMode}}",
    '"__IPC_MODE__"': "{{json .HostConfig.IpcMode}}",
    '"__BINDS__"': "{{json .HostConfig.Binds}}",
    '"__DEVICES__"': "{{json .HostConfig.Devices}}",
    '"__DEVICE_REQUESTS__"': "{{json .HostConfig.DeviceRequests}}",
    '"__CAP_ADD__"': "{{json .HostConfig.CapAdd}}",
    '"__SECURITY_OPT__"': "{{json .HostConfig.SecurityOpt}}",
    '"__EXTRA_HOSTS__"': "{{json .HostConfig.ExtraHosts}}",
    '"__PORT_BINDINGS__"': "{{json .HostConfig.PortBindings}}",
    '"__RESTART_POLICY__"': "{{json .HostConfig.RestartPolicy}}",
    '"__MOUNTS__"': "{{json .Mounts}}",
    '"__NETWORKS__"': "{{json .NetworkSettings.Networks}}",
    '"__PUBLISHED_PORTS__"': "{{json .NetworkSettings.Ports}}",
}.items():
    INSPECT_TEMPLATE = INSPECT_TEMPLATE.replace(placeholder, expression)


def identity_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _empty(value: Any) -> bool:
    return value in (None, [], {})


def _only_network(data: dict[str, Any], network_id: str) -> bool:
    networks = data.get("networks") or {}
    return (
        isinstance(networks, dict)
        and len(networks) == 1
        and next(iter(networks.values())).get("NetworkID") == network_id
    )


def _has_socket_mount(data: dict[str, Any]) -> bool:
    values: list[str] = []
    values.extend(str(item) for item in (data.get("binds") or []))
    for mount in data.get("mounts") or []:
        if isinstance(mount, dict):
            values.extend([str(mount.get("Source", "")), str(mount.get("Destination", ""))])
    return any("docker.sock" in value for value in values)


def _actual_db_binding(data: dict[str, Any]) -> bool:
    ports = data.get("published_ports") or {}
    bindings = ports.get("5432/tcp") if isinstance(ports, dict) else None
    return bindings == [{"HostIp": "127.0.0.1", "HostPort": DB_PORT}]


def _has_published_binding(data: dict[str, Any]) -> bool:
    ports = data.get("published_ports") or {}
    return isinstance(ports, dict) and any(bool(bindings) for bindings in ports.values())


def classify_and_validate(
    data: dict[str, Any],
    phase: str,
    network_name: str,
    network_id: str,
    postgres_image_id: str,
    gotrue_image_id: str,
) -> tuple[str, list[str]]:
    """Return a sanitized role and stable violation codes."""

    violations: list[str] = []
    name = str(data.get("name", "")).lstrip("/")
    image_id = data.get("image_id")
    cmd = data.get("cmd") or []

    if name == DB_NAME and image_id == postgres_image_id:
        role = "database"
    elif image_id == gotrue_image_id and cmd == ["gotrue", "migrate"]:
        role = "gotrue_migration"
    else:
        role = "unexpected"
        violations.append("UNEXPECTED_PACKET_CONTAINER")

    labels = data.get("labels") or {}
    for key, value in PROJECT_LABELS.items():
        if labels.get(key) != value:
            violations.append("PACKET_LABEL_MISMATCH")

    if data.get("network_mode") != network_name or not _only_network(data, network_id):
        violations.append("NETWORK_ATTACHMENT_MISMATCH")
    if data.get("privileged") is not False:
        violations.append("PRIVILEGED_MODE_REJECTED")
    if data.get("pid_mode") not in (None, "", "private"):
        violations.append("PID_MODE_REJECTED")
    if data.get("ipc_mode") not in (None, "", "private"):
        violations.append("IPC_MODE_REJECTED")
    if not _empty(data.get("devices")) or not _empty(data.get("device_requests")):
        violations.append("DEVICE_ACCESS_REJECTED")
    if not _empty(data.get("cap_add")):
        violations.append("ADDED_CAPABILITY_REJECTED")
    if not _empty(data.get("security_opt")):
        violations.append("SECURITY_OPTION_REJECTED")
    if _has_socket_mount(data):
        violations.append("DOCKER_SOCKET_REJECTED")
    if (data.get("extra_hosts") or []) != EXPECTED_EXTRA_HOSTS:
        violations.append("EXTRA_HOST_CONTRACT_MISMATCH")

    if role == "database":
        expected_bind = f"{DB_VOLUME}:{DB_DESTINATION}"
        if (data.get("binds") or []) != [expected_bind]:
            violations.append("DATABASE_BIND_MISMATCH")
        mounts = data.get("mounts") or []
        if not (
            len(mounts) == 1
            and isinstance(mounts[0], dict)
            and mounts[0].get("Type") == "volume"
            and mounts[0].get("Name") == DB_VOLUME
            and mounts[0].get("Destination") == DB_DESTINATION
            and mounts[0].get("RW") is True
        ):
            violations.append("DATABASE_MOUNT_MISMATCH")
        requested = (data.get("port_bindings") or {}).get("5432/tcp")
        if requested not in (
            [{"HostIp": "", "HostPort": DB_PORT}],
            [{"HostIp": "127.0.0.1", "HostPort": DB_PORT}],
        ):
            violations.append("DATABASE_PORT_REQUEST_MISMATCH")
        if phase == "start" and not _actual_db_binding(data):
            violations.append("DATABASE_PORT_BINDING_MISMATCH")
        if (data.get("restart_policy") or {}).get("Name") != "unless-stopped":
            violations.append("DATABASE_RESTART_POLICY_MISMATCH")
    elif role == "gotrue_migration":
        if not _empty(data.get("binds")) or not _empty(data.get("mounts")):
            violations.append("GOTRUE_MOUNT_REJECTED")
        if not _empty(data.get("port_bindings")) or (
            phase == "start" and _has_published_binding(data)
        ):
            violations.append("GOTRUE_PORT_REJECTED")
        if (data.get("restart_policy") or {}).get("Name") not in (None, "", "no"):
            violations.append("GOTRUE_RESTART_POLICY_MISMATCH")

    return role, sorted(set(violations))


def validate_network_contract(
    data: dict[str, Any],
    resolved_ids: list[str],
    correlated_ids: list[str],
    network_name: str,
    network_id: str,
    network_subnet: str,
    packet: str,
) -> list[str]:
    """Validate only allowlisted, non-secret Docker network metadata."""

    violations: list[str] = []
    if sorted(set(resolved_ids)) != [network_id]:
        violations.append("NETWORK_NAME_ID_MAPPING_FAILED")
    if sorted(set(correlated_ids)) != [network_id]:
        violations.append("SECOND_PACKET_NETWORK_DETECTED")
    if data.get("id") != network_id or data.get("name") != network_name:
        violations.append("NETWORK_NAME_ID_MAPPING_FAILED")
    if data.get("driver") != "bridge":
        violations.append("NETWORK_DRIVER_MISMATCH")
    if data.get("scope") != "local":
        violations.append("NETWORK_SCOPE_MISMATCH")
    if data.get("internal") is not True:
        violations.append("NETWORK_NOT_INTERNAL")
    if data.get("enable_ipv6") is not False:
        violations.append("NETWORK_IPV6_ENABLED")
    if data.get("subnet") != network_subnet:
        violations.append("NETWORK_SUBNET_MISMATCH")
    options = data.get("options") or {}
    if not isinstance(options, dict):
        options = {}
    if options.get("com.docker.network.bridge.host_binding_ipv4") != "127.0.0.1":
        violations.append("NETWORK_HOST_BINDING_MISMATCH")
    if options.get("com.docker.network.bridge.gateway_mode_ipv4") != "isolated":
        violations.append("NETWORK_GATEWAY_MODE_MISMATCH")
    labels = data.get("labels") or {}
    if not isinstance(labels, dict):
        labels = {}
    expected_labels = {
        "io.fawxzzy.packet": packet,
        "io.fawxzzy.role": "containment-network",
        "com.supabase.cli.project": PROJECT,
        "com.docker.compose.project": PROJECT,
    }
    if any(labels.get(key) != value for key, value in expected_labels.items()):
        violations.append("NETWORK_LABEL_MISMATCH")
    return sorted(set(violations))


def _run_lines(command: list[str]) -> tuple[int, list[str]]:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    return result.returncode, [line for line in result.stdout.splitlines() if line]


def inspect_live_network(
    network_name: str, network_id: str, network_subnet: str, packet: str
) -> list[str]:
    name_rc, resolved_ids = _run_lines(
        [
            "docker",
            "network",
            "ls",
            "--no-trunc",
            "--filter",
            f"name=^{network_name}$",
            "--format",
            "{{.ID}}",
        ]
    )
    packet_rc, packet_ids = _run_lines(
        [
            "docker",
            "network",
            "ls",
            "--no-trunc",
            "--filter",
            f"label=io.fawxzzy.packet={packet}",
            "--format",
            "{{.ID}}",
        ]
    )
    project_rc, project_ids = _run_lines(
        [
            "docker",
            "network",
            "ls",
            "--no-trunc",
            "--filter",
            f"label=com.supabase.cli.project={PROJECT}",
            "--format",
            "{{.ID}}",
        ]
    )
    if name_rc != 0:
        return ["NETWORK_NAME_ID_MAPPING_FAILED"]
    if packet_rc != 0 or project_rc != 0:
        return ["SECOND_PACKET_NETWORK_DETECTED"]

    template = json.dumps(
        {
            "id": "{{.Id}}",
            "name": "{{.Name}}",
            "driver": "{{.Driver}}",
            "scope": "{{.Scope}}",
            "internal": "__INTERNAL__",
            "enable_ipv6": "__ENABLE_IPV6__",
            "subnet": "{{(index .IPAM.Config 0).Subnet}}",
            "options": "__OPTIONS__",
            "labels": "__LABELS__",
        },
        separators=(",", ":"),
    )
    template = template.replace('"__INTERNAL__"', "{{json .Internal}}")
    template = template.replace('"__ENABLE_IPV6__"', "{{json .EnableIPv6}}")
    template = template.replace('"__OPTIONS__"', "{{json .Options}}")
    template = template.replace('"__LABELS__"', "{{json .Labels}}")
    inspected = subprocess.run(
        ["docker", "network", "inspect", "--format", template, network_name],
        capture_output=True,
        text=True,
        check=False,
    )
    if inspected.returncode != 0:
        return ["NETWORK_NAME_ID_MAPPING_FAILED"]
    try:
        data = json.loads(inspected.stdout)
    except (json.JSONDecodeError, TypeError):
        return ["NETWORK_NAME_ID_MAPPING_FAILED"]
    correlated_ids = sorted(set(packet_ids + project_ids))
    return validate_network_contract(
        data,
        resolved_ids,
        correlated_ids,
        network_name,
        network_id,
        network_subnet,
        packet,
    )


def safe_inspect(container_id: str) -> dict[str, Any] | None:
    for _ in range(30):
        result = subprocess.run(
            ["docker", "inspect", "--format", INSPECT_TEMPLATE, container_id],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            try:
                return json.loads(result.stdout)
            except (json.JSONDecodeError, TypeError):
                return None
        time.sleep(0.05)
    return None


def append_json(path: Path, payload: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
        handle.flush()


def _network_failure_payload(violations: list[str]) -> dict[str, Any]:
    safe = sorted(set(violations) & ALLOWED_VIOLATIONS)
    if not safe:
        safe = ["OBSERVER_FAILURE_UNCLASSIFIED"]
    return {
        "phase": "network_contract",
        "container_id": None,
        "role": "network_contract",
        "image_id": None,
        "command": [],
        "network_ids": [],
        "published_db_binding": None,
        "compliant": False,
        "violations": safe,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--network-id", required=True)
    parser.add_argument("--network-name", required=True)
    parser.add_argument("--network-subnet", required=True)
    parser.add_argument("--packet", required=True)
    parser.add_argument("--postgres-image-id", required=True)
    parser.add_argument("--gotrue-image-id", required=True)
    parser.add_argument("--audit-file", required=True, type=Path)
    parser.add_argument("--violation-file", required=True, type=Path)
    parser.add_argument("--ready-file", required=True, type=Path)
    args = parser.parse_args()

    running = True

    def stop(_signum: int, _frame: Any) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    initial_network_violations = inspect_live_network(
        args.network_name, args.network_id, args.network_subnet, args.packet
    )
    if initial_network_violations:
        payload = _network_failure_payload(initial_network_violations)
        append_json(args.audit_file, payload)
        append_json(args.violation_file, payload)
        return 1

    command = [
        "docker",
        "events",
        "--filter",
        "type=container",
        "--filter",
        "event=create",
        "--filter",
        "event=start",
        "--filter",
        f"label=com.supabase.cli.project={PROJECT}",
        "--format",
        "{{.Action}}\t{{.ID}}",
    ]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    args.ready_file.write_text("ready\n", encoding="utf-8")

    assert process.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    next_network_check = time.monotonic() + 1.0
    try:
        while running:
            if time.monotonic() >= next_network_check:
                network_violations = inspect_live_network(
                    args.network_name, args.network_id, args.network_subnet, args.packet
                )
                if network_violations:
                    payload = _network_failure_payload(network_violations)
                    append_json(args.audit_file, payload)
                    append_json(args.violation_file, payload)
                    return 1
                next_network_check = time.monotonic() + 1.0

            events = selector.select(timeout=0.25)
            if not events:
                if process.poll() is not None:
                    break
                continue
            line = process.stdout.readline()
            if not line:
                if process.poll() is not None:
                    break
                continue
            parts = line.rstrip("\n").split("\t", 1)
            if len(parts) != 2 or parts[0] not in ("create", "start"):
                payload = _network_failure_payload(["OBSERVER_FAILURE_UNCLASSIFIED"])
                append_json(args.audit_file, payload)
                append_json(args.violation_file, payload)
                return 1
            phase, container_id = parts
            network_violations = inspect_live_network(
                args.network_name, args.network_id, args.network_subnet, args.packet
            )
            data = safe_inspect(container_id)
            if data is None:
                payload = {
                    "phase": phase,
                    "container_id": identity_digest(container_id),
                    "image_id": None,
                    "command": [],
                    "network_ids": [],
                    "published_db_binding": None,
                    "compliant": False,
                    "role": "unobserved",
                    "violations": ["CONTAINER_INSPECTION_MISSED"],
                }
            else:
                role, violations = classify_and_validate(
                    data,
                    phase,
                    args.network_name,
                    args.network_id,
                    args.postgres_image_id,
                    args.gotrue_image_id,
                )
                violations = sorted(set(violations + network_violations))
                if any(code not in ALLOWED_VIOLATIONS for code in violations):
                    violations = ["OBSERVER_FAILURE_UNCLASSIFIED"]
                networks = data.get("networks") or {}
                if not isinstance(networks, dict):
                    networks = {}
                observed_network_ids = sorted(
                    identity_digest(item.get("NetworkID", ""))
                    for item in networks.values()
                    if item.get("NetworkID")
                )
                payload = {
                    "phase": phase,
                    "container_id": identity_digest(str(data.get("id", ""))),
                    "role": role,
                    "image_id": data.get("image_id"),
                    "command": [],
                    "network_ids": observed_network_ids,
                    "published_db_binding": (
                        "127.0.0.1:56422" if phase == "start" and _actual_db_binding(data) else None
                    ),
                    "compliant": not violations,
                    "violations": violations,
                }
            append_json(args.audit_file, payload)
            if not payload["compliant"]:
                append_json(args.violation_file, payload)
                action = "rm" if phase == "create" else "stop"
                command = ["docker", action]
                if action == "rm":
                    command.append("-f")
                else:
                    command.extend(["--time", "0"])
                command.append(container_id)
                subprocess.run(
                    command,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                return 1
    finally:
        selector.close()
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
