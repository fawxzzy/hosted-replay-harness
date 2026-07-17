#!/usr/bin/env python3
"""Observe and fail closed on Supabase CLI container creation.

The Docker inspection template deliberately excludes Config.Env so local-only
credentials and connection material are never read or written by this harness.
"""

from __future__ import annotations

import argparse
import json
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


def _empty(value: Any) -> bool:
    return value in (None, [], {})


def _only_network(data: dict[str, Any], network_id: str) -> bool:
    networks = data.get("networks") or {}
    return len(networks) == 1 and next(iter(networks.values())).get("NetworkID") == network_id


def _has_socket_mount(data: dict[str, Any]) -> bool:
    values: list[str] = []
    values.extend(str(item) for item in (data.get("binds") or []))
    for mount in data.get("mounts") or []:
        values.extend([str(mount.get("Source", "")), str(mount.get("Destination", ""))])
    return any("docker.sock" in value for value in values)


def _actual_db_binding(data: dict[str, Any]) -> bool:
    ports = data.get("published_ports") or {}
    bindings = ports.get("5432/tcp")
    return bindings == [{"HostIp": "127.0.0.1", "HostPort": DB_PORT}]


def _has_published_binding(data: dict[str, Any]) -> bool:
    ports = data.get("published_ports") or {}
    return any(bool(bindings) for bindings in ports.values())


def classify_and_validate(
    data: dict[str, Any], network_id: str, postgres_image_id: str, gotrue_image_id: str
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

    if data.get("network_mode") != network_id or not _only_network(data, network_id):
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
        if not _actual_db_binding(data):
            violations.append("DATABASE_PORT_BINDING_MISMATCH")
        if (data.get("restart_policy") or {}).get("Name") != "unless-stopped":
            violations.append("DATABASE_RESTART_POLICY_MISMATCH")
    elif role == "gotrue_migration":
        if not _empty(data.get("binds")) or not _empty(data.get("mounts")):
            violations.append("GOTRUE_MOUNT_REJECTED")
        if not _empty(data.get("port_bindings")) or _has_published_binding(data):
            violations.append("GOTRUE_PORT_REJECTED")
        if (data.get("restart_policy") or {}).get("Name") not in (None, "", "no"):
            violations.append("GOTRUE_RESTART_POLICY_MISMATCH")

    return role, sorted(set(violations))


def safe_inspect(container_id: str) -> dict[str, Any] | None:
    for _ in range(30):
        result = subprocess.run(
            ["docker", "inspect", "--format", INSPECT_TEMPLATE, container_id],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
        time.sleep(0.05)
    return None


def append_json(path: Path, payload: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
        handle.flush()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--network-id", required=True)
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

    command = [
        "docker",
        "events",
        "--filter",
        "type=container",
        "--filter",
        "event=start",
        "--filter",
        f"label=com.supabase.cli.project={PROJECT}",
        "--format",
        "{{.ID}}",
    ]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    args.ready_file.write_text("ready\n", encoding="utf-8")

    assert process.stdout is not None
    try:
        while running:
            line = process.stdout.readline()
            if not line:
                if process.poll() is not None:
                    break
                time.sleep(0.05)
                continue
            container_id = line.strip()
            data = safe_inspect(container_id)
            if data is None:
                payload = {
                    "container_id": container_id[:12],
                    "compliant": False,
                    "role": "unobserved",
                    "violations": ["CONTAINER_INSPECTION_MISSED"],
                }
                append_json(args.audit_file, payload)
                append_json(args.violation_file, payload)
                continue

            role, violations = classify_and_validate(
                data, args.network_id, args.postgres_image_id, args.gotrue_image_id
            )
            networks = data.get("networks") or {}
            observed_network_ids = sorted(
                item.get("NetworkID", "") for item in networks.values() if item.get("NetworkID")
            )
            payload = {
                "container_id": str(data.get("id", ""))[:12],
                "role": role,
                "image_id": data.get("image_id"),
                "command": data.get("cmd") or [],
                "network_ids": observed_network_ids,
                "published_db_binding": "127.0.0.1:56422" if _actual_db_binding(data) else None,
                "compliant": not violations,
                "violations": violations,
            }
            append_json(args.audit_file, payload)
            if violations:
                append_json(args.violation_file, payload)
                subprocess.run(
                    ["docker", "stop", "--time", "0", container_id],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
    finally:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
