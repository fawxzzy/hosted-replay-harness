#!/usr/bin/env python3
"""Validate the direct Docker/Postgres port path without reading container env.

The Docker template is deliberately allowlisted. In particular, Config.Env is
never requested, retained, printed, or written to the diagnostic receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import socket
import subprocess
import sys
import time
from typing import Any


SCHEMA_VERSION = 1
PACKET = "FP-HOSTED-REPLAY-DIRECT-PORT-DIAG-001"
PROJECT = "fp-hosted-replay-ro-001"
ROLE = "direct-postgres"
CONTAINER_NAME = f"{PROJECT}-direct-postgres"
DB_PORT = "56422"
DB_DESTINATION = "/var/lib/postgresql/data"
DB_CONTAINER_PORT = "5432/tcp"
LEGACY_TMPFS_BASE_OPTIONS = frozenset({"rw", "nosuid", "nodev", "noexec"})
EXPECTED_LABELS = {
    "io.fawxzzy.packet": PACKET,
    "io.fawxzzy.role": ROLE,
    "com.supabase.cli.project": PROJECT,
    "com.docker.compose.project": PROJECT,
}


def _template() -> str:
    template = json.dumps(
        {
            "schema_version": SCHEMA_VERSION,
            "id": "{{.Id}}",
            "name": "{{.Name}}",
            "image_id": "{{.Image}}",
            "config_image": "__CONFIG_IMAGE__",
            "labels": "__LABELS__",
            "network_mode": "__NETWORK_MODE__",
            "privileged": "__PRIVILEGED__",
            "pid_mode": "__PID_MODE__",
            "ipc_mode": "__IPC_MODE__",
            "binds": "__BINDS__",
            "host_mounts": "__HOST_MOUNTS__",
            "volumes_from": "__VOLUMES_FROM__",
            "tmpfs": "__TMPFS__",
            "devices": "__DEVICES__",
            "device_requests": "__DEVICE_REQUESTS__",
            "cap_add": "__CAP_ADD__",
            "security_opt": "__SECURITY_OPT__",
            "extra_hosts": "__EXTRA_HOSTS__",
            "config_exposed_ports": "__CONFIG_EXPOSED_PORTS__",
            "port_bindings": "__PORT_BINDINGS__",
            "publish_all_ports": "__PUBLISH_ALL_PORTS__",
            "restart_policy": "__RESTART_POLICY__",
            "mounts": "__MOUNTS__",
            "networks": "__NETWORKS__",
            "published_ports": "__PUBLISHED_PORTS__",
            "restart_count": "__RESTART_COUNT__",
            "state": {
                "Status": "__STATE_STATUS__",
                "Running": "__STATE_RUNNING__",
                "Restarting": "__STATE_RESTARTING__",
                "OOMKilled": "__STATE_OOM_KILLED__",
            },
            "health": {
                "Status": "__HEALTH_STATUS__",
                "FailingStreak": "__HEALTH_FAILING_STREAK__",
            },
        },
        separators=(",", ":"),
    )
    replacements = {
        '"__CONFIG_IMAGE__"': "{{json .Config.Image}}",
        '"__LABELS__"': "{{json .Config.Labels}}",
        '"__NETWORK_MODE__"': "{{json .HostConfig.NetworkMode}}",
        '"__PRIVILEGED__"': "{{json .HostConfig.Privileged}}",
        '"__PID_MODE__"': "{{json .HostConfig.PidMode}}",
        '"__IPC_MODE__"': "{{json .HostConfig.IpcMode}}",
        '"__BINDS__"': "{{json .HostConfig.Binds}}",
        '"__HOST_MOUNTS__"': "{{json .HostConfig.Mounts}}",
        '"__VOLUMES_FROM__"': "{{json .HostConfig.VolumesFrom}}",
        '"__TMPFS__"': "{{json .HostConfig.Tmpfs}}",
        '"__DEVICES__"': "{{json .HostConfig.Devices}}",
        '"__DEVICE_REQUESTS__"': "{{json .HostConfig.DeviceRequests}}",
        '"__CAP_ADD__"': "{{json .HostConfig.CapAdd}}",
        '"__SECURITY_OPT__"': "{{json .HostConfig.SecurityOpt}}",
        '"__EXTRA_HOSTS__"': "{{json .HostConfig.ExtraHosts}}",
        '"__CONFIG_EXPOSED_PORTS__"': "{{json .Config.ExposedPorts}}",
        '"__PORT_BINDINGS__"': "{{json .HostConfig.PortBindings}}",
        '"__PUBLISH_ALL_PORTS__"': "{{json .HostConfig.PublishAllPorts}}",
        '"__RESTART_POLICY__"': "{{json .HostConfig.RestartPolicy}}",
        '"__MOUNTS__"': "{{json .Mounts}}",
        '"__NETWORKS__"': "{{json .NetworkSettings.Networks}}",
        '"__PUBLISHED_PORTS__"': "{{json .NetworkSettings.Ports}}",
        '"__RESTART_COUNT__"': "{{json .RestartCount}}",
        '"__STATE_STATUS__"': "{{json .State.Status}}",
        '"__STATE_RUNNING__"': "{{json .State.Running}}",
        '"__STATE_RESTARTING__"': "{{json .State.Restarting}}",
        '"__STATE_OOM_KILLED__"': "{{json .State.OOMKilled}}",
        '"__HEALTH_STATUS__"': "{{json .State.Health.Status}}",
        '"__HEALTH_FAILING_STREAK__"': "{{json .State.Health.FailingStreak}}",
    }
    for placeholder, expression in replacements.items():
        template = template.replace(placeholder, expression)
    return template


INSPECT_TEMPLATE = _template()


def _publication_template() -> str:
    template = json.dumps(
        {
            "schema_version": SCHEMA_VERSION,
            "config": {"exposed_ports": "__CONFIG_EXPOSED_PORTS__"},
            "host_config": {
                "port_bindings": "__PORT_BINDINGS__",
                "publish_all_ports": "__PUBLISH_ALL_PORTS__",
            },
            "network_settings": {"ports": "__PUBLISHED_PORTS__"},
        },
        separators=(",", ":"),
    )
    replacements = {
        '"__CONFIG_EXPOSED_PORTS__"': "{{json .Config.ExposedPorts}}",
        '"__PORT_BINDINGS__"': "{{json .HostConfig.PortBindings}}",
        '"__PUBLISH_ALL_PORTS__"': "{{json .HostConfig.PublishAllPorts}}",
        '"__PUBLISHED_PORTS__"': "{{json .NetworkSettings.Ports}}",
    }
    for placeholder, expression in replacements.items():
        template = template.replace(placeholder, expression)
    return template


PUBLICATION_INSPECT_TEMPLATE = _publication_template()
PUBLICATION_VALUE_CLASSES = frozenset(
    {"ABSENT", "NULL", "EMPTY_LIST", "NONEMPTY_LIST", "WRONG_TYPE"}
)


def identity_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _empty(value: Any) -> bool:
    return value in (None, [], {})


def legacy_tmpfs_matches(value: Any, expected_size: str) -> bool:
    """Validate Docker's legacy --tmpfs HostConfig representation exactly."""

    if not isinstance(value, dict) or set(value) != {DB_DESTINATION}:
        return False
    raw_options = value.get(DB_DESTINATION)
    if not isinstance(raw_options, str):
        return False
    options = raw_options.split(",")
    if not options or any(not option for option in options):
        return False
    if len(options) != len(set(options)):
        return False
    return set(options) == LEGACY_TMPFS_BASE_OPTIONS | {f"size={expected_size}"}


class DuplicateJsonKeyError(ValueError):
    """Raised when an inspected JSON object contains an ambiguous duplicate key."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError(key)
        result[key] = value
    return result


def strict_json_object(raw: bytes | str) -> dict[str, Any]:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="strict")
    value = json.loads(raw, object_pairs_hook=_strict_object)
    if not isinstance(value, dict):
        raise ValueError("top-level JSON value is not an object")
    return value


def _valid_port_key(value: Any) -> bool:
    if not isinstance(value, str) or "/" not in value:
        return False
    port, protocol = value.rsplit("/", 1)
    return (
        port.isascii()
        and port.isdigit()
        and 1 <= int(port) <= 65535
        and protocol in {"tcp", "udp", "sctp"}
    )


def _exposed_port_summary(value: Any) -> tuple[dict[str, int | bool], bool]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        return {}, False
    for key, marker in value.items():
        if not _valid_port_key(key) or marker not in (None, {}):
            return {}, False
    return {
        "config_exposed_ports_key_count": len(value),
        "config_exposed_ports_5432_present": DB_CONTAINER_PORT in value,
    }, True


def _binding_map_summary(
    value: Any,
) -> tuple[dict[str, int | bool], dict[str, tuple[tuple[str, str], ...]], bool]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        return {}, {}, False
    signatures: dict[str, tuple[tuple[str, str], ...]] = {}
    total = 0
    for key, bindings in value.items():
        if not _valid_port_key(key):
            return {}, {}, False
        if bindings is None:
            signatures[key] = ()
            continue
        if not isinstance(bindings, list):
            return {}, {}, False
        normalized: list[tuple[str, str]] = []
        for binding in bindings:
            if not isinstance(binding, dict) or set(binding) != {"HostIp", "HostPort"}:
                return {}, {}, False
            host_ip = binding.get("HostIp")
            host_port = binding.get("HostPort")
            if not isinstance(host_ip, str) or not isinstance(host_port, str):
                return {}, {}, False
            normalized.append((host_ip, host_port))
        signatures[key] = tuple(normalized)
        total += len(normalized)
    db_bindings = signatures.get(DB_CONTAINER_PORT, ())
    return {
        "key_count": len(value),
        "port_5432_present": DB_CONTAINER_PORT in value,
        "port_5432_binding_count": len(db_bindings),
        "total_binding_count": total,
    }, signatures, True


def _network_5432_value_class(value: Any) -> str:
    if not isinstance(value, dict):
        return "WRONG_TYPE"
    if DB_CONTAINER_PORT not in value:
        return "ABSENT"
    bindings = value[DB_CONTAINER_PORT]
    if bindings is None:
        return "NULL"
    if not isinstance(bindings, list):
        return "WRONG_TYPE"
    return "EMPTY_LIST" if not bindings else "NONEMPTY_LIST"


def _publication_digest(summary: dict[str, Any]) -> str:
    canonical = json.dumps(summary, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def classify_unpublished_publication_shape(
    data: dict[str, Any], *, subject: str = "FIREWALL_CLIENT"
) -> dict[str, Any]:
    """Classify every Docker publication surface without retaining binding values."""

    schema_failure = f"{subject}_PUBLICATION_SCHEMA_REJECTED"
    expected_top = {"schema_version", "config", "host_config", "network_settings"}
    if set(data) != expected_top or data.get("schema_version") != SCHEMA_VERSION:
        return {"class": schema_failure}
    config = data.get("config")
    host_config = data.get("host_config")
    network_settings = data.get("network_settings")
    if (
        not isinstance(config, dict)
        or set(config) != {"exposed_ports"}
        or not isinstance(host_config, dict)
        or set(host_config) != {"port_bindings", "publish_all_ports"}
        or not isinstance(network_settings, dict)
        or set(network_settings) != {"ports"}
    ):
        return {"class": schema_failure}

    exposed, exposed_valid = _exposed_port_summary(config["exposed_ports"])
    requested, request_signatures, requested_valid = _binding_map_summary(
        host_config["port_bindings"]
    )
    published_value = network_settings["ports"]
    value_class = _network_5432_value_class(published_value)
    published, published_signatures, published_valid = _binding_map_summary(
        published_value
    )
    publish_all = host_config["publish_all_ports"]
    if (
        not exposed_valid
        or not requested_valid
        or not published_valid
        or not isinstance(publish_all, bool)
        or value_class not in PUBLICATION_VALUE_CLASSES
        or value_class == "WRONG_TYPE"
    ):
        return {"class": schema_failure, "network_ports_5432_value_class": value_class}

    summary: dict[str, Any] = {
        **exposed,
        "host_port_bindings_key_count": requested["key_count"],
        "host_port_bindings_5432_present": requested["port_5432_present"],
        "host_port_bindings_5432_binding_count": requested[
            "port_5432_binding_count"
        ],
        "host_port_bindings_total_binding_count": requested[
            "total_binding_count"
        ],
        "host_publish_all_ports": publish_all,
        "network_ports_key_count": published["key_count"],
        "network_ports_5432_value_class": value_class,
        "network_ports_5432_binding_count": published["port_5432_binding_count"],
        "network_ports_total_binding_count": published["total_binding_count"],
    }
    summary["digest"] = _publication_digest(summary)

    requested_nonempty = {
        key: tuple(sorted(host_port for _, host_port in bindings))
        for key, bindings in request_signatures.items()
        if bindings
    }
    published_nonempty = {
        key: tuple(sorted(host_port for _, host_port in bindings))
        for key, bindings in published_signatures.items()
        if bindings
    }
    if (
        requested_nonempty
        and published_nonempty
        and requested_nonempty != published_nonempty
    ):
        classification = schema_failure
    elif publish_all or requested_nonempty:
        classification = f"{subject}_PUBLICATION_REQUEST_REJECTED"
    elif published_nonempty:
        classification = f"{subject}_PUBLICATION_RUNTIME_REJECTED"
    else:
        classification = f"{subject}_PUBLICATION_SHAPE_SAFE"
    return {"class": classification, **summary}


def _contains_docker_socket(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            _contains_docker_socket(key) or _contains_docker_socket(item)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_docker_socket(item) for item in value)
    return isinstance(value, str) and "docker.sock" in value


def validate_inspection(
    data: dict[str, Any],
    network_id: str,
    image_id: str,
    image_reference: str,
    *,
    container_name: str = CONTAINER_NAME,
    expected_labels: dict[str, str] | None = None,
) -> list[str]:
    """Return stable, sorted violation codes for an allowlisted inspection."""

    if data.get("schema_version") != SCHEMA_VERSION:
        return ["DIRECT_INSPECTION_SCHEMA_INVALID"]

    violations: list[str] = []
    if str(data.get("name", "")).lstrip("/") != container_name:
        violations.append("DIRECT_CONTAINER_IDENTITY_MISMATCH")
    if data.get("image_id") != image_id or data.get("config_image") != image_reference:
        violations.append("DIRECT_IMAGE_IDENTITY_MISMATCH")

    labels = data.get("labels")
    required_labels = EXPECTED_LABELS if expected_labels is None else expected_labels
    if not isinstance(labels, dict) or any(labels.get(key) != value for key, value in required_labels.items()):
        violations.append("DIRECT_LABEL_CONTRACT_MISMATCH")

    networks = data.get("networks")
    if not isinstance(networks, dict) or len(networks) != 1:
        violations.append("DIRECT_NETWORK_ATTACHMENT_MISMATCH")
    else:
        observed = next(iter(networks.values()))
        if not isinstance(observed, dict) or observed.get("NetworkID") != network_id:
            violations.append("DIRECT_NETWORK_ATTACHMENT_MISMATCH")
    if data.get("network_mode") != network_id:
        violations.append("DIRECT_NETWORK_MODE_MISMATCH")

    if data.get("privileged") is not False:
        violations.append("DIRECT_PRIVILEGED_MODE_REJECTED")
    if data.get("pid_mode") not in (None, "", "private"):
        violations.append("DIRECT_PID_MODE_REJECTED")
    if data.get("ipc_mode") not in (None, "", "private"):
        violations.append("DIRECT_IPC_MODE_REJECTED")
    if not _empty(data.get("devices")) or not _empty(data.get("device_requests")):
        violations.append("DIRECT_DEVICE_ACCESS_REJECTED")
    if not _empty(data.get("cap_add")):
        violations.append("DIRECT_ADDED_CAPABILITY_REJECTED")
    if not _empty(data.get("security_opt")):
        violations.append("DIRECT_SECURITY_OPTION_REJECTED")
    if not _empty(data.get("extra_hosts")):
        violations.append("DIRECT_EXTRA_HOST_REJECTED")
    binds = data.get("binds")
    host_mounts = data.get("host_mounts")
    volumes_from = data.get("volumes_from")
    mounts = data.get("mounts")
    if not _empty(binds):
        violations.append("DIRECT_BIND_MOUNT_REJECTED")
    if not _empty(host_mounts) or not _empty(volumes_from) or not _empty(mounts):
        violations.append("DIRECT_MOUNT_CONTRACT_MISMATCH")
    if any(
        _contains_docker_socket(value)
        for value in (binds, host_mounts, volumes_from, mounts)
    ):
        violations.append("DIRECT_DOCKER_SOCKET_REJECTED")

    tmpfs = data.get("tmpfs")
    if not legacy_tmpfs_matches(tmpfs, "1g"):
        violations.append("DIRECT_TMPFS_CONTRACT_MISMATCH")

    publication = classify_unpublished_publication_shape(
        {
            "schema_version": SCHEMA_VERSION,
            "config": {"exposed_ports": data.get("config_exposed_ports")},
            "host_config": {
                "port_bindings": data.get("port_bindings"),
                "publish_all_ports": data.get("publish_all_ports"),
            },
            "network_settings": {"ports": data.get("published_ports")},
        },
        subject="DIRECT",
    )
    if publication.get("class") == "DIRECT_PUBLICATION_SCHEMA_REJECTED":
        violations.append("DIRECT_PUBLICATION_SCHEMA_INVALID")
    if data.get("publish_all_ports") is not False:
        violations.append("DIRECT_PUBLISH_ALL_PORTS_REJECTED")
    requested = data.get("port_bindings")
    if requested != {DB_CONTAINER_PORT: [{"HostIp": "", "HostPort": DB_PORT}]}:
        violations.append("DIRECT_PORT_REQUEST_MISMATCH")
    published = data.get("published_ports")
    if published != {
        DB_CONTAINER_PORT: [{"HostIp": "127.0.0.1", "HostPort": DB_PORT}]
    }:
        violations.append("DIRECT_PORT_BINDING_MISMATCH")
    restart_policy = data.get("restart_policy")
    if not isinstance(restart_policy, dict) or restart_policy.get("Name") not in (None, "", "no"):
        violations.append("DIRECT_RESTART_POLICY_MISMATCH")

    state = data.get("state")
    health = data.get("health")
    if not isinstance(state, dict) or not isinstance(health, dict):
        violations.append("DIRECT_HEALTH_SCHEMA_INVALID")
    else:
        if state.get("Running") is not True or state.get("Status") != "running":
            violations.append("DIRECT_CONTAINER_NOT_RUNNING")
        if state.get("Restarting") is not False:
            violations.append("DIRECT_CONTAINER_RESTARTING")
        if state.get("OOMKilled") is not False:
            violations.append("DIRECT_CONTAINER_OOM_KILLED")
        if health.get("Status") != "healthy" or health.get("FailingStreak") != 0:
            violations.append("DIRECT_CONTAINER_NOT_HEALTHY")
    if data.get("restart_count") != 0:
        violations.append("DIRECT_RESTART_COUNT_NONZERO")

    return sorted(set(violations))


def safe_inspect(container_id: str) -> dict[str, Any] | None:
    completed = subprocess.run(
        ["docker", "inspect", "--format", INSPECT_TEMPLATE, container_id],
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        return None
    try:
        payload = strict_json_object(completed.stdout)
    except (DuplicateJsonKeyError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return None
    return payload


def global_ip_addresses() -> list[str]:
    completed = subprocess.run(
        ["ip", "-j", "addr", "show", "scope", "global"],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        return []
    try:
        interfaces = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return []
    addresses: set[str] = set()
    for interface in interfaces if isinstance(interfaces, list) else []:
        if not isinstance(interface, dict):
            continue
        for item in interface.get("addr_info", []):
            if not isinstance(item, dict):
                continue
            candidate = item.get("local")
            try:
                parsed = ipaddress.ip_address(candidate)
            except (TypeError, ValueError):
                continue
            if not (
                parsed.is_loopback or parsed.is_link_local or parsed.is_unspecified
            ):
                addresses.add(str(parsed))
    return sorted(addresses)


def global_ipv4_addresses() -> list[str]:
    return [
        address
        for address in global_ip_addresses()
        if isinstance(ipaddress.ip_address(address), ipaddress.IPv4Address)
    ]


def tcp_connects(host: str, port: int, timeout_seconds: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds):
            return True
    except OSError:
        return False


def state_line(key: str, kind: str, value: Any) -> str:
    rendered = str(value).lower() if isinstance(value, bool) else str(value)
    rendered = rendered.replace("\t", " ").replace("\r", " ").replace("\n", " ")
    return f"{key}\t{kind}\t{rendered}"


def inspect_unpublished_publication(
    container_id: str, subject: str
) -> dict[str, Any]:
    completed = subprocess.run(
        ["docker", "inspect", "--format", PUBLICATION_INSPECT_TEMPLATE, container_id],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if completed.returncode != 0:
        return {"class": f"{subject}_PUBLICATION_INSPECT_FAILED"}
    try:
        payload = strict_json_object(completed.stdout)
    except (
        DuplicateJsonKeyError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ):
        return {"class": f"{subject}_PUBLICATION_PARSE_FAILED"}
    return classify_unpublished_publication_shape(payload, subject=subject)


def publication_state_lines(prefix: str, result: dict[str, Any]) -> list[str]:
    allowed = {
        "class": "str",
        "config_exposed_ports_key_count": "int",
        "config_exposed_ports_5432_present": "bool",
        "host_port_bindings_key_count": "int",
        "host_port_bindings_5432_present": "bool",
        "host_port_bindings_5432_binding_count": "int",
        "host_port_bindings_total_binding_count": "int",
        "host_publish_all_ports": "bool",
        "network_ports_key_count": "int",
        "network_ports_5432_value_class": "str",
        "network_ports_5432_binding_count": "int",
        "network_ports_total_binding_count": "int",
        "digest": "str",
    }
    if set(result) - set(allowed):
        raise ValueError("publication result contains an unallowlisted key")
    classes = {
        f"{subject}_PUBLICATION_{suffix}"
        for subject in ("FIREWALL_CLIENT", "FOREIGN_CANARY")
        for suffix in (
            "SHAPE_SAFE",
            "REQUEST_REJECTED",
            "RUNTIME_REJECTED",
            "SCHEMA_REJECTED",
            "INSPECT_FAILED",
            "PARSE_FAILED",
        )
    }
    classification = result.get("class")
    if classification not in classes:
        raise ValueError("publication result contains an invalid class")
    for key, value in result.items():
        kind = allowed[key]
        if kind == "bool" and not isinstance(value, bool):
            raise ValueError("publication boolean field has an invalid type")
        if kind == "int" and (
            isinstance(value, bool) or not isinstance(value, int) or value < 0
        ):
            raise ValueError("publication integer field has an invalid type")
        if kind == "str" and not isinstance(value, str):
            raise ValueError("publication string field has an invalid type")
    if "network_ports_5432_value_class" in result and result[
        "network_ports_5432_value_class"
    ] not in PUBLICATION_VALUE_CLASSES:
        raise ValueError("publication value class is not allowlisted")
    if "digest" in result and (
        len(result["digest"]) != 64
        or any(character not in "0123456789abcdef" for character in result["digest"])
    ):
        raise ValueError("publication digest is invalid")
    return [
        state_line(f"diagnostic.publication.{prefix}.{key}", allowed[key], result[key])
        for key in allowed
        if key in result
    ]


def publication_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--container-id", required=True)
    parser.add_argument(
        "--subject", required=True, choices=("FIREWALL_CLIENT", "FOREIGN_CANARY")
    )
    parser.add_argument(
        "--receipt-prefix",
        required=True,
        choices=("firewall_client", "foreign_canary"),
    )
    args = parser.parse_args(argv)
    expected_prefix = {
        "FIREWALL_CLIENT": "firewall_client",
        "FOREIGN_CANARY": "foreign_canary",
    }[args.subject]
    if args.receipt_prefix != expected_prefix:
        return 1
    result = inspect_unpublished_publication(args.container_id, args.subject)
    for line in publication_state_lines(args.receipt_prefix, result):
        print(line)
    return 0 if result.get("class") == f"{args.subject}_PUBLICATION_SHAPE_SAFE" else 1


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "validate-unpublished":
        return publication_main(sys.argv[2:])
    parser = argparse.ArgumentParser()
    parser.add_argument("--container-id", required=True)
    parser.add_argument("--network-id", required=True)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--image-reference", required=True)
    parser.add_argument("--packet", default=PACKET)
    parser.add_argument("--role", default=ROLE)
    parser.add_argument("--container-name", default=CONTAINER_NAME)
    parser.add_argument("--health-timeout-seconds", type=int, default=120)
    parser.add_argument("--stable-seconds", type=int, default=10)
    args = parser.parse_args()

    started = time.monotonic()
    deadline = started + args.health_timeout_seconds
    healthy_since: float | None = None
    final_data: dict[str, Any] | None = None
    failure_code = "DIRECT_HEALTH_TIMEOUT"

    while time.monotonic() < deadline:
        observed = safe_inspect(args.container_id)
        if observed is None:
            failure_code = "DIRECT_INSPECTION_FAILED"
            break
        if observed.get("schema_version") != SCHEMA_VERSION:
            failure_code = "DIRECT_INSPECTION_SCHEMA_INVALID"
            break
        state = observed.get("state") or {}
        health = observed.get("health") or {}
        if state.get("OOMKilled") is True:
            failure_code = "DIRECT_CONTAINER_OOM_KILLED"
            break
        if observed.get("restart_count") not in (0, None):
            failure_code = "DIRECT_RESTART_COUNT_NONZERO"
            break
        if state.get("Running") is not True or state.get("Status") != "running":
            failure_code = "DIRECT_CONTAINER_NOT_RUNNING"
            break
        if health.get("Status") == "healthy" and health.get("FailingStreak") == 0:
            healthy_since = healthy_since or time.monotonic()
            if time.monotonic() - healthy_since >= args.stable_seconds:
                final_data = observed
                break
        else:
            healthy_since = None
        time.sleep(1)

    if final_data is None:
        print(state_line("diagnostic.probe.failure_code", "str", failure_code))
        return 1

    expected_labels = {
        "io.fawxzzy.packet": args.packet,
        "io.fawxzzy.role": args.role,
        "com.supabase.cli.project": PROJECT,
        "com.docker.compose.project": PROJECT,
    }
    violations = validate_inspection(
        final_data,
        args.network_id,
        args.image_id,
        args.image_reference,
        container_name=args.container_name,
        expected_labels=expected_labels,
    )
    if violations:
        print(state_line("diagnostic.probe.failure_code", "str", violations[0]))
        print(state_line("diagnostic.probe.violation_count", "int", len(violations)))
        return 1

    if not tcp_connects("127.0.0.1", int(DB_PORT)):
        print(state_line("diagnostic.probe.failure_code", "str", "DIRECT_LOOPBACK_CONNECT_FAILED"))
        return 1

    host_addresses = global_ip_addresses()
    nonloopback_successes = sum(tcp_connects(address, int(DB_PORT)) for address in host_addresses)
    if nonloopback_successes:
        print(state_line("diagnostic.probe.failure_code", "str", "DIRECT_NONLOOPBACK_CONNECT_SUCCEEDED"))
        print(state_line("diagnostic.binding.nonloopback_tested_count", "int", len(host_addresses)))
        print(state_line("diagnostic.binding.nonloopback_success_count", "int", nonloopback_successes))
        return 1

    elapsed = time.monotonic() - started
    print(state_line("diagnostic.identity.image", "str", identity_digest(args.image_id)))
    print(state_line("diagnostic.identity.network", "str", identity_digest(args.network_id)))
    print(state_line("diagnostic.identity.container", "str", identity_digest(args.container_id)))
    print(state_line("diagnostic.binding.class", "str", "loopback-ipv4-only"))
    print(state_line("diagnostic.binding.host_port", "int", int(DB_PORT)))
    print(state_line("diagnostic.binding.loopback_connect", "bool", True))
    print(state_line("diagnostic.binding.nonloopback_tested_count", "int", len(host_addresses)))
    print(state_line("diagnostic.binding.nonloopback_success_count", "int", 0))
    print(state_line("diagnostic.health.status", "str", "healthy"))
    print(state_line("diagnostic.health.restart_count", "int", 0))
    print(state_line("diagnostic.health.oom_killed", "bool", False))
    print(state_line("diagnostic.health.stable_seconds", "int", args.stable_seconds))
    print(state_line("diagnostic.timing.probe_seconds", "float", f"{elapsed:.3f}"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
