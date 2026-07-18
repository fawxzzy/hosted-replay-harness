#!/usr/bin/env python3
"""Transparent Unix-socket relay with a closed, sanitized Docker API receipt."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import signal
from collections import Counter, deque
from pathlib import Path
from typing import Final, Iterable, NamedTuple
from urllib.parse import parse_qs, unquote, urlsplit


SCHEMA: Final = "fawxzzy.hosted-replay-harness.docker-api-boundary.v2"
POLICY_SCHEMA: Final = "fawxzzy.hosted-replay-harness.db-start-policy.v1"
POLICY_MATRIX_SHA256: Final = "9669ebd4ae75cfdc3950c9db8b2786270023ce0e26dde993806b3f7b6b2c5492"
PHASES: Final = (
    "API_NEGOTIATION",
    "IMAGE_INSPECT",
    "IMAGE_PULL",
    "NETWORK_INSPECT_REUSE",
    "VOLUME_INSPECT",
    "VOLUME_CREATE",
    "CONTAINER_INSPECT",
    "CONTAINER_LIST",
    "CONTAINER_CREATE",
    "CONTAINER_START",
    "CONTAINER_LOGS",
    "CONTAINER_REMOVE",
    "CLEANUP_API_PHASE",
    "UNKNOWN_API_PHASE",
)
METHOD_CLASSES: Final = ("READ", "WRITE", "DELETE", "OTHER")
STATUS_CLASSES: Final = ("1XX", "2XX", "3XX", "4XX", "5XX", "OTHER")
STATUS_CODES: Final = (200, 201, 204, 304, 400, 401, 403, 404, 405, 409, 422, 429, 500, 502, 503)
CLASSIFICATIONS: Final = (
    "NO_DOCKER_API_REQUEST_OBSERVED",
    "DOCKER_API_REQUESTS_OBSERVED",
    "DOCKER_API_ERROR_RESPONSE_OBSERVED",
    "DOCKER_API_RESPONSE_INCOMPLETE",
    "DOCKER_API_WRITE_ATTEMPT_OBSERVED",
    "OBSERVER_FORWARDING_FAILED",
    "DB_START_POLICY_COMPLETE",
    "DB_START_POLICY_INCOMPLETE",
    "DB_START_POLICY_VIOLATION",
)
POLICY_MODES: Final = ("READ_ONLY", "DB_START_V1")
POLICY_FAILURE_CODES: Final = (
    "NONE",
    "POLICY_DESCRIPTOR_INVALID",
    "POLICY_LEDGER_LOST",
    "POLICY_CONCURRENT_REQUEST",
    "POLICY_API_VERSION_REJECTED",
    "POLICY_OPERATION_REJECTED",
    "POLICY_ORDER_REJECTED",
    "POLICY_QUERY_REJECTED",
    "POLICY_MEDIA_TYPE_REJECTED",
    "POLICY_FRAMING_REJECTED",
    "POLICY_BODY_OVERSIZED",
    "POLICY_BODY_REJECTED",
    "POLICY_IDENTITY_REJECTED",
    "POLICY_STATUS_REJECTED",
    "POLICY_RESPONSE_REJECTED",
    "POLICY_STREAM_REJECTED",
)
API_PREFIX = re.compile(br"^/v[0-9]+(?:\.[0-9]+)?(?=/|$)")
MAX_LINE: Final = 16384
MAX_HEADERS: Final = 65536
MAX_CONTROL_RESPONSE: Final = 4 * 1024 * 1024
MAX_STREAM_RESPONSE: Final = 8 * 1024 * 1024
ZERO_SHA256: Final = "0" * 64


class WriteAttemptError(Exception):
    """Stop a prohibited non-read-only request before it reaches Docker."""


class PolicyViolation(Exception):
    """Reject a request or response at the closed DB-start policy boundary."""

    def __init__(self, code: str) -> None:
        if code not in POLICY_FAILURE_CODES or code == "NONE":
            code = "POLICY_OPERATION_REJECTED"
        self.code = code
        super().__init__(code)


def method_class(method: bytes) -> str:
    if method in (b"GET", b"HEAD"):
        return "READ"
    if method in (b"POST", b"PUT", b"PATCH"):
        return "WRITE"
    if method == b"DELETE":
        return "DELETE"
    return "OTHER"


def normalize_path(target: bytes) -> bytes:
    path = target.split(b"?", 1)[0]
    return API_PREFIX.sub(b"", path, count=1) or b"/"


def classify_path(method: bytes, target: bytes) -> str:
    path = normalize_path(target)
    if path in (b"/_ping", b"/version", b"/info"):
        return "API_NEGOTIATION"
    if path == b"/images/create":
        return "IMAGE_PULL"
    if path.startswith(b"/images/") and path.endswith(b"/json"):
        return "IMAGE_INSPECT"
    if path == b"/networks/create" or path.startswith(b"/networks/"):
        return "NETWORK_INSPECT_REUSE"
    if path == b"/volumes/create":
        return "VOLUME_CREATE"
    if path.startswith(b"/volumes/"):
        return "VOLUME_INSPECT"
    if path == b"/containers/create":
        return "CONTAINER_CREATE"
    if path == b"/containers/json":
        return "CONTAINER_LIST"
    if path.startswith(b"/containers/") and path.endswith(b"/start"):
        return "CONTAINER_START"
    if path.startswith(b"/containers/") and path.endswith(b"/logs"):
        return "CONTAINER_LOGS"
    if method == b"DELETE" and path.startswith(b"/containers/"):
        return "CONTAINER_REMOVE"
    if path.startswith(b"/containers/") and path.endswith(b"/json"):
        return "CONTAINER_INSPECT"
    if path in (b"/containers/prune", b"/volumes/prune", b"/networks/prune"):
        return "CLEANUP_API_PHASE"
    return "UNKNOWN_API_PHASE"


class PolicyDecision(NamedTuple):
    name: str
    phase: str
    method: bytes
    expected_statuses: tuple[int, ...]
    stream: bool = False


def _closed_json(raw: bytes, maximum: int) -> dict[str, object]:
    if len(raw) > maximum:
        raise PolicyViolation("POLICY_BODY_OVERSIZED")

    def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise PolicyViolation("POLICY_BODY_REJECTED")
            value[key] = item
        return value

    def no_constants(_: str) -> object:
        raise PolicyViolation("POLICY_BODY_REJECTED")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=no_duplicates,
            parse_constant=no_constants,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PolicyViolation("POLICY_BODY_REJECTED") from exc
    if not isinstance(value, dict):
        raise PolicyViolation("POLICY_BODY_REJECTED")
    return value


def _empty(value: object) -> bool:
    if value in (None, False, 0, ""):
        return True
    if isinstance(value, (list, tuple)):
        return all(_empty(item) for item in value)
    if isinstance(value, dict):
        return all(_empty(item) for item in value.values())
    return False


def _exact_keys(value: dict[str, object], allowed: Iterable[str]) -> None:
    if not set(value).issubset(set(allowed)):
        raise PolicyViolation("POLICY_BODY_REJECTED")


def _split_env(values: object, allowed: set[str]) -> dict[str, str]:
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        raise PolicyViolation("POLICY_BODY_REJECTED")
    result: dict[str, str] = {}
    for item in values:
        name, separator, value = item.partition("=")
        if not separator or name not in allowed or name in result:
            raise PolicyViolation("POLICY_BODY_REJECTED")
        if not value or len(value) > 4096 or "\x00" in value or "\n" in value or "\r" in value:
            raise PolicyViolation("POLICY_BODY_REJECTED")
        result[name] = value
    if set(result) != allowed:
        raise PolicyViolation("POLICY_BODY_REJECTED")
    return result


class DBStartPolicy:
    """Closed one-shot policy for the pinned database-only CLI lifecycle."""

    CONFIG_KEYS: Final = {
        "Hostname", "Domainname", "User", "AttachStdin", "AttachStdout", "AttachStderr",
        "ExposedPorts", "Tty", "OpenStdin", "StdinOnce", "Env", "Cmd", "Healthcheck",
        "ArgsEscaped", "Image", "Volumes", "WorkingDir", "Entrypoint", "NetworkDisabled",
        "MacAddress", "OnBuild", "Labels", "StopSignal", "StopTimeout", "Shell",
    }
    HOST_KEYS: Final = {
        "Annotations", "AutoRemove", "Binds", "BlkioDeviceReadBps", "BlkioDeviceReadIOps",
        "BlkioDeviceWriteBps", "BlkioDeviceWriteIOps", "BlkioWeight", "BlkioWeightDevice",
        "CapAdd", "CapDrop", "Cgroup", "CgroupParent", "CgroupnsMode", "ConsoleSize",
        "ContainerIDFile", "CpuCount", "CpuPercent", "CpuPeriod", "CpuQuota",
        "CpuRealtimePeriod", "CpuRealtimeRuntime", "CpuShares", "CpusetCpus", "CpusetMems",
        "DeviceCgroupRules", "DeviceRequests", "Devices", "Dns", "DnsOptions", "DnsSearch",
        "ExtraHosts", "GroupAdd", "IOMaximumBandwidth", "IOMaximumIOps", "Init", "IpcMode",
        "Isolation", "KernelMemoryTCP", "Links", "LogConfig", "MaskedPaths", "Memory",
        "MemoryReservation", "MemorySwap", "MemorySwappiness", "Mounts", "NanoCpus",
        "NetworkMode", "OomKillDisable", "OomScoreAdj", "PidMode", "PidsLimit",
        "PortBindings", "Privileged", "PublishAllPorts", "ReadonlyPaths", "ReadonlyRootfs",
        "RestartPolicy", "Runtime", "SecurityOpt", "ShmSize", "StorageOpt", "Sysctls",
        "Tmpfs", "UTSMode", "Ulimits", "UsernsMode", "VolumeDriver", "VolumesFrom",
    }
    NETWORK_CREATE_KEYS: Final = {
        "Name", "CheckDuplicate", "Driver", "Internal", "Attachable", "Ingress", "IPAM",
        "EnableIPv6", "Options", "Labels", "Scope", "ConfigOnly", "ConfigFrom",
    }
    VOLUME_CREATE_KEYS: Final = {"Name", "Driver", "DriverOpts", "Labels", "ClusterVolumeSpec"}
    ENDPOINT_KEYS: Final = {
        "IPAMConfig", "Links", "Aliases", "MacAddress", "DriverOpts", "GwPriority",
        "NetworkID", "EndpointID", "Gateway", "IPAddress", "IPPrefixLen", "IPv6Gateway",
        "GlobalIPv6Address", "GlobalIPv6PrefixLen", "DNSNames",
    }
    POLICY_KEYS: Final = {
        "schema", "matrix_sha256", "generation", "nonce", "api_version", "project",
        "network_name", "network_id", "db_name", "db_volume", "db_port",
        "postgres_image_ref", "postgres_image_id", "postgres_digest",
        "gotrue_image_ref", "gotrue_image_id", "gotrue_digest",
    }

    def __init__(self, data: dict[str, object]) -> None:
        if set(data) != self.POLICY_KEYS or data.get("schema") != POLICY_SCHEMA:
            raise PolicyViolation("POLICY_DESCRIPTOR_INVALID")
        if data.get("matrix_sha256") != POLICY_MATRIX_SHA256:
            raise PolicyViolation("POLICY_DESCRIPTOR_INVALID")
        if data.get("generation") != 0:
            raise PolicyViolation("POLICY_LEDGER_LOST")
        string_keys = self.POLICY_KEYS - {"generation"}
        if any(not isinstance(data.get(key), str) or not data[key] for key in string_keys):
            raise PolicyViolation("POLICY_DESCRIPTOR_INVALID")
        if re.fullmatch(r"[0-9a-f]{64}", str(data["nonce"])) is None:
            raise PolicyViolation("POLICY_DESCRIPTOR_INVALID")
        if re.fullmatch(r"[0-9]+\.[0-9]+", str(data["api_version"])) is None:
            raise PolicyViolation("POLICY_DESCRIPTOR_INVALID")
        if re.fullmatch(r"[0-9]+", str(data["db_port"])) is None:
            raise PolicyViolation("POLICY_DESCRIPTOR_INVALID")
        if re.fullmatch(r"[0-9a-f]{64}", str(data["network_id"])) is None:
            raise PolicyViolation("POLICY_DESCRIPTOR_INVALID")
        if any(re.fullmatch(r"sha256:[0-9a-f]{64}", str(data[key])) is None for key in (
            "postgres_image_id", "postgres_digest", "gotrue_image_id", "gotrue_digest"
        )):
            raise PolicyViolation("POLICY_DESCRIPTOR_INVALID")
        self.data = {key: data[key] for key in sorted(data)}
        canonical = json.dumps(self.data, sort_keys=True, separators=(",", ":")).encode()
        self.digest = hashlib.sha256(canonical).hexdigest()
        self.matrix_sha256 = str(data["matrix_sha256"])
        self.state = "NEGOTIATE_HEAD"
        self.step_index = 0
        self.health_probe_count = 0
        self.request_body_bytes = 0
        self.response_body_bytes = 0
        self.db_id = ""
        self.gotrue_id = ""
        self.complete = False
        self.failed = False

    @classmethod
    def from_fd(cls, descriptor: int) -> DBStartPolicy:
        try:
            raw = os.read(descriptor, 65537)
            extra = os.read(descriptor, 1)
        except OSError as exc:
            raise PolicyViolation("POLICY_DESCRIPTOR_INVALID") from exc
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if not raw or extra or len(raw) > 65536:
            raise PolicyViolation("POLICY_DESCRIPTOR_INVALID")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise PolicyViolation("POLICY_DESCRIPTOR_INVALID") from exc
        if not isinstance(value, dict):
            raise PolicyViolation("POLICY_DESCRIPTOR_INVALID")
        return cls(value)

    @property
    def db_id_sha256(self) -> str:
        return hashlib.sha256(self.db_id.encode()).hexdigest() if self.db_id else ZERO_SHA256

    @property
    def gotrue_id_sha256(self) -> str:
        return hashlib.sha256(self.gotrue_id.encode()).hexdigest() if self.gotrue_id else ZERO_SHA256

    def fail(self, code: str) -> None:
        self.failed = True
        self.state = "FAILED"
        raise PolicyViolation(code)

    def _target(self, target: bytes, ping: bool = False) -> tuple[str, dict[str, list[str]]]:
        try:
            raw = target.decode("ascii")
        except UnicodeError:
            self.fail("POLICY_OPERATION_REJECTED")
        split = urlsplit(raw)
        if split.scheme or split.netloc or split.fragment:
            self.fail("POLICY_OPERATION_REJECTED")
        expected_prefix = f"/v{self.data['api_version']}"
        if ping:
            if split.path != "/_ping":
                self.fail("POLICY_API_VERSION_REJECTED")
            normalized = split.path
        else:
            if not split.path.startswith(expected_prefix + "/"):
                self.fail("POLICY_API_VERSION_REJECTED")
            normalized = split.path[len(expected_prefix):]
            if API_PREFIX.match(normalized.encode()):
                self.fail("POLICY_API_VERSION_REJECTED")
        try:
            query = parse_qs(split.query, keep_blank_values=True, strict_parsing=True)
        except ValueError:
            self.fail("POLICY_QUERY_REJECTED")
        if any(len(values) != 1 for values in query.values()):
            self.fail("POLICY_QUERY_REJECTED")
        return normalized, query

    def _require_json_media(self, headers: dict[str, str], body: bytes, maximum: int) -> dict[str, object]:
        media = headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if media != "application/json":
            self.fail("POLICY_MEDIA_TYPE_REJECTED")
        return _closed_json(body, maximum)

    def _labels(self, value: object) -> None:
        expected = {
            "com.supabase.cli.project": str(self.data["project"]),
            "com.docker.compose.project": str(self.data["project"]),
        }
        if value != expected:
            self.fail("POLICY_IDENTITY_REJECTED")

    def _inactive_config(self, config: dict[str, object], active: set[str]) -> None:
        _exact_keys(config, self.CONFIG_KEYS)
        for key, value in config.items():
            if key not in active and not _empty(value):
                self.fail("POLICY_BODY_REJECTED")

    def _inactive_host(self, host: dict[str, object], active: set[str]) -> None:
        _exact_keys(host, self.HOST_KEYS)
        for key, value in host.items():
            if key not in active and not _empty(value):
                self.fail("POLICY_BODY_REJECTED")

    def _networking(self, value: object, database: bool) -> None:
        if not isinstance(value, dict) or not set(value).issubset({"EndpointsConfig"}):
            self.fail("POLICY_BODY_REJECTED")
        endpoints = value.get("EndpointsConfig")
        if not database:
            if not _empty(endpoints):
                self.fail("POLICY_BODY_REJECTED")
            return
        if not isinstance(endpoints, dict) or set(endpoints) != {self.data["network_name"]}:
            self.fail("POLICY_IDENTITY_REJECTED")
        endpoint = endpoints[self.data["network_name"]]
        if not isinstance(endpoint, dict):
            self.fail("POLICY_BODY_REJECTED")
        _exact_keys(endpoint, self.ENDPOINT_KEYS)
        if endpoint.get("Aliases") != ["db", "db.supabase.internal"]:
            self.fail("POLICY_IDENTITY_REJECTED")
        for key, item in endpoint.items():
            if key != "Aliases" and not _empty(item):
                self.fail("POLICY_BODY_REJECTED")

    def _container_body(self, body: dict[str, object], database: bool) -> None:
        if set(body) != {"Config", "HostConfig", "NetworkingConfig"}:
            self.fail("POLICY_BODY_REJECTED")
        config = body["Config"]
        host = body["HostConfig"]
        if not isinstance(config, dict) or not isinstance(host, dict):
            self.fail("POLICY_BODY_REJECTED")
        expected_image = self.data["postgres_image_ref"] if database else self.data["gotrue_image_ref"]
        if config.get("Image") != expected_image:
            self.fail("POLICY_IDENTITY_REJECTED")
        self._labels(config.get("Labels"))
        if host.get("NetworkMode") != self.data["network_name"]:
            self.fail("POLICY_IDENTITY_REJECTED")
        if host.get("ExtraHosts") != ["host.docker.internal:host-gateway"]:
            self.fail("POLICY_BODY_REJECTED")
        if database:
            self._inactive_config(config, {"Env", "Healthcheck", "Image", "Labels", "Entrypoint"})
            env = _split_env(config.get("Env"), {"POSTGRES_PASSWORD", "POSTGRES_HOST", "JWT_SECRET", "JWT_EXP"})
            if env["POSTGRES_HOST"] != "/var/run/postgresql" or not env["JWT_EXP"].isdigit():
                self.fail("POLICY_BODY_REJECTED")
            health = config.get("Healthcheck")
            if not isinstance(health, dict) or health.get("Test") != ["CMD", "pg_isready", "-U", "postgres", "-h", "127.0.0.1", "-p", "5432"]:
                self.fail("POLICY_BODY_REJECTED")
            if health.get("Interval") != 10_000_000_000 or health.get("Timeout") != 2_000_000_000 or health.get("Retries") != 3:
                self.fail("POLICY_BODY_REJECTED")
            if any(key not in {"Test", "Interval", "Timeout", "Retries", "StartPeriod", "StartInterval"} for key in health):
                self.fail("POLICY_BODY_REJECTED")
            if any(not _empty(health.get(key)) for key in ("StartPeriod", "StartInterval")):
                self.fail("POLICY_BODY_REJECTED")
            entrypoint = config.get("Entrypoint")
            if (
                not isinstance(entrypoint, list)
                or len(entrypoint) != 3
                or entrypoint[:2] != ["sh", "-c"]
                or not isinstance(entrypoint[2], str)
                or entrypoint[2].count("docker-entrypoint.sh postgres") != 1
            ):
                self.fail("POLICY_BODY_REJECTED")
            if len(entrypoint[2].encode()) > 1024 * 1024 or "/var/run/docker.sock" in entrypoint[2]:
                self.fail("POLICY_BODY_REJECTED")
            self._inactive_host(host, {"Binds", "NetworkMode", "PortBindings", "RestartPolicy", "ExtraHosts"})
            if host.get("Binds") != [f"{self.data['db_volume']}:/var/lib/postgresql/data"]:
                self.fail("POLICY_BODY_REJECTED")
            binding = host.get("PortBindings")
            expected_binding = {"5432/tcp": [{"HostIp": "", "HostPort": self.data["db_port"]}]}
            if binding != expected_binding:
                self.fail("POLICY_BODY_REJECTED")
            restart = host.get("RestartPolicy")
            if not isinstance(restart, dict) or restart.get("Name") != "unless-stopped" or not _empty(restart.get("MaximumRetryCount")):
                self.fail("POLICY_BODY_REJECTED")
        else:
            self._inactive_config(config, {"Env", "Cmd", "Image", "Labels"})
            if config.get("Cmd") != ["gotrue", "migrate"]:
                self.fail("POLICY_BODY_REJECTED")
            env = _split_env(config.get("Env"), {
                "API_EXTERNAL_URL", "GOTRUE_LOG_LEVEL", "GOTRUE_DB_DRIVER",
                "GOTRUE_DB_DATABASE_URL", "GOTRUE_SITE_URL", "GOTRUE_JWT_SECRET",
            })
            if env["GOTRUE_LOG_LEVEL"] != "error" or env["GOTRUE_DB_DRIVER"] != "postgres" or env["GOTRUE_SITE_URL"] != "http://localhost:3000":
                self.fail("POLICY_BODY_REJECTED")
            external = urlsplit(env["API_EXTERNAL_URL"])
            if external.scheme not in {"http", "https"} or external.hostname not in {"127.0.0.1", "localhost"} or external.username or external.password:
                self.fail("POLICY_BODY_REJECTED")
            database_url = urlsplit(env["GOTRUE_DB_DATABASE_URL"])
            try:
                database_port = database_url.port
            except ValueError:
                self.fail("POLICY_BODY_REJECTED")
            if database_url.scheme != "postgresql" or database_url.hostname != self.data["db_name"] or database_port != 5432 or database_url.username != "supabase_auth_admin" or database_url.path != "/postgres" or not database_url.password:
                self.fail("POLICY_BODY_REJECTED")
            self._inactive_host(host, {"NetworkMode", "ExtraHosts"})
        self._networking(body["NetworkingConfig"], database)

    def authorize(self, method: bytes, target: bytes, headers: dict[str, str], body: bytes) -> PolicyDecision:
        if self.failed or self.complete:
            self.fail("POLICY_ORDER_REJECTED")
        self.request_body_bytes += len(body)
        state = self.state
        if state in {"NEGOTIATE_HEAD", "NEGOTIATE_GET"}:
            path, query = self._target(target, ping=True)
        else:
            path, query = self._target(target)
        if state == "NEGOTIATE_HEAD":
            if method != b"HEAD" or path != "/_ping" or query or body:
                self.fail("POLICY_ORDER_REJECTED")
            return PolicyDecision(state, "API_NEGOTIATION", method, (200, 405))
        if state == "NEGOTIATE_GET":
            if method != b"GET" or path != "/_ping" or query or body:
                self.fail("POLICY_ORDER_REJECTED")
            return PolicyDecision(state, "API_NEGOTIATION", method, (200,))
        if state == "DB_INSPECT":
            expected = f"/containers/{self.data['db_name']}/json"
            return self._simple(method, path, query, body, b"GET", expected, "CONTAINER_INSPECT", (404,))
        if state == "VOLUME_INSPECT":
            expected = f"/volumes/{self.data['db_volume']}"
            return self._simple(method, path, query, body, b"GET", expected, "VOLUME_INSPECT", (404,))
        if state in {"PG_IMAGE_INSPECT", "GOTRUE_IMAGE_INSPECT"}:
            image = self.data["postgres_image_ref"] if state == "PG_IMAGE_INSPECT" else self.data["gotrue_image_ref"]
            expected = f"/images/{image}/json"
            if method != b"GET" or unquote(path) != expected or query or body:
                self.fail("POLICY_IDENTITY_REJECTED")
            return PolicyDecision(state, "IMAGE_INSPECT", method, (200,))
        if state in {"NETWORK_DB", "NETWORK_GOTRUE"}:
            if method != b"POST" or path != "/networks/create" or query:
                self.fail("POLICY_ORDER_REJECTED")
            value = self._require_json_media(headers, body, 65536)
            _exact_keys(value, self.NETWORK_CREATE_KEYS)
            if value.get("Name") != self.data["network_name"]:
                self.fail("POLICY_IDENTITY_REJECTED")
            self._labels(value.get("Labels"))
            if any(key not in {"Name", "Labels"} and not _empty(item) for key, item in value.items()):
                self.fail("POLICY_BODY_REJECTED")
            return PolicyDecision(state, "NETWORK_INSPECT_REUSE", method, (409,))
        if state == "VOLUME_CREATE":
            if method != b"POST" or path != "/volumes/create" or query:
                self.fail("POLICY_ORDER_REJECTED")
            value = self._require_json_media(headers, body, 65536)
            _exact_keys(value, self.VOLUME_CREATE_KEYS)
            if value.get("Name") != self.data["db_volume"]:
                self.fail("POLICY_IDENTITY_REJECTED")
            self._labels(value.get("Labels"))
            if any(key not in {"Name", "Labels"} and not _empty(item) for key, item in value.items()):
                self.fail("POLICY_BODY_REJECTED")
            return PolicyDecision(state, "VOLUME_CREATE", method, (201,))
        if state in {"DB_CREATE", "GOTRUE_CREATE"}:
            if method != b"POST" or path != "/containers/create":
                self.fail("POLICY_ORDER_REJECTED")
            expected_query = {"name": [str(self.data["db_name"])]} if state == "DB_CREATE" else {}
            if query != expected_query:
                self.fail("POLICY_QUERY_REJECTED")
            value = self._require_json_media(headers, body, 1024 * 1024)
            self._container_body(value, state == "DB_CREATE")
            return PolicyDecision(state, "CONTAINER_CREATE", method, (201,))
        if state in {"DB_START", "GOTRUE_START"}:
            identifier = self.db_id if state == "DB_START" else self.gotrue_id
            expected = f"/containers/{identifier}/start"
            return self._simple(method, path, query, body, b"POST", expected, "CONTAINER_START", (204,))
        if state == "DB_HEALTH":
            expected = f"/containers/{self.data['db_name']}/json"
            return self._simple(method, path, query, body, b"GET", expected, "CONTAINER_INSPECT", (200,))
        if state == "DB_LOGS":
            expected = f"/containers/{self.data['db_name']}/logs"
            decision = self._simple(method, path, {}, body, b"GET", expected, "CONTAINER_LOGS", (200,), stream=True)
            if query != {"stderr": ["1"], "stdout": ["1"], "tail": [""]}:
                self.fail("POLICY_QUERY_REJECTED")
            return decision
        if state == "GOTRUE_LOGS":
            expected = f"/containers/{self.gotrue_id}/logs"
            decision = self._simple(method, path, {}, body, b"GET", expected, "CONTAINER_LOGS", (200,), stream=True)
            if query != {"follow": ["1"], "stderr": ["1"], "stdout": ["1"], "tail": [""]}:
                self.fail("POLICY_QUERY_REJECTED")
            return decision
        if state == "GOTRUE_INSPECT":
            expected = f"/containers/{self.gotrue_id}/json"
            return self._simple(method, path, query, body, b"GET", expected, "CONTAINER_INSPECT", (200,))
        if state == "GOTRUE_REMOVE":
            expected = f"/containers/{self.gotrue_id}"
            if query != {"force": ["1"], "v": ["1"]}:
                self.fail("POLICY_QUERY_REJECTED")
            return self._simple(method, path, {}, body, b"DELETE", expected, "CONTAINER_REMOVE", (204,))
        self.fail("POLICY_OPERATION_REJECTED")

    def _simple(self, method: bytes, path: str, query: dict[str, list[str]], body: bytes, expected_method: bytes, expected_path: str, phase: str, statuses: tuple[int, ...], stream: bool = False) -> PolicyDecision:
        if method != expected_method or path != expected_path or query or body:
            self.fail("POLICY_ORDER_REJECTED")
        return PolicyDecision(self.state, phase, method, statuses, stream)

    def accept(self, decision: PolicyDecision, code: int, headers: dict[str, str], body: bytes | None, body_bytes: int) -> None:
        if decision.name != self.state or code not in decision.expected_statuses:
            self.fail("POLICY_STATUS_REJECTED")
        self.response_body_bytes += body_bytes
        state = self.state
        if state == "NEGOTIATE_HEAD":
            if code == 405:
                self.state = "NEGOTIATE_GET"
            else:
                if headers.get("api-version") != self.data["api_version"]:
                    self.fail("POLICY_API_VERSION_REJECTED")
                self.state = "DB_INSPECT"
        elif state == "NEGOTIATE_GET":
            if headers.get("api-version") != self.data["api_version"]:
                self.fail("POLICY_API_VERSION_REJECTED")
            self.state = "DB_INSPECT"
        elif state == "DB_INSPECT":
            self.state = "VOLUME_INSPECT"
        elif state == "VOLUME_INSPECT":
            self.state = "PG_IMAGE_INSPECT"
        elif state in {"PG_IMAGE_INSPECT", "GOTRUE_IMAGE_INSPECT"}:
            value = self._response_json(headers, body)
            expected = self.data["postgres_image_id"] if state == "PG_IMAGE_INSPECT" else self.data["gotrue_image_id"]
            if value.get("Id") != expected:
                self.fail("POLICY_IDENTITY_REJECTED")
            self.state = "NETWORK_DB" if state == "PG_IMAGE_INSPECT" else "NETWORK_GOTRUE"
        elif state == "NETWORK_DB":
            self.state = "VOLUME_CREATE"
        elif state == "NETWORK_GOTRUE":
            self.state = "GOTRUE_CREATE"
        elif state == "VOLUME_CREATE":
            value = self._response_json(headers, body)
            if value.get("Name") != self.data["db_volume"]:
                self.fail("POLICY_IDENTITY_REJECTED")
            self.state = "DB_CREATE"
        elif state in {"DB_CREATE", "GOTRUE_CREATE"}:
            value = self._response_json(headers, body)
            identifier = value.get("Id")
            if not isinstance(identifier, str) or re.fullmatch(r"[0-9a-f]{64}", identifier) is None:
                self.fail("POLICY_RESPONSE_REJECTED")
            if identifier in {self.db_id, self.gotrue_id}:
                self.fail("POLICY_IDENTITY_REJECTED")
            if state == "DB_CREATE":
                self.db_id = identifier
                self.state = "DB_START"
            else:
                self.gotrue_id = identifier
                self.state = "GOTRUE_START"
        elif state == "DB_START":
            self.state = "DB_HEALTH"
        elif state == "GOTRUE_START":
            self.state = "GOTRUE_LOGS"
        elif state == "DB_HEALTH":
            value = self._response_json(headers, body)
            self._inspect_identity(value, database=True)
            health = ((value.get("State") or {}).get("Health") or {}).get("Status") if isinstance(value.get("State"), dict) else None
            self.health_probe_count += 1
            if health == "healthy":
                self.state = "GOTRUE_IMAGE_INSPECT"
            elif health in {"starting", "unhealthy"} and self.health_probe_count < 121:
                pass
            elif health in {"starting", "unhealthy"}:
                self.state = "DB_LOGS"
            else:
                self.fail("POLICY_RESPONSE_REJECTED")
        elif state == "DB_LOGS":
            self.failed = True
            self.state = "FAILED"
        elif state == "GOTRUE_LOGS":
            self.state = "GOTRUE_INSPECT"
        elif state == "GOTRUE_INSPECT":
            value = self._response_json(headers, body)
            self._inspect_identity(value, database=False)
            container_state = value.get("State")
            if not isinstance(container_state, dict) or container_state.get("ExitCode") != 0:
                self.fail("POLICY_STATUS_REJECTED")
            self.state = "GOTRUE_REMOVE"
        elif state == "GOTRUE_REMOVE":
            self.state = "COMPLETE"
            self.complete = True
        self.step_index += 1

    def _response_json(self, headers: dict[str, str], body: bytes | None) -> dict[str, object]:
        if body is None:
            self.fail("POLICY_RESPONSE_REJECTED")
        media = headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if media != "application/json":
            self.fail("POLICY_MEDIA_TYPE_REJECTED")
        return _closed_json(body, MAX_CONTROL_RESPONSE)

    def _inspect_identity(self, value: dict[str, object], database: bool) -> None:
        identifier = self.db_id if database else self.gotrue_id
        expected_image = self.data["postgres_image_id"] if database else self.data["gotrue_image_id"]
        expected_name = f"/{self.data['db_name']}" if database else None
        if value.get("Id") != identifier or value.get("Image") != expected_image:
            self.fail("POLICY_IDENTITY_REJECTED")
        if database and value.get("Name") != expected_name:
            self.fail("POLICY_IDENTITY_REJECTED")
        network_settings = value.get("NetworkSettings")
        if not isinstance(network_settings, dict):
            self.fail("POLICY_RESPONSE_REJECTED")
        networks = network_settings.get("Networks")
        if not isinstance(networks, dict) or set(networks) != {self.data["network_name"]}:
            self.fail("POLICY_IDENTITY_REJECTED")
        endpoint = networks[self.data["network_name"]]
        if not isinstance(endpoint, dict) or endpoint.get("NetworkID") != self.data["network_id"]:
            self.fail("POLICY_IDENTITY_REJECTED")
        ports = network_settings.get("Ports")
        if database:
            if ports != {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": self.data["db_port"]}]}:
                self.fail("POLICY_IDENTITY_REJECTED")
        elif not _empty(ports):
            self.fail("POLICY_IDENTITY_REJECTED")


class Receipt:
    def __init__(self) -> None:
        self.connection_count = 0
        self.request_count = 0
        self.response_count = 0
        self.error_response_count = 0
        self.write_attempt_count = 0
        self.forwarding_error_count = 0
        self.parser_error_count = 0
        self.phase_counts: Counter[str] = Counter()
        self.method_counts: Counter[str] = Counter()
        self.status_class_counts: Counter[str] = Counter()
        self.status_code_counts: Counter[str] = Counter()
        self.first_phase = "NONE"
        self.last_phase = "NONE"
        self.first_error_phase = "NONE"
        self.first_error_status_code = 0
        self.policy_mode = "READ_ONLY"
        self.policy_matrix_sha256 = ZERO_SHA256
        self.policy_digest = ZERO_SHA256
        self.policy_descriptor_consumed = 0
        self.policy_complete = 0
        self.policy_violation_count = 0
        self.policy_failure_code = "NONE"
        self.policy_step_index = 0
        self.policy_health_probe_count = 0
        self.policy_request_body_bytes = 0
        self.policy_response_body_bytes = 0
        self.db_container_id_sha256 = ZERO_SHA256
        self.gotrue_container_id_sha256 = ZERO_SHA256

    def attach_policy(self, policy: DBStartPolicy) -> None:
        self.policy_mode = "DB_START_V1"
        self.policy_matrix_sha256 = policy.matrix_sha256
        self.policy_digest = policy.digest
        self.policy_descriptor_consumed = 1

    def sync_policy(self, policy: DBStartPolicy) -> None:
        self.policy_complete = int(policy.complete)
        self.policy_step_index = policy.step_index
        self.policy_health_probe_count = policy.health_probe_count
        self.policy_request_body_bytes = policy.request_body_bytes
        self.policy_response_body_bytes = policy.response_body_bytes
        self.db_container_id_sha256 = policy.db_id_sha256
        self.gotrue_container_id_sha256 = policy.gotrue_id_sha256

    def policy_violation(self, code: str) -> None:
        self.policy_violation_count += 1
        if self.policy_failure_code == "NONE":
            self.policy_failure_code = code if code in POLICY_FAILURE_CODES else "POLICY_OPERATION_REJECTED"

    def connect(self) -> None:
        self.connection_count += 1

    def request(self, phase: str, method: str) -> None:
        self.request_count += 1
        self.phase_counts[phase] += 1
        self.method_counts[method] += 1
        if self.first_phase == "NONE":
            self.first_phase = phase
        self.last_phase = phase

    def response(self, phase: str, code: int) -> None:
        self.response_count += 1
        status_class = f"{code // 100}XX" if 100 <= code <= 599 else "OTHER"
        self.status_class_counts[status_class] += 1
        key = f"CODE_{code}" if code in STATUS_CODES else "CODE_OTHER"
        self.status_code_counts[key] += 1
        if code >= 400 or code < 100:
            self.error_response_count += 1
            if self.first_error_phase == "NONE":
                self.first_error_phase = phase
                self.first_error_status_code = code if code in STATUS_CODES else 0

    def write_attempt(self) -> None:
        self.write_attempt_count += 1

    def forwarding_error(self) -> None:
        self.forwarding_error_count += 1

    def parser_error(self) -> None:
        self.parser_error_count += 1

    def classification(self) -> str:
        if self.policy_mode == "DB_START_V1":
            if self.policy_violation_count:
                return "DB_START_POLICY_VIOLATION"
            if self.forwarding_error_count or self.parser_error_count:
                return "OBSERVER_FORWARDING_FAILED"
            if self.policy_complete:
                return "DB_START_POLICY_COMPLETE"
            return "DB_START_POLICY_INCOMPLETE"
        if self.write_attempt_count:
            return "DOCKER_API_WRITE_ATTEMPT_OBSERVED"
        if self.forwarding_error_count or self.parser_error_count:
            return "OBSERVER_FORWARDING_FAILED"
        if self.request_count == 0:
            return "NO_DOCKER_API_REQUEST_OBSERVED"
        if self.response_count < self.request_count:
            return "DOCKER_API_RESPONSE_INCOMPLETE"
        if self.error_response_count:
            return "DOCKER_API_ERROR_RESPONSE_OBSERVED"
        return "DOCKER_API_REQUESTS_OBSERVED"

    def sanitized(self) -> dict[str, object]:
        result: dict[str, object] = {
            "schema": SCHEMA,
            "classification": self.classification(),
            "connection_count": self.connection_count,
            "request_count": self.request_count,
            "response_count": self.response_count,
            "error_response_count": self.error_response_count,
            "write_attempt_count": self.write_attempt_count,
            "forwarding_error_count": self.forwarding_error_count,
            "parser_error_count": self.parser_error_count,
            "first_phase": self.first_phase,
            "last_phase": self.last_phase,
            "first_error_phase": self.first_error_phase,
            "first_error_status_code": self.first_error_status_code,
            "policy_mode": self.policy_mode,
            "policy_matrix_sha256": self.policy_matrix_sha256,
            "policy_digest": self.policy_digest,
            "policy_descriptor_consumed": self.policy_descriptor_consumed,
            "policy_complete": self.policy_complete,
            "policy_violation_count": self.policy_violation_count,
            "policy_failure_code": self.policy_failure_code,
            "policy_step_index": self.policy_step_index,
            "policy_health_probe_count": self.policy_health_probe_count,
            "policy_request_body_bytes": self.policy_request_body_bytes,
            "policy_response_body_bytes": self.policy_response_body_bytes,
            "db_container_id_sha256": self.db_container_id_sha256,
            "gotrue_container_id_sha256": self.gotrue_container_id_sha256,
            "phase_counts": {phase: self.phase_counts[phase] for phase in PHASES},
            "method_class_counts": {name: self.method_counts[name] for name in METHOD_CLASSES},
            "status_class_counts": {name: self.status_class_counts[name] for name in STATUS_CLASSES},
            "status_code_counts": {
                **{f"CODE_{code}": self.status_code_counts[f"CODE_{code}"] for code in STATUS_CODES},
                "CODE_OTHER": self.status_code_counts["CODE_OTHER"],
            },
        }
        canonical = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        result["canonical_sha256"] = hashlib.sha256(canonical).hexdigest()
        validate_result(result)
        return result


class HTTPFramingParser:
    def __init__(self) -> None:
        self.buffer = bytearray()
        self.state = "line"
        self.content_remaining = 0
        self.chunk_remaining = 0
        self.chunked = False
        self.content_length = 0

    def pop_line(self) -> bytes | None:
        marker = self.buffer.find(b"\r\n")
        if marker < 0:
            if len(self.buffer) > MAX_LINE:
                raise ValueError("HTTP line exceeds bound")
            return None
        line = bytes(self.buffer[:marker])
        del self.buffer[: marker + 2]
        return line

    def consume_body(self) -> bool:
        if self.state == "body":
            consumed = min(len(self.buffer), self.content_remaining)
            del self.buffer[:consumed]
            self.content_remaining -= consumed
            if self.content_remaining == 0:
                self.state = "line"
            return consumed > 0
        if self.state == "chunk_data":
            consumed = min(len(self.buffer), self.chunk_remaining)
            del self.buffer[:consumed]
            self.chunk_remaining -= consumed
            if self.chunk_remaining == 0:
                self.state = "chunk_crlf"
            return consumed > 0
        if self.state == "chunk_crlf":
            if len(self.buffer) < 2:
                return False
            if self.buffer[:2] != b"\r\n":
                raise ValueError("invalid chunk framing")
            del self.buffer[:2]
            self.state = "chunk_size"
            return True
        return False

    def parse_header(self, line: bytes) -> None:
        name, separator, value = line.partition(b":")
        if not separator:
            raise ValueError("invalid HTTP header framing")
        name = name.strip().lower()
        value = value.strip().lower()
        if name == b"content-length":
            if not value.isdigit():
                raise ValueError("invalid content length")
            self.content_length = int(value)
        elif name == b"transfer-encoding" and b"chunked" in value:
            self.chunked = True

    def finish_headers(self) -> None:
        if self.chunked:
            self.state = "chunk_size"
        elif self.content_length:
            self.content_remaining = self.content_length
            self.state = "body"
        else:
            self.state = "line"
        self.chunked = False
        self.content_length = 0


class RequestParser(HTTPFramingParser):
    def __init__(self, receipt: Receipt, pending: deque[tuple[str, bytes]]) -> None:
        super().__init__()
        self.receipt = receipt
        self.pending = pending

    def feed(self, data: bytes) -> None:
        self.buffer.extend(data)
        while self.buffer:
            if self.consume_body():
                continue
            if self.state == "chunk_size":
                line = self.pop_line()
                if line is None:
                    return
                size_token = line.split(b";", 1)[0]
                try:
                    size = int(size_token, 16)
                except ValueError as exc:
                    raise ValueError("invalid chunk size") from exc
                if size == 0:
                    self.state = "chunk_trailer"
                else:
                    self.chunk_remaining = size
                    self.state = "chunk_data"
                continue
            if self.state == "chunk_trailer":
                line = self.pop_line()
                if line is None:
                    return
                if not line:
                    self.state = "line"
                continue
            line = self.pop_line()
            if line is None:
                return
            if self.state == "line":
                parts = line.split(b" ", 2)
                if len(parts) != 3 or not parts[2].startswith(b"HTTP/1."):
                    raise ValueError("invalid HTTP request line")
                method, target = parts[0], parts[1]
                phase = classify_path(method, target)
                method_kind = method_class(method)
                self.receipt.request(phase, method_kind)
                if method_kind != "READ":
                    self.receipt.write_attempt()
                    raise WriteAttemptError
                self.pending.append((phase, method))
                self.state = "headers"
            elif self.state == "headers":
                if line:
                    self.parse_header(line)
                else:
                    self.finish_headers()


class ResponseParser(HTTPFramingParser):
    def __init__(self, receipt: Receipt, pending: deque[tuple[str, bytes]]) -> None:
        super().__init__()
        self.receipt = receipt
        self.pending = pending
        self.no_body = False

    def feed(self, data: bytes) -> None:
        self.buffer.extend(data)
        while self.buffer:
            if self.consume_body():
                continue
            if self.state == "chunk_size":
                line = self.pop_line()
                if line is None:
                    return
                try:
                    size = int(line.split(b";", 1)[0], 16)
                except ValueError as exc:
                    raise ValueError("invalid response chunk size") from exc
                if size == 0:
                    self.state = "chunk_trailer"
                else:
                    self.chunk_remaining = size
                    self.state = "chunk_data"
                continue
            if self.state == "chunk_trailer":
                line = self.pop_line()
                if line is None:
                    return
                if not line:
                    self.state = "line"
                continue
            line = self.pop_line()
            if line is None:
                return
            if self.state == "line":
                parts = line.split(b" ", 2)
                if len(parts) < 2 or not parts[0].startswith(b"HTTP/1.") or not parts[1].isdigit():
                    raise ValueError("invalid HTTP response line")
                code = int(parts[1])
                phase, method = self.pending.popleft() if self.pending else ("UNKNOWN_API_PHASE", b"")
                self.receipt.response(phase, code)
                self.no_body = method == b"HEAD" or code in (204, 304) or 100 <= code < 200
                self.state = "headers"
            elif self.state == "headers":
                if line:
                    self.parse_header(line)
                else:
                    if self.no_body:
                        self.state = "line"
                        self.chunked = False
                        self.content_length = 0
                    else:
                        self.finish_headers()
                    self.no_body = False


def validate_result(result: dict[str, object]) -> None:
    expected_keys = {
        "schema",
        "classification",
        "connection_count",
        "request_count",
        "response_count",
        "error_response_count",
        "write_attempt_count",
        "forwarding_error_count",
        "parser_error_count",
        "first_phase",
        "last_phase",
        "first_error_phase",
        "first_error_status_code",
        "policy_mode",
        "policy_matrix_sha256",
        "policy_digest",
        "policy_descriptor_consumed",
        "policy_complete",
        "policy_violation_count",
        "policy_failure_code",
        "policy_step_index",
        "policy_health_probe_count",
        "policy_request_body_bytes",
        "policy_response_body_bytes",
        "db_container_id_sha256",
        "gotrue_container_id_sha256",
        "phase_counts",
        "method_class_counts",
        "status_class_counts",
        "status_code_counts",
        "canonical_sha256",
    }
    if set(result) != expected_keys:
        raise ValueError("observer result schema is invalid")
    if result.get("schema") != SCHEMA or result.get("classification") not in CLASSIFICATIONS:
        raise ValueError("observer result enum is invalid")
    if result.get("policy_mode") not in POLICY_MODES or result.get("policy_failure_code") not in POLICY_FAILURE_CODES:
        raise ValueError("observer policy enum is invalid")
    for key in (
        "connection_count",
        "request_count",
        "response_count",
        "error_response_count",
        "write_attempt_count",
        "forwarding_error_count",
        "parser_error_count",
        "first_error_status_code",
        "policy_descriptor_consumed",
        "policy_complete",
        "policy_violation_count",
        "policy_step_index",
        "policy_health_probe_count",
        "policy_request_body_bytes",
        "policy_response_body_bytes",
    ):
        if type(result.get(key)) is not int or int(result[key]) < 0:
            raise ValueError("observer result count is invalid")
    for key in ("first_phase", "last_phase", "first_error_phase"):
        if result.get(key) not in (*PHASES, "NONE"):
            raise ValueError("observer phase is invalid")
    expected_maps = {
        "phase_counts": set(PHASES),
        "method_class_counts": set(METHOD_CLASSES),
        "status_class_counts": set(STATUS_CLASSES),
        "status_code_counts": {*(f"CODE_{code}" for code in STATUS_CODES), "CODE_OTHER"},
    }
    for key, expected in expected_maps.items():
        values = result.get(key)
        if not isinstance(values, dict) or set(values) != expected:
            raise ValueError("observer count map is invalid")
        if any(type(value) is not int or value < 0 for value in values.values()):
            raise ValueError("observer map count is invalid")
    digest = result.get("canonical_sha256")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ValueError("observer digest is invalid")
    canonical = json.dumps(
        {key: value for key, value in result.items() if key != "canonical_sha256"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    if digest != hashlib.sha256(canonical).hexdigest():
        raise ValueError("observer digest does not match sanitized state")
    for key in ("policy_matrix_sha256", "policy_digest", "db_container_id_sha256", "gotrue_container_id_sha256"):
        value = result.get(key)
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError("observer policy digest is invalid")


def format_state_lines(result: dict[str, object]) -> str:
    validate_result(result)
    fields: list[tuple[str, str, object]] = []
    for key in (
        "schema",
        "classification",
        "connection_count",
        "request_count",
        "response_count",
        "error_response_count",
        "write_attempt_count",
        "forwarding_error_count",
        "parser_error_count",
        "first_phase",
        "last_phase",
        "first_error_phase",
        "first_error_status_code",
        "policy_mode",
        "policy_matrix_sha256",
        "policy_digest",
        "policy_descriptor_consumed",
        "policy_complete",
        "policy_violation_count",
        "policy_failure_code",
        "policy_step_index",
        "policy_health_probe_count",
        "policy_request_body_bytes",
        "policy_response_body_bytes",
        "db_container_id_sha256",
        "gotrue_container_id_sha256",
        "canonical_sha256",
    ):
        kind = "int" if key.endswith("_count") or key in {
            "first_error_status_code", "policy_descriptor_consumed", "policy_complete",
            "policy_step_index", "policy_health_probe_count", "policy_request_body_bytes",
            "policy_response_body_bytes",
        } else "str"
        fields.append((f"docker_api_boundary.{key}", kind, result[key]))
    for map_key in ("phase_counts", "method_class_counts", "status_class_counts", "status_code_counts"):
        for key, value in sorted(result[map_key].items()):
            fields.append((f"docker_api_boundary.{map_key}.{key}", "int", value))
    rendered = "".join(f"{key}\t{kind}\t{value}\n" for key, kind, value in fields)
    if not all(re.fullmatch(r"[A-Za-z0-9_.]+\t(?:str|int)\t[A-Za-z0-9_.-]+", line) for line in rendered.splitlines()):
        raise ValueError("observer state output is not closed-schema")
    return rendered


class BoundaryServer:
    def __init__(self, listen: Path, upstream: Path, receipt: Receipt) -> None:
        self.listen = listen
        self.upstream = upstream
        self.receipt = receipt
        self.tasks: set[asyncio.Task[None]] = set()

    async def relay(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, parser: object) -> None:
        while True:
            data = await reader.read(65536)
            if not data:
                try:
                    writer.write_eof()
                except (AttributeError, OSError):
                    pass
                return
            try:
                parser.feed(data)
            except WriteAttemptError:
                writer.close()
                await asyncio.gather(writer.wait_closed(), return_exceptions=True)
                return
            except ValueError:
                self.receipt.parser_error()
            writer.write(data)
            await writer.drain()

    async def handle(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self.tasks.add(task)
        self.receipt.connect()
        upstream_writer: asyncio.StreamWriter | None = None
        try:
            upstream_reader, upstream_writer = await asyncio.open_unix_connection(str(self.upstream))
            pending: deque[tuple[str, bytes]] = deque()
            request_parser = RequestParser(self.receipt, pending)
            response_parser = ResponseParser(self.receipt, pending)
            await asyncio.gather(
                self.relay(client_reader, upstream_writer, request_parser),
                self.relay(upstream_reader, client_writer, response_parser),
            )
        except (OSError, asyncio.IncompleteReadError):
            self.receipt.forwarding_error()
        finally:
            client_writer.close()
            if upstream_writer is not None:
                upstream_writer.close()
            await asyncio.gather(
                client_writer.wait_closed(),
                *(
                    [upstream_writer.wait_closed()]
                    if upstream_writer is not None
                    else []
                ),
                return_exceptions=True,
            )
            if task is not None:
                self.tasks.discard(task)

    async def run(self, stop: asyncio.Event, ready: Path) -> None:
        if self.listen.exists():
            raise FileExistsError("observer listen socket already exists")
        server = await asyncio.start_unix_server(self.handle, path=str(self.listen))
        os.chmod(self.listen, 0o600)
        ready.touch(mode=0o600, exist_ok=False)
        async with server:
            await stop.wait()
        if self.tasks:
            done, pending = await asyncio.wait(self.tasks, timeout=5)
            if pending:
                self.receipt.forwarding_error()
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)


def _parse_head(head: bytes, request: bool) -> tuple[list[bytes], dict[str, str]]:
    if len(head) > MAX_HEADERS or not head.endswith(b"\r\n\r\n"):
        raise PolicyViolation("POLICY_FRAMING_REJECTED")
    lines = head[:-4].split(b"\r\n")
    if not lines or not lines[0]:
        raise PolicyViolation("POLICY_FRAMING_REJECTED")
    headers: dict[str, str] = {}
    for raw in lines[1:]:
        name, separator, value = raw.partition(b":")
        if not separator or not name or re.fullmatch(br"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) is None:
            raise PolicyViolation("POLICY_FRAMING_REJECTED")
        try:
            key = name.decode("ascii").lower()
            decoded = value.strip().decode("latin-1")
        except UnicodeError as exc:
            raise PolicyViolation("POLICY_FRAMING_REJECTED") from exc
        if key in headers:
            raise PolicyViolation("POLICY_FRAMING_REJECTED")
        headers[key] = decoded
    if "content-length" in headers:
        if not headers["content-length"].isdigit():
            raise PolicyViolation("POLICY_FRAMING_REJECTED")
    transfer = headers.get("transfer-encoding", "").lower()
    if transfer and transfer != "chunked":
        raise PolicyViolation("POLICY_FRAMING_REJECTED")
    if transfer and "content-length" in headers:
        raise PolicyViolation("POLICY_FRAMING_REJECTED")
    if request and transfer:
        raise PolicyViolation("POLICY_FRAMING_REJECTED")
    return lines, headers


async def _read_head(reader: asyncio.StreamReader) -> bytes | None:
    try:
        head = await reader.readuntil(b"\r\n\r\n")
    except asyncio.IncompleteReadError as exc:
        if not exc.partial:
            return None
        raise PolicyViolation("POLICY_FRAMING_REJECTED") from exc
    except asyncio.LimitOverrunError as exc:
        raise PolicyViolation("POLICY_FRAMING_REJECTED") from exc
    if len(head) > MAX_HEADERS:
        raise PolicyViolation("POLICY_FRAMING_REJECTED")
    return head


async def _read_request(reader: asyncio.StreamReader) -> tuple[bytes, bytes, bytes, dict[str, str], bytes] | None:
    head = await _read_head(reader)
    if head is None:
        return None
    lines, headers = _parse_head(head, request=True)
    parts = lines[0].split(b" ", 2)
    if len(parts) != 3 or not parts[2].startswith(b"HTTP/1."):
        raise PolicyViolation("POLICY_FRAMING_REJECTED")
    length = int(headers.get("content-length", "0"))
    if length > 1024 * 1024:
        raise PolicyViolation("POLICY_BODY_OVERSIZED")
    try:
        body = await reader.readexactly(length) if length else b""
    except asyncio.IncompleteReadError as exc:
        raise PolicyViolation("POLICY_FRAMING_REJECTED") from exc
    return head, parts[0], parts[1], headers, body


async def _read_chunked_body(
    reader: asyncio.StreamReader,
    maximum: int,
    writer: asyncio.StreamWriter | None = None,
) -> tuple[bytes, bytes, int]:
    raw_parts: list[bytes] = []
    decoded_parts: list[bytes] = []
    total = 0
    trailer_bytes = 0
    while True:
        try:
            line = await reader.readuntil(b"\r\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
            raise PolicyViolation("POLICY_STREAM_REJECTED") from exc
        if len(line) > MAX_LINE or b";" in line:
            raise PolicyViolation("POLICY_STREAM_REJECTED")
        try:
            size = int(line[:-2], 16)
        except ValueError as exc:
            raise PolicyViolation("POLICY_STREAM_REJECTED") from exc
        if writer is not None:
            writer.write(line)
            await writer.drain()
        else:
            raw_parts.append(line)
        if size == 0:
            while True:
                trailer = await reader.readuntil(b"\r\n")
                trailer_bytes += len(trailer)
                if trailer_bytes > MAX_HEADERS:
                    raise PolicyViolation("POLICY_STREAM_REJECTED")
                if writer is not None:
                    writer.write(trailer)
                    await writer.drain()
                else:
                    raw_parts.append(trailer)
                if trailer == b"\r\n":
                    return b"".join(raw_parts), b"".join(decoded_parts), total
        if total + size > maximum:
            raise PolicyViolation("POLICY_BODY_OVERSIZED")
        try:
            payload = await reader.readexactly(size + 2)
        except asyncio.IncompleteReadError as exc:
            raise PolicyViolation("POLICY_STREAM_REJECTED") from exc
        if payload[-2:] != b"\r\n":
            raise PolicyViolation("POLICY_STREAM_REJECTED")
        total += size
        if writer is not None:
            writer.write(payload)
            await writer.drain()
        else:
            raw_parts.append(payload)
            decoded_parts.append(payload[:-2])


async def _read_response_body(
    reader: asyncio.StreamReader,
    headers: dict[str, str],
    no_body: bool,
    maximum: int,
) -> tuple[bytes, bytes, int]:
    if no_body:
        return b"", b"", 0
    if headers.get("transfer-encoding", "").lower() == "chunked":
        return await _read_chunked_body(reader, maximum)
    if "content-length" not in headers:
        raise PolicyViolation("POLICY_FRAMING_REJECTED")
    length = int(headers["content-length"])
    if length > maximum:
        raise PolicyViolation("POLICY_BODY_OVERSIZED")
    try:
        body = await reader.readexactly(length) if length else b""
    except asyncio.IncompleteReadError as exc:
        raise PolicyViolation("POLICY_FRAMING_REJECTED") from exc
    return body, body, len(body)


async def _stream_response_body(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    headers: dict[str, str],
) -> int:
    if headers.get("transfer-encoding", "").lower() == "chunked":
        _, _, total = await _read_chunked_body(reader, MAX_STREAM_RESPONSE, writer)
        return total
    if "content-length" in headers:
        remaining = int(headers["content-length"])
        if remaining > MAX_STREAM_RESPONSE:
            raise PolicyViolation("POLICY_BODY_OVERSIZED")
        total = remaining
        while remaining:
            chunk = await reader.read(min(65536, remaining))
            if not chunk:
                raise PolicyViolation("POLICY_STREAM_REJECTED")
            remaining -= len(chunk)
            writer.write(chunk)
            await writer.drain()
        return total
    if headers.get("connection", "").lower() != "close":
        raise PolicyViolation("POLICY_FRAMING_REJECTED")
    total = 0
    while True:
        chunk = await reader.read(65536)
        if not chunk:
            return total
        total += len(chunk)
        if total > MAX_STREAM_RESPONSE:
            raise PolicyViolation("POLICY_BODY_OVERSIZED")
        writer.write(chunk)
        await writer.drain()


class PolicyBoundaryServer(BoundaryServer):
    def __init__(self, listen: Path, upstream: Path, receipt: Receipt, policy: DBStartPolicy) -> None:
        super().__init__(listen, upstream, receipt)
        self.policy = policy
        self.exchange_lock = asyncio.Lock()
        self.receipt.attach_policy(policy)
        self.receipt.sync_policy(policy)

    def ensure_exchange_available(self) -> None:
        if self.exchange_lock.locked():
            raise PolicyViolation("POLICY_CONCURRENT_REQUEST")

    async def handle(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self.tasks.add(task)
        self.receipt.connect()
        upstream_writer: asyncio.StreamWriter | None = None
        current_method = b""
        try:
            upstream_reader, upstream_writer = await asyncio.open_unix_connection(str(self.upstream))
            while True:
                request = await _read_request(client_reader)
                if request is None:
                    break
                head, current_method, target, headers, body = request
                phase = classify_path(current_method, target)
                self.receipt.request(phase, method_class(current_method))
                self.ensure_exchange_available()
                async with self.exchange_lock:
                    decision = self.policy.authorize(current_method, target, headers, body)
                    upstream_writer.write(head + body)
                    await upstream_writer.drain()
                    response_head = await _read_head(upstream_reader)
                    if response_head is None:
                        raise PolicyViolation("POLICY_FRAMING_REJECTED")
                    lines, response_headers = _parse_head(response_head, request=False)
                    parts = lines[0].split(b" ", 2)
                    if len(parts) < 2 or not parts[0].startswith(b"HTTP/1.") or not parts[1].isdigit():
                        raise PolicyViolation("POLICY_FRAMING_REJECTED")
                    code = int(parts[1])
                    self.receipt.response(decision.phase, code)
                    if code not in decision.expected_statuses:
                        raise PolicyViolation("POLICY_STATUS_REJECTED")
                    no_body = current_method == b"HEAD" or code in (204, 304) or 100 <= code < 200
                    if decision.stream:
                        media = response_headers.get("content-type", "").split(";", 1)[0].strip().lower()
                        if media not in {"application/vnd.docker.raw-stream", "application/vnd.docker.multiplexed-stream"}:
                            raise PolicyViolation("POLICY_MEDIA_TYPE_REJECTED")
                        client_writer.write(response_head)
                        await client_writer.drain()
                        body_bytes = await _stream_response_body(upstream_reader, client_writer, response_headers)
                        self.policy.accept(decision, code, response_headers, None, body_bytes)
                    else:
                        raw_body, decoded_body, body_bytes = await _read_response_body(
                            upstream_reader, response_headers, no_body, MAX_CONTROL_RESPONSE
                        )
                        self.policy.accept(decision, code, response_headers, decoded_body, body_bytes)
                        client_writer.write(response_head + raw_body)
                        await client_writer.drain()
                    self.receipt.sync_policy(self.policy)
        except PolicyViolation as exc:
            if method_class(current_method) != "READ" and current_method:
                self.receipt.write_attempt()
            self.policy.failed = True
            self.policy.state = "FAILED"
            self.receipt.policy_violation(exc.code)
            self.receipt.sync_policy(self.policy)
        except (OSError, asyncio.IncompleteReadError):
            self.receipt.forwarding_error()
        finally:
            client_writer.close()
            if upstream_writer is not None:
                upstream_writer.close()
            await asyncio.gather(
                client_writer.wait_closed(),
                *([upstream_writer.wait_closed()] if upstream_writer is not None else []),
                return_exceptions=True,
            )
            if task is not None:
                self.tasks.discard(task)


def write_state(path: Path, result: dict[str, object]) -> None:
    rendered = format_state_lines(result).encode()
    temporary = path.with_suffix(path.suffix + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(rendered)
    os.replace(temporary, path)


async def async_main(args: argparse.Namespace) -> int:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for name in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(name, stop.set)
    receipt = Receipt()
    server: BoundaryServer
    try:
        if args.policy_fd is None:
            server = BoundaryServer(args.listen, args.upstream, receipt)
        else:
            policy = DBStartPolicy.from_fd(args.policy_fd)
            server = PolicyBoundaryServer(args.listen, args.upstream, receipt, policy)
        await server.run(stop, args.ready)
    except PolicyViolation as exc:
        receipt.policy_mode = "DB_START_V1"
        receipt.policy_descriptor_consumed = 1
        receipt.policy_matrix_sha256 = POLICY_MATRIX_SHA256
        receipt.policy_violation(exc.code)
    except (OSError, ValueError):
        receipt.forwarding_error()
    finally:
        for path in (args.listen, args.ready):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        write_state(args.state, receipt.sanitized())
    if receipt.write_attempt_count or receipt.policy_violation_count:
        return 2
    if receipt.policy_mode == "DB_START_V1" and not receipt.policy_complete:
        return 3
    return 1 if receipt.forwarding_error_count or receipt.parser_error_count else 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", required=True, type=Path)
    parser.add_argument("--upstream", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--ready", required=True, type=Path)
    parser.add_argument("--policy-fd", type=int)
    args = parser.parse_args()
    raise SystemExit(asyncio.run(async_main(args)))


if __name__ == "__main__":
    main()
