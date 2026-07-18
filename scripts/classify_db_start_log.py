#!/usr/bin/env python3
"""Classify a transient Supabase DB-start log without emitting its contents."""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path
from typing import Final


UNKNOWN: Final = "UNKNOWN_SANITIZED"
ALLOWED_CATEGORIES: Final = (
    "CONFIG_VALIDATION_FAILED",
    "CLI_USAGE_ERROR",
    "DOCKER_CLIENT_API_NEGOTIATION_FAILED",
    "IMAGE_RESOLUTION_FAILED",
    "NETWORK_REUSE_ATTACHMENT_REJECTED",
    "NETWORK_CONFIGURATION_REJECTED",
    "VOLUME_CREATE_REJECTED",
    "VOLUME_PREPARATION_FAILED",
    "CONTAINER_CREATE_REJECTED",
    "CONTAINER_CREATE_FAILED",
    "CONTAINER_START_FAILED",
    "PORT_BIND_FAILED",
    "DATABASE_HEALTH_FAILED",
    "GOTRUE_MIGRATION_FAILED",
    "DOCKER_DAEMON_ERROR",
    UNKNOWN,
)

STATE_PREFIX: Final = "supabase_cli.db_start_diagnostic."
BASE_STATE_FIELDS: Final = {
    "category": ("str", r"^[A-Z0-9_]+$"),
    "exit_code": ("int", r"^[0-9]+$"),
    "match_count": ("int", r"^[0-9]+$"),
    "raw_byte_count": ("int", r"^[0-9]+$"),
    "raw_line_count": ("int", r"^[0-9]+$"),
    "raw_sha256": ("str", r"^[0-9a-f]{64}$"),
    "debug_enabled": ("bool", r"^(?:true|false)$"),
    "sensitive_shape_detected": ("bool", r"^(?:true|false)$"),
    "sensitive_shape_count": ("int", r"^[0-9]+$"),
}

SENSITIVE_PATTERNS: Final = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\b(?:postgres(?:ql)?|https?)://[^\s/:]+:[^\s/@]+@",
        r"\beyj[a-z0-9_-]{12,}\.[a-z0-9_-]{12,}(?:\.[a-z0-9_-]{8,})?\b",
        r"\bauthorization\s*:\s*bearer\s+\S+",
        r"\b(?:password|passwd|secret|token|api[_-]?key|jwt)(?:[_-][a-z0-9]+)*\s*[=:]\s*\S+",
        r"-----begin (?:rsa |ec |openssh )?private key-----",
    )
)

# Specific categories precede generic Docker daemon errors by design.
RULES: Final = (
    (
        "CONFIG_VALIDATION_FAILED",
        (
            r"\bfailed to (?:load|parse|validate) (?:the )?config(?:uration)?\b",
            r"\binvalid config(?:uration)?\b",
            r"\bconfig\.toml:.*\b(?:invalid|parse|validation)\b",
        ),
    ),
    (
        "CLI_USAGE_ERROR",
        (
            r"\bunknown (?:flag|command)\b",
            r"\baccepts? \d+ arg(?:ument)?s?\b",
            r"(?m)^usage:\s+supabase\b",
        ),
    ),
    (
        "DOCKER_CLIENT_API_NEGOTIATION_FAILED",
        (
            r"\bfailed to create docker cli(?:ent)?\b",
            r"\bfailed to initialize docker cli(?:ent)?\b",
            r"\bclient is newer than server\b",
            r"\bserver api version\b[^\r\n]{0,160}\b(?:unsupported|too old|mismatch)\b",
            r"\bdocker api\b[^\r\n]{0,160}\b(?:negotiat|version)\w*\b[^\r\n]{0,160}\b(?:fail|error|mismatch|unsupported)\w*\b",
        ),
    ),
    (
        "IMAGE_RESOLUTION_FAILED",
        (
            r"\bmanifest unknown\b",
            r"\bpull access denied\b",
            r"\bno such image\b",
            r"\bfailed to inspect docker image\b",
            r"\bfailed to pull docker image(?: from all registries)?\b",
            r"\breference does not match digest\b",
            r"\bimage\b[^\r\n]{0,160}\b(?:tag|digest|identity)\b[^\r\n]{0,160}\b(?:mismatch|invalid|unexpected)\b",
            r"\b(?:unable|failed) to (?:find|pull|resolve) (?:the )?image\b",
        ),
    ),
    (
        "NETWORK_REUSE_ATTACHMENT_REJECTED",
        (
            r"\bfailed to create (?:docker )?network\b",
            r"\binvalid endpoint settings\b",
            r"\bcould not attach to network\b",
            r"\bnetwork-scoped alias is supported only for containers in user defined networks\b",
        ),
    ),
    (
        "NETWORK_CONFIGURATION_REJECTED",
        (
            r"\bnetwork\b[^\r\n]{0,160}\b(?:not found|already exists|invalid)\b",
            r"\bpool overlaps with other one on this address space\b",
        ),
    ),
    (
        "PORT_BIND_FAILED",
        (
            r"\bport is already allocated\b",
            r"\baddress already in use\b",
            r"\bfailed to bind\b",
            r"\blisten tcp\b[^\r\n]{0,160}\bbind\b",
        ),
    ),
    (
        "VOLUME_CREATE_REJECTED",
        (r"\bfailed to create volume\b",),
    ),
    (
        "VOLUME_PREPARATION_FAILED",
        (
            r"\bfailed to parse docker volume\b",
        ),
    ),
    (
        "GOTRUE_MIGRATION_FAILED",
        (
            r"\bgotrue\b[^\r\n]{0,160}\bmigrat\w*\b[^\r\n]{0,160}\b(?:fail|error|exit)\w*\b",
            r"\b(?:fail|error)\w*\b[^\r\n]{0,160}\bgotrue\b[^\r\n]{0,160}\bmigrat\w*\b",
            r"\bauth migration\b[^\r\n]{0,160}\bfailed\b",
        ),
    ),
    (
        "DATABASE_HEALTH_FAILED",
        (
            r"\bdatabase\b[^\r\n]{0,160}\b(?:unhealthy|not healthy)\b",
            r"\btimed out waiting for\b[^\r\n]{0,160}\b(?:database|postgres)\b",
            r"\bhealth ?check\b[^\r\n]{0,160}\bfailed\b",
            r"\bfailed to connect to postgres\b",
            r"\bpostgres\b[^\r\n]{0,160}\bnot ready\b",
        ),
    ),
    (
        "CONTAINER_CREATE_REJECTED",
        (r"\bfailed to create docker container\b",),
    ),
    (
        "CONTAINER_CREATE_FAILED",
        (
            r"\bfailed to create (?:the )?container\b",
            r"\bcontainer name\b[^\r\n]{0,160}\balready in use\b",
            r"\binvalid mount config\b",
            r"\bcontainer create failed\b",
        ),
    ),
    (
        "CONTAINER_START_FAILED",
        (
            r"\bfailed to start docker container\b",
            r"\bcontainer start failed\b",
        ),
    ),
    (
        "DOCKER_DAEMON_ERROR",
        (
            r"\bcannot connect to the docker daemon\b",
            r"\bdocker daemon\b[^\r\n]{0,160}\b(?:not running|unavailable)\b",
            r"\berror response from daemon\b",
        ),
    ),
)


def count_sensitive_shapes(text: str) -> int:
    return sum(
        1
        for line in text.splitlines()
        if any(pattern.search(line) for pattern in SENSITIVE_PATTERNS)
    )


def classify(raw: bytes, exit_code: int, *, debug_enabled: bool = False) -> dict[str, bool | int | str]:
    text = raw.decode("utf-8", errors="replace").lower()
    category = UNKNOWN
    matching_lines: list[int] = []
    for candidate, patterns in RULES:
        matching_lines = [
            line_number
            for line_number, line in enumerate(text.splitlines(), start=1)
            if any(re.search(pattern, line) for pattern in patterns)
        ]
        if matching_lines:
            category = candidate
            break
    sensitive_shape_count = count_sensitive_shapes(text)
    result: dict[str, bool | int | str] = {
        "category": category,
        "exit_code": exit_code,
        "match_count": len(matching_lines),
        "raw_byte_count": len(raw),
        "raw_line_count": len(raw.splitlines()),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "debug_enabled": debug_enabled,
        "sensitive_shape_detected": sensitive_shape_count > 0,
        "sensitive_shape_count": sensitive_shape_count,
    }
    if matching_lines:
        result["first_match_line"] = matching_lines[0]
    return result


def validate_state_lines(rendered: str, *, has_first_match: bool) -> None:
    expected = dict(BASE_STATE_FIELDS)
    if has_first_match:
        expected["first_match_line"] = ("int", r"^[0-9]+$")
    observed: dict[str, tuple[str, str]] = {}
    for line in rendered.splitlines():
        if line.count("\t") != 2:
            raise ValueError("sanitized state line is malformed")
        key, kind, value = line.split("\t", 2)
        if not key.startswith(STATE_PREFIX):
            raise ValueError("sanitized state key is not allowlisted")
        field = key.removeprefix(STATE_PREFIX)
        if field in observed or field not in expected:
            raise ValueError("sanitized state field is not allowlisted")
        expected_kind, value_pattern = expected[field]
        if kind != expected_kind or re.fullmatch(value_pattern, value) is None:
            raise ValueError("sanitized state value is not allowlisted")
        observed[field] = (kind, value)
    if set(observed) != set(expected):
        raise ValueError("sanitized state fields are incomplete")
    if observed["category"][1] not in ALLOWED_CATEGORIES:
        raise ValueError("category is not allowlisted")


def format_state_lines(result: dict[str, bool | int | str]) -> str:
    if result["category"] not in ALLOWED_CATEGORIES:
        raise ValueError("category is not allowlisted")
    fields = (
        ("supabase_cli.db_start_diagnostic.category", "str", result["category"]),
        ("supabase_cli.db_start_diagnostic.exit_code", "int", result["exit_code"]),
        ("supabase_cli.db_start_diagnostic.match_count", "int", result["match_count"]),
        ("supabase_cli.db_start_diagnostic.raw_byte_count", "int", result["raw_byte_count"]),
        ("supabase_cli.db_start_diagnostic.raw_line_count", "int", result["raw_line_count"]),
        ("supabase_cli.db_start_diagnostic.raw_sha256", "str", result["raw_sha256"]),
        ("supabase_cli.db_start_diagnostic.debug_enabled", "bool", str(result["debug_enabled"]).lower()),
        (
            "supabase_cli.db_start_diagnostic.sensitive_shape_detected",
            "bool",
            str(result["sensitive_shape_detected"]).lower(),
        ),
        (
            "supabase_cli.db_start_diagnostic.sensitive_shape_count",
            "int",
            result["sensitive_shape_count"],
        ),
    )
    rendered = "".join(f"{key}\t{kind}\t{value}\n" for key, kind, value in fields)
    if "first_match_line" in result:
        rendered += (
            "supabase_cli.db_start_diagnostic.first_match_line\tint\t"
            f"{result['first_match_line']}\n"
        )
    validate_state_lines(rendered, has_first_match="first_match_line" in result)
    return rendered


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--exit-code", required=True, type=int)
    parser.add_argument("--debug-enabled", action="store_true")
    args = parser.parse_args()
    raw = args.input.read_bytes()
    print(
        format_state_lines(
            classify(raw, args.exit_code, debug_enabled=args.debug_enabled)
        ),
        end="",
    )


if __name__ == "__main__":
    main()
