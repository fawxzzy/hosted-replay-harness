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
    "IMAGE_RESOLUTION_FAILED",
    "NETWORK_CONFIGURATION_REJECTED",
    "VOLUME_PREPARATION_FAILED",
    "CONTAINER_CREATE_FAILED",
    "CONTAINER_START_FAILED",
    "PORT_BIND_FAILED",
    "DATABASE_HEALTH_FAILED",
    "GOTRUE_MIGRATION_FAILED",
    "DOCKER_DAEMON_ERROR",
    UNKNOWN,
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
        "IMAGE_RESOLUTION_FAILED",
        (
            r"\bmanifest unknown\b",
            r"\bpull access denied\b",
            r"\bno such image\b",
            r"\b(?:unable|failed) to (?:find|pull|resolve) (?:the )?image\b",
        ),
    ),
    (
        "NETWORK_CONFIGURATION_REJECTED",
        (
            r"\bfailed to create (?:docker )?network\b",
            r"\bnetwork\b[^\r\n]{0,160}\b(?:not found|already exists|invalid)\b",
            r"\binvalid endpoint settings\b",
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
        "VOLUME_PREPARATION_FAILED",
        (
            r"\bfailed to parse docker volume\b",
            r"\bfailed to create volume\b",
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
        "CONTAINER_CREATE_FAILED",
        (
            r"\bfailed to create docker container\b",
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


def classify(raw: bytes, exit_code: int) -> dict[str, int | str]:
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
    result: dict[str, int | str] = {
        "category": category,
        "exit_code": exit_code,
        "match_count": len(matching_lines),
        "raw_byte_count": len(raw),
        "raw_line_count": len(raw.splitlines()),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
    }
    if matching_lines:
        result["first_match_line"] = matching_lines[0]
    return result


def format_state_lines(result: dict[str, int | str]) -> str:
    if result["category"] not in ALLOWED_CATEGORIES:
        raise ValueError("category is not allowlisted")
    fields = (
        ("supabase_cli.db_start_diagnostic.category", "str", result["category"]),
        ("supabase_cli.db_start_diagnostic.exit_code", "int", result["exit_code"]),
        ("supabase_cli.db_start_diagnostic.match_count", "int", result["match_count"]),
        ("supabase_cli.db_start_diagnostic.raw_byte_count", "int", result["raw_byte_count"]),
        ("supabase_cli.db_start_diagnostic.raw_line_count", "int", result["raw_line_count"]),
        ("supabase_cli.db_start_diagnostic.raw_sha256", "str", result["raw_sha256"]),
    )
    rendered = "".join(f"{key}\t{kind}\t{value}\n" for key, kind, value in fields)
    if "first_match_line" in result:
        rendered += (
            "supabase_cli.db_start_diagnostic.first_match_line\tint\t"
            f"{result['first_match_line']}\n"
        )
    return rendered


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--exit-code", required=True, type=int)
    args = parser.parse_args()
    raw = args.input.read_bytes()
    print(format_state_lines(classify(raw, args.exit_code)), end="")


if __name__ == "__main__":
    main()
