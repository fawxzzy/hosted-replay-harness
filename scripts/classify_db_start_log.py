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
    "CLI_USAGE_ERROR",
    "CONFIG_LOAD_OR_VALIDATION_FAILED",
    "DOCKER_CLIENT_INITIALIZATION_FAILED",
    UNKNOWN,
)
NORMALIZATION_STATUSES: Final = (
    "PLAIN",
    "SGR_STRIPPED",
    "REJECTED_CONTROL",
    "INVALID_UTF8",
)
KNOWN_FINGERPRINT: Final = (
    1078,
    23,
    "d3a19bac055dc3fad0bca48c92d3cbe3d1d59ec9ac43d90829b5dd0c41545d31",
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
    "normalization_status": ("str", r"^(?:PLAIN|SGR_STRIPPED|REJECTED_CONTROL|INVALID_UTF8)$"),
    "sgr_count": ("int", r"^[0-9]+$"),
    "rejected_control_count": ("int", r"^[0-9]+$"),
    "matched_family_count": ("int", r"^[0-9]+$"),
    "known_fingerprint": ("bool", r"^(?:true|false)$"),
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

# These phrases are pinned to Cobra v1.10.2, pflag v1.0.10, and Supabase CLI
# source commit 6d4c19870ed213ba7f682f117d0345c8a40bfa94. No generic fallback is
# admitted: an unmatched or cross-family message remains UNKNOWN_SANITIZED.
RULES: Final = (
    (
        "CLI_USAGE_ERROR",
        (
            r'^unknown command "[^"]+" for "[^"]+"(?:.*)?$',
            r"^unknown flag: --[a-z0-9][a-z0-9_-]*$",
            r"^unknown shorthand flag: '.+' in -[a-z0-9]+$",
            r"^requires at least \d+ arg\(s\), only received \d+$",
            r"^accepts at most \d+ arg\(s\), received \d+$",
            r"^accepts \d+ arg\(s\), received \d+$",
            r"^accepts between \d+ and \d+ arg\(s\), received \d+$",
            r"^flag needs an argument: (?:--[a-z0-9][a-z0-9_-]*|'.+' in -[a-z0-9]+)$",
            r'^flag "[^"]+" does not exist$',
            r"^no such flag -[a-z0-9]+$",
        ),
    ),
    (
        "CONFIG_LOAD_OR_VALIDATION_FAILED",
        (
            r"^failed to get repo directory:",
            r"^failed to change directory:",
            r"^failed to parse environment file:",
            r"^failed to restore directory:",
            r"^failed to get working directory:",
            r"^failed to initialise config:",
            r"^failed to merge default values:",
            r"^failed to read file config:",
            r"^failed to merge file config:",
            r"^failed to merge remote config:",
            r"^failed to parse config:",
            r"^missing required field in config:",
            r"^invalid config for ",
            r"^failed reading config: invalid ",
            r"^duplicate project_id for \[remotes\.",
        ),
    ),
    (
        "DOCKER_CLIENT_INITIALIZATION_FAILED",
        (
            r"^failed to create docker client:",
            r"^failed to initialize docker client:",
        ),
    ),
)

SGR_PATTERN: Final = re.compile(rb"\x1b\[[0-9;:]*m")


def count_sensitive_shapes(text: str) -> int:
    return sum(
        1
        for line in text.splitlines()
        if any(pattern.search(line) for pattern in SENSITIVE_PATTERNS)
    )


def normalize(raw: bytes) -> tuple[str, str, int, int]:
    output = bytearray()
    sgr_count = 0
    rejected_control_count = 0
    index = 0
    while index < len(raw):
        value = raw[index]
        if value == 0x1B:
            match = SGR_PATTERN.match(raw, index)
            if match is None:
                rejected_control_count += 1
                index += 1
                continue
            sgr_count += 1
            index = match.end()
            continue
        if (value < 0x20 and value not in (0x09, 0x0A, 0x0D)) or value == 0x7F:
            rejected_control_count += 1
            index += 1
            continue
        output.append(value)
        index += 1

    try:
        text = output.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return "", "INVALID_UTF8", sgr_count, max(1, rejected_control_count)

    c1_count = sum(1 for character in text if 0x80 <= ord(character) <= 0x9F)
    rejected_control_count += c1_count
    if rejected_control_count:
        return "", "REJECTED_CONTROL", sgr_count, rejected_control_count

    text = text.replace("\r\n", "\n").replace("\r", "\n").lower()
    status = "SGR_STRIPPED" if sgr_count else "PLAIN"
    return text, status, sgr_count, 0


def classify_normalized(text: str) -> tuple[str, list[int], int]:
    family_matches: dict[str, list[int]] = {}
    lines = text.splitlines()
    for category, patterns in RULES:
        matching_lines = [
            line_number
            for line_number, line in enumerate(lines, start=1)
            if any(re.search(pattern, line) for pattern in patterns)
        ]
        if matching_lines:
            family_matches[category] = matching_lines
    if len(family_matches) != 1:
        return UNKNOWN, [], len(family_matches)
    category, matching_lines = next(iter(family_matches.items()))
    return category, matching_lines, 1


def is_known_fingerprint(byte_count: int, line_count: int, digest: str) -> bool:
    return (byte_count, line_count, digest) == KNOWN_FINGERPRINT


def classify(raw: bytes, exit_code: int, *, debug_enabled: bool = False) -> dict[str, bool | int | str]:
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    raw_line_count = len(raw.splitlines())
    text, normalization_status, sgr_count, rejected_control_count = normalize(raw)
    sensitive_text = raw.decode("utf-8", errors="ignore").lower()
    sensitive_shape_count = count_sensitive_shapes(sensitive_text)

    category = UNKNOWN
    matching_lines: list[int] = []
    matched_family_count = 0
    if normalization_status in ("PLAIN", "SGR_STRIPPED") and sensitive_shape_count == 0:
        category, matching_lines, matched_family_count = classify_normalized(text)

    result: dict[str, bool | int | str] = {
        "category": category,
        "exit_code": exit_code,
        "match_count": len(matching_lines),
        "raw_byte_count": len(raw),
        "raw_line_count": raw_line_count,
        "raw_sha256": raw_sha256,
        "debug_enabled": debug_enabled,
        "sensitive_shape_detected": sensitive_shape_count > 0,
        "sensitive_shape_count": sensitive_shape_count,
        "normalization_status": normalization_status,
        "sgr_count": sgr_count,
        "rejected_control_count": rejected_control_count,
        "matched_family_count": matched_family_count,
        "known_fingerprint": is_known_fingerprint(len(raw), raw_line_count, raw_sha256),
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
    if observed["normalization_status"][1] not in NORMALIZATION_STATUSES:
        raise ValueError("normalization status is not allowlisted")


def format_state_lines(result: dict[str, bool | int | str]) -> str:
    if result["category"] not in ALLOWED_CATEGORIES:
        raise ValueError("category is not allowlisted")
    fields = (
        ("category", "str", result["category"]),
        ("exit_code", "int", result["exit_code"]),
        ("match_count", "int", result["match_count"]),
        ("raw_byte_count", "int", result["raw_byte_count"]),
        ("raw_line_count", "int", result["raw_line_count"]),
        ("raw_sha256", "str", result["raw_sha256"]),
        ("debug_enabled", "bool", str(result["debug_enabled"]).lower()),
        ("sensitive_shape_detected", "bool", str(result["sensitive_shape_detected"]).lower()),
        ("sensitive_shape_count", "int", result["sensitive_shape_count"]),
        ("normalization_status", "str", result["normalization_status"]),
        ("sgr_count", "int", result["sgr_count"]),
        ("rejected_control_count", "int", result["rejected_control_count"]),
        ("matched_family_count", "int", result["matched_family_count"]),
        ("known_fingerprint", "bool", str(result["known_fingerprint"]).lower()),
    )
    rendered = "".join(
        f"{STATE_PREFIX}{field}\t{kind}\t{value}\n" for field, kind, value in fields
    )
    if "first_match_line" in result:
        rendered += (
            f"{STATE_PREFIX}first_match_line\tint\t{result['first_match_line']}\n"
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
