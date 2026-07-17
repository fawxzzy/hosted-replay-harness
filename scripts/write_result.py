#!/usr/bin/env python3
"""Build the only publishable smoke artifact from sanitized scalar state."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def set_nested(target: dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    current = target
    for part in parts[:-1]:
        current = current.setdefault(part, {})
    current[parts[-1]] = value


def decode(kind: str, value: str) -> Any:
    if kind == "int":
        return int(value)
    if kind == "float":
        return float(value)
    if kind == "bool":
        return value.lower() == "true"
    if kind == "json":
        return json.loads(value)
    return value


def read_state(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if not path.exists():
        return result
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        key, kind, value = line.split("\t", 2)
        set_nested(result, key, decode(kind, value))
    return result


def read_audit(path: Path) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line:
                entries.append(json.loads(line))

    roles: dict[str, int] = {}
    violations: set[str] = set()
    sanitized_entries: list[dict[str, Any]] = []
    for entry in entries:
        role = str(entry.get("role", "unknown"))
        roles[role] = roles.get(role, 0) + 1
        violations.update(str(item) for item in entry.get("violations", []))
        sanitized_entries.append(
            {
                "role": role,
                "container_id": entry.get("container_id"),
                "image_id": entry.get("image_id"),
                "command": entry.get("command", []),
                "network_ids": entry.get("network_ids", []),
                "published_db_binding": entry.get("published_db_binding"),
                "compliant": bool(entry.get("compliant", False)),
                "violations": sorted(str(item) for item in entry.get("violations", [])),
            }
        )
    return {
        "observations": len(entries),
        "roles": roles,
        "violation_codes": sorted(violations),
        "containers": sanitized_entries,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--audit", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--merge-existing", action="store_true")
    args = parser.parse_args()

    pins = json.loads((args.root / "pins.json").read_text(encoding="utf-8"))
    state = read_state(args.state)
    if args.merge_existing and args.output.exists():
        result = json.loads(args.output.read_text(encoding="utf-8"))
        status = state.pop("status", None)
        failure = state.pop("failure", None)
        if status is not None:
            result["status"] = status
            result["failure"] = None if status == "CONTAINMENT_SMOKE_PASS" else failure
        result.update(state)
        if args.audit.exists() and args.audit.stat().st_size:
            result["container_audit"] = read_audit(args.audit)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return

    status = state.pop("status", "BLOCKED")
    failure = state.pop(
        "failure", {"code": "HARNESS_RESULT_INCOMPLETE", "detail": "sanitized-state-missing"}
    )
    if status == "CONTAINMENT_SMOKE_PASS":
        failure = None
    result: dict[str, Any] = {
        "schema": "fawxzzy.hosted-replay-harness.result.v1",
        "packet": pins["packet"],
        "status": status,
        "failure": failure,
        "pins": pins,
        "source_contract": {
            "command": "supabase db start",
            "database_only": True,
            "gotrue_command": ["gotrue", "migrate"],
            "application_migrations_enabled": False,
            "seed_enabled": False,
        },
        "container_audit": read_audit(args.audit),
    }
    result.update(state)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
