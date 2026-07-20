#!/usr/bin/env python3
"""Reduce bounded Docker event history to a secret-free lifecycle receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Final


PROJECT_LABEL: Final = "com.supabase.cli.project"
ALLOWED_CONTAINER_ACTIONS: Final = {"create", "start", "die", "destroy"}
ALLOWED_VOLUME_ACTIONS: Final = {"create"}
ALLOWED_NETWORK_ACTIONS: Final = {"connect"}
ALLOWED_CLASSIFICATIONS: Final = {
    "EVENT_HISTORY_CONSISTENT",
    "NO_DOCKER_MUTATION_OBSERVED",
    "OBSERVER_COVERAGE_GAP",
    "CONTAINER_CREATE_FAILED",
    "CONTAINER_CREATED_NOT_STARTED",
    "DATABASE_HEALTH_FAILED",
    "GOTRUE_MIGRATION_FAILED",
}


class EventHistoryError(ValueError):
    """Raised when event history is outside the frozen allowlist."""


def identity_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def set_digest(values: set[str]) -> str:
    payload = "\n".join(sorted(values)).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _read_json_lines(raw: bytes) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EventHistoryError("invalid event history") from exc
        if not isinstance(value, dict):
            raise EventHistoryError("invalid event record")
        entries.append(value)
    return entries


def _event_fields(event: dict[str, Any]) -> tuple[str, str, str, dict[str, str]]:
    event_type = str(event.get("Type", event.get("type", ""))).lower()
    action = str(event.get("Action", event.get("action", event.get("status", "")))).lower()
    actor = event.get("Actor", event.get("actor", {}))
    if not isinstance(actor, dict):
        raise EventHistoryError("invalid event actor")
    object_id = str(actor.get("ID", actor.get("id", event.get("id", ""))))
    raw_attributes = actor.get("Attributes", actor.get("attributes", {}))
    if not isinstance(raw_attributes, dict):
        raise EventHistoryError("invalid event attributes")
    attributes = {str(key): str(value) for key, value in raw_attributes.items()}
    if not event_type or not action or not object_id:
        raise EventHistoryError("incomplete event record")
    return event_type, action, object_id, attributes


def _role_for_image(
    image: str,
    postgres_references: set[str],
    gotrue_references: set[str],
) -> str | None:
    if image in postgres_references:
        return "database"
    if image in gotrue_references:
        return "gotrue_migration"
    return None


def _live_phase_ids(raw: bytes) -> tuple[set[str], set[str]]:
    create_ids: set[str] = set()
    start_ids: set[str] = set()
    for entry in _read_json_lines(raw):
        phase = str(entry.get("phase", ""))
        container_id = str(entry.get("container_id", ""))
        if phase not in {"create", "start"} or not container_id.startswith("sha256:"):
            raise EventHistoryError("invalid live observer record")
        if phase == "create":
            create_ids.add(container_id)
        else:
            start_ids.add(container_id)
    return create_ids, start_ids


def analyze(
    container_raw: bytes,
    volume_raw: bytes,
    network_raw: bytes,
    live_raw: bytes,
    *,
    project: str,
    network_name: str,
    network_id: str,
    db_volume: str,
    postgres_image: str,
    postgres_image_id: str,
    gotrue_image: str,
    gotrue_image_id: str,
) -> dict[str, int | str | bool]:
    container_events = _read_json_lines(container_raw)
    volume_events = _read_json_lines(volume_raw)
    network_events = _read_json_lines(network_raw)
    live_create_ids, live_start_ids = _live_phase_ids(live_raw)

    container_counts = {action: 0 for action in ALLOWED_CONTAINER_ACTIONS}
    volume_counts = {action: 0 for action in ALLOWED_VOLUME_ACTIONS}
    network_counts = {action: 0 for action in ALLOWED_NETWORK_ACTIONS}
    phase_ids = {action: set() for action in ALLOWED_CONTAINER_ACTIONS}
    volume_ids: set[str] = set()
    connected_ids: set[str] = set()
    roles: dict[str, str] = {}
    nonzero_database_exits = 0
    nonzero_gotrue_exits = 0
    pinned_images_correlated = True
    frozen_network_correlated = True

    postgres_references = {postgres_image, postgres_image_id}
    gotrue_references = {gotrue_image, gotrue_image_id}

    for event in container_events:
        event_type, action, object_id, attributes = _event_fields(event)
        if event_type != "container" or action not in ALLOWED_CONTAINER_ACTIONS:
            raise EventHistoryError("unexpected container event")
        if attributes.get(PROJECT_LABEL) != project:
            raise EventHistoryError("container project label mismatch")
        hashed_id = identity_digest(object_id)
        image = attributes.get("image", "")
        role = roles.get(hashed_id) or _role_for_image(
            image, postgres_references, gotrue_references
        )
        if role is None:
            pinned_images_correlated = False
        else:
            roles[hashed_id] = role
        container_counts[action] += 1
        phase_ids[action].add(hashed_id)
        if action == "die":
            try:
                exit_code = int(attributes.get("exitCode", attributes.get("exit_code", "0")))
            except ValueError as exc:
                raise EventHistoryError("invalid container exit status") from exc
            if exit_code != 0 and role == "database":
                nonzero_database_exits += 1
            elif exit_code != 0 and role == "gotrue_migration":
                nonzero_gotrue_exits += 1

    for event in volume_events:
        event_type, action, object_id, attributes = _event_fields(event)
        if event_type != "volume" or action not in ALLOWED_VOLUME_ACTIONS:
            raise EventHistoryError("unexpected volume event")
        if object_id != db_volume or attributes.get(PROJECT_LABEL) != project:
            raise EventHistoryError("volume identity mismatch")
        volume_counts[action] += 1
        volume_ids.add(identity_digest(object_id))

    for event in network_events:
        event_type, action, object_id, attributes = _event_fields(event)
        if event_type != "network" or action not in ALLOWED_NETWORK_ACTIONS:
            raise EventHistoryError("unexpected network event")
        if object_id != network_id or attributes.get("name") != network_name:
            frozen_network_correlated = False
        container_id = attributes.get("container", "")
        if not container_id:
            raise EventHistoryError("network event missing container identity")
        network_counts[action] += 1
        if action == "connect":
            connected_ids.add(identity_digest(container_id))

    history_create_ids = phase_ids["create"]
    history_start_ids = phase_ids["start"]
    observer_correlated = (
        history_create_ids == live_create_ids and history_start_ids == live_start_ids
    )
    if history_create_ids and not history_create_ids.issubset(connected_ids):
        frozen_network_correlated = False

    if not observer_correlated:
        classification = "OBSERVER_COVERAGE_GAP"
    elif volume_counts["create"] > 0 and container_counts["create"] == 0:
        classification = "CONTAINER_CREATE_FAILED"
    elif container_counts["create"] > container_counts["start"]:
        classification = "CONTAINER_CREATED_NOT_STARTED"
    elif nonzero_gotrue_exits > 0:
        classification = "GOTRUE_MIGRATION_FAILED"
    elif nonzero_database_exits > 0:
        classification = "DATABASE_HEALTH_FAILED"
    elif container_counts["create"] == 0 and volume_counts["create"] == 0:
        classification = "NO_DOCKER_MUTATION_OBSERVED"
    else:
        classification = "EVENT_HISTORY_CONSISTENT"

    if classification not in ALLOWED_CLASSIFICATIONS:
        raise EventHistoryError("classification is not allowlisted")

    combined_raw = container_raw + b"\0" + volume_raw + b"\0" + network_raw
    all_container_ids = set().union(*phase_ids.values())
    return {
        "classification": classification,
        "container_create_count": container_counts["create"],
        "container_start_count": container_counts["start"],
        "container_die_count": container_counts["die"],
        "container_destroy_count": container_counts["destroy"],
        "volume_create_count": volume_counts["create"],
        "network_connect_count": network_counts["connect"],
        "database_nonzero_exit_count": nonzero_database_exits,
        "gotrue_nonzero_exit_count": nonzero_gotrue_exits,
        "container_id_set_sha256": set_digest(all_container_ids),
        "volume_id_set_sha256": set_digest(volume_ids),
        "network_container_id_set_sha256": set_digest(connected_ids),
        "pinned_image_identity_correlated": pinned_images_correlated,
        "frozen_network_id_correlated": frozen_network_correlated,
        "live_observer_correlated": observer_correlated,
        "raw_byte_count": len(combined_raw),
        "raw_line_count": sum(
            len(raw.splitlines()) for raw in (container_raw, volume_raw, network_raw)
        ),
        "raw_sha256": hashlib.sha256(combined_raw).hexdigest(),
    }


def format_state_lines(result: dict[str, int | str | bool]) -> str:
    classification = str(result["classification"])
    if classification not in ALLOWED_CLASSIFICATIONS:
        raise EventHistoryError("classification is not allowlisted")
    lines: list[str] = []
    for key, value in result.items():
        kind = "bool" if isinstance(value, bool) else "int" if isinstance(value, int) else "str"
        lines.append(f"docker_event_history.{key}\t{kind}\t{str(value).lower() if isinstance(value, bool) else value}\n")
    return "".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--container-events", required=True, type=Path)
    parser.add_argument("--volume-events", required=True, type=Path)
    parser.add_argument("--network-events", required=True, type=Path)
    parser.add_argument("--live-audit", required=True, type=Path)
    parser.add_argument("--project", required=True)
    parser.add_argument("--network-name", required=True)
    parser.add_argument("--network-id", required=True)
    parser.add_argument("--db-volume", required=True)
    parser.add_argument("--postgres-image", required=True)
    parser.add_argument("--postgres-image-id", required=True)
    parser.add_argument("--gotrue-image", required=True)
    parser.add_argument("--gotrue-image-id", required=True)
    args = parser.parse_args()
    result = analyze(
        args.container_events.read_bytes(),
        args.volume_events.read_bytes(),
        args.network_events.read_bytes(),
        args.live_audit.read_bytes(),
        project=args.project,
        network_name=args.network_name,
        network_id=args.network_id,
        db_volume=args.db_volume,
        postgres_image=args.postgres_image,
        postgres_image_id=args.postgres_image_id,
        gotrue_image=args.gotrue_image,
        gotrue_image_id=args.gotrue_image_id,
    )
    print(format_state_lines(result), end="")


if __name__ == "__main__":
    main()
