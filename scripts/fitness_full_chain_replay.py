#!/usr/bin/env python3
"""Fail-closed, synthetic-only Fitness migration replay adapter.

The adapter stages immutable public Git objects before it touches the private
runtime. Runtime execution is intentionally unavailable unless a separately
provisioned JIT attestation and private Unix Docker socket satisfy the closed
contract. Subprocess output remains private and is never copied to receipts.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "fitness" / "contract.v1.json"
MANIFEST_PATH = ROOT / "fitness" / "source-manifest.v1.json"
CONFIG_PATH = ROOT / "supabase" / "config.toml"
FIXTURE_PATH = ROOT / "scripts" / "fitness_replay_fixture.sql"
PINS_PATH = ROOT / "pins.json"
ARTIFACT_PATH = ROOT / "artifacts" / "fitness-full-chain-replay.json"
SOURCE_ROOT = ROOT / ".fitness-replay-runtime"
WORKFLOW_PATH = ".github/workflows/fitness-full-chain-replay.yml"
ZERO_SHA256 = "0" * 64
PRIVATE_DATABASE_PORT = "56422"
SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MIGRATION_PATH = re.compile(r"^supabase/migrations/[0-9A-Za-z_]+\.sql$")
UNSAFE_KEY = re.compile(
    r"(?i)(email|discord|jwt|token|secret|password|database_?url|db_?uri|"
    r"profile_?id|user_?id|request_?body|raw_?log)"
)
UNSAFE_VALUE = re.compile(
    r"(?i)(postgres(?:ql)?://|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|"
    r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})"
)
TOP_LEVEL_KEYS = {
    "schema", "status", "failure_class", "adapter", "source", "migrations",
    "fixtures", "security", "containment", "cleanup", "timings", "receipt_sha256",
}
FAILURE_CLASSES = {
    "NONE", "ADAPTER_IDENTITY_MISMATCH", "SOURCE_STAGE_FAILED",
    "SOURCE_IDENTITY_MISMATCH", "SOURCE_MANIFEST_REJECTED",
    "PRIVATE_RUNTIME_UNAVAILABLE", "PRIVATE_RUNTIME_ATTESTATION_REJECTED",
    "LOCAL_DATABASE_START_FAILED", "MIGRATION_REPLAY_FAILED",
    "FIXTURE_PROOF_FAILED", "IMMUTABILITY_PROOF_FAILED",
    "PRIVILEGE_PROOF_FAILED", "IDEMPOTENCY_PROOF_FAILED",
    "CONTAINMENT_PROOF_FAILED", "CLEANUP_RESIDUE", "RECEIPT_REJECTED",
    "INTERNAL_ERROR",
}


class ReplayFailure(RuntimeError):
    def __init__(self, code: str):
        if code not in FAILURE_CLASSES - {"NONE"}:
            code = "INTERNAL_ERROR"
        super().__init__(code)
        self.code = code


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def parse_json_bytes(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=strict_object)


def read_json(path: Path) -> dict[str, Any]:
    value = parse_json_bytes(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("top-level object required")
    return value


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def remove_tree(path: Path) -> None:
    if path.is_symlink():
        raise OSError("symlinked packet root")

    def make_writable(function, name, _error):
        target = Path(name)
        target.chmod(target.stat().st_mode | stat.S_IWUSR)
        function(name)

    if path.exists():
        shutil.rmtree(path, onexc=make_writable)


def self_digest(value: dict[str, Any], field: str) -> str:
    payload = dict(value)
    payload.pop(field, None)
    return sha256_bytes(canonical_bytes(payload))


def run_command(
    command: list[str], *, input_bytes: bytes | None = None, timeout: float = 120,
    env: dict[str, str] | None = None, cwd: Path | None = None,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, timeout=timeout, env=env, cwd=cwd,
    )


def require_keys(value: dict[str, Any], keys: set[str]) -> None:
    if set(value) != keys:
        raise ValueError("closed schema mismatch")


def validate_private_database_publication(ports: Any) -> None:
    expected = {
        "5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": PRIVATE_DATABASE_PORT}],
    }
    if ports != expected:
        raise ValueError("publication")


def chain_digest(rows: list[dict[str, Any]]) -> str:
    payload = [
        {key: row[key] for key in ("path", "git_blob", "bytes", "sha256")}
        for row in rows
    ]
    # Key order is a versioned part of source-manifest.v1.
    return sha256_bytes(json.dumps(payload, separators=(",", ":")).encode())


def validate_manifest(manifest: dict[str, Any], contract: dict[str, Any]) -> None:
    require_keys(manifest, {"$schema", "$id", "repository", "base", "candidate", "delta", "migrations"})
    source = contract["source"]
    if manifest["repository"] != source["repository"]:
        raise ValueError("repository mismatch")
    for side in ("base", "candidate"):
        require_keys(manifest[side], {"commit", "tree", "migration_count", "chain_sha256"})
    expected_base = {
        "commit": source["base_commit"], "tree": source["base_tree"],
        "migration_count": source["base_migration_count"],
        "chain_sha256": source["base_chain_sha256"],
    }
    expected_candidate = {
        "commit": source["candidate_commit"], "tree": source["candidate_tree"],
        "migration_count": source["candidate_migration_count"],
        "chain_sha256": source["candidate_chain_sha256"],
    }
    if manifest["base"] != expected_base or manifest["candidate"] != expected_candidate:
        raise ValueError("commit or tree mismatch")
    rows = manifest["migrations"]
    if not isinstance(rows, list) or len(rows) != 102:
        raise ValueError("migration count mismatch")
    seen: set[str] = set()
    for index, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise ValueError("migration row type")
        require_keys(row, {"ordinal", "phase", "path", "git_blob", "bytes", "sha256"})
        if row["ordinal"] != index or row["phase"] != ("base" if index <= 101 else "candidate"):
            raise ValueError("migration ordering mismatch")
        if not isinstance(row["path"], str) or not MIGRATION_PATH.fullmatch(row["path"]):
            raise ValueError("migration path rejected")
        if row["path"] in seen or ".." in Path(row["path"]).parts:
            raise ValueError("duplicate or escaping path")
        seen.add(row["path"])
        if not isinstance(row["bytes"], int) or row["bytes"] <= 0:
            raise ValueError("migration size rejected")
        if not isinstance(row["git_blob"], str) or not SHA1.fullmatch(row["git_blob"]):
            raise ValueError("blob rejected")
        if not isinstance(row["sha256"], str) or not SHA256.fullmatch(row["sha256"]):
            raise ValueError("digest rejected")
    if rows != sorted(rows, key=lambda row: row["path"]):
        raise ValueError("path order mismatch")
    if chain_digest(rows[:101]) != source["base_chain_sha256"] or chain_digest(rows) != source["candidate_chain_sha256"]:
        raise ValueError("chain digest mismatch")
    delta = manifest["delta"]
    require_keys(delta, {"added_count", "historical_edit_count", "path", "git_blob", "bytes", "sha256"})
    expected_delta = {
        "added_count": 1, "historical_edit_count": 0,
        "path": source["candidate_path"], "git_blob": source["candidate_blob"],
        "bytes": source["candidate_bytes"], "sha256": source["candidate_sha256"],
    }
    if delta != expected_delta or rows[-1]["path"] != delta["path"]:
        raise ValueError("candidate delta mismatch")
    if sha256_file(MANIFEST_PATH) != source["source_manifest_sha256"]:
        raise ValueError("source manifest file mismatch")


def scan_receipt(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if UNSAFE_KEY.search(key):
                raise ValueError("unsafe receipt key")
            scan_receipt(child)
    elif isinstance(value, list):
        for child in value:
            scan_receipt(child)
    elif isinstance(value, str):
        if len(value) > 240 or any(ord(char) < 0x20 for char in value) or UNSAFE_VALUE.search(value):
            raise ValueError("unsafe receipt value")


def validate_receipt(receipt: dict[str, Any], manifest: dict[str, Any], contract: dict[str, Any]) -> None:
    require_keys(receipt, TOP_LEVEL_KEYS)
    scan_receipt(receipt)
    if receipt["schema"] != contract["receipt"]["schema"]:
        raise ValueError("receipt schema")
    if receipt["status"] not in {"PASS", "BLOCKED"} or receipt["failure_class"] not in FAILURE_CLASSES:
        raise ValueError("receipt disposition")
    if (receipt["status"] == "PASS") != (receipt["failure_class"] == "NONE"):
        raise ValueError("receipt status mismatch")
    if not isinstance(receipt["receipt_sha256"], str) or receipt["receipt_sha256"] != self_digest(receipt, "receipt_sha256"):
        raise ValueError("receipt digest")
    adapter = receipt["adapter"]
    require_keys(adapter, {"repository", "head", "tree", "workflow", "private_runtime_label"})
    if adapter["repository"] != contract["foundation"]["repository"] or adapter["workflow"] != WORKFLOW_PATH:
        raise ValueError("adapter identity")
    if not SHA1.fullmatch(adapter["head"]) or not SHA1.fullmatch(adapter["tree"]):
        raise ValueError("adapter hash")
    if adapter["private_runtime_label"] != contract["foundation"]["private_runtime_label"]:
        raise ValueError("runtime label")
    source = receipt["source"]
    expected_source = {
        "repository": contract["source"]["repository"],
        "base_commit": contract["source"]["base_commit"],
        "base_tree": contract["source"]["base_tree"],
        "candidate_commit": contract["source"]["candidate_commit"],
        "candidate_tree": contract["source"]["candidate_tree"],
        "base_count": 101, "candidate_count": 102,
        "base_chain_sha256": contract["source"]["base_chain_sha256"],
        "candidate_chain_sha256": contract["source"]["candidate_chain_sha256"],
        "candidate_delta_count": 1, "historical_edit_count": 0,
        "source_manifest_sha256": contract["source"]["source_manifest_sha256"],
        "staged_before_isolation": source.get("staged_before_isolation"),
        "network_closed_during_replay": source.get("network_closed_during_replay"),
    }
    if source != expected_source:
        raise ValueError("receipt source")
    migrations = receipt["migrations"]
    require_keys(migrations, {"ordered_count", "candidate_applied_count", "idempotency_rerun", "records_digest", "records"})
    records = migrations["records"]
    if not isinstance(records, list) or len(records) > 102:
        raise ValueError("receipt records")
    if migrations["ordered_count"] != len(records):
        raise ValueError("receipt record count")
    for index, record in enumerate(records, 1):
        require_keys(record, {"ordinal", "path", "sha256", "applied", "duration_ms"})
        if record["ordinal"] != index or record["path"] != manifest["migrations"][index - 1]["path"]:
            raise ValueError("receipt migration order")
        if record["sha256"] != manifest["migrations"][index - 1]["sha256"]:
            raise ValueError("receipt migration digest")
        if not isinstance(record["applied"], bool):
            raise ValueError("receipt migration applied")
        if not isinstance(record["duration_ms"], int) or not 0 <= record["duration_ms"] <= 120000:
            raise ValueError("receipt duration")
    records_payload = [{key: row[key] for key in ("ordinal", "path", "sha256", "applied")} for row in records]
    if migrations["records_digest"] != sha256_bytes(canonical_bytes(records_payload)):
        raise ValueError("receipt records digest")
    fixtures = receipt["fixtures"]
    fixture_keys = {
        "initial_humans", "initial_automations", "deleted_label", "deleted_gap_preserved",
        "concurrent_requested", "concurrent_succeeded", "concurrent_distinct",
        "concurrent_min", "concurrent_max", "prior_high_water", "post_high_water",
        "effective_next", "automation_null", "mapping_before_sha256",
        "mapping_after_delete_sha256", "mapping_final_sha256",
    }
    require_keys(fixtures, fixture_keys)
    if fixtures["initial_humans"] != 6 or fixtures["initial_automations"] != 1 or fixtures["deleted_label"] != "human-003" or fixtures["concurrent_requested"] != 8:
        raise ValueError("fixture denominator")
    for key in ("deleted_gap_preserved", "concurrent_distinct", "automation_null"):
        if not isinstance(fixtures[key], bool):
            raise ValueError("fixture boolean")
    for key in ("concurrent_succeeded", "concurrent_min", "concurrent_max", "prior_high_water", "post_high_water", "effective_next"):
        if not isinstance(fixtures[key], int) or fixtures[key] < 0:
            raise ValueError("fixture count")
    for key in ("mapping_before_sha256", "mapping_after_delete_sha256", "mapping_final_sha256"):
        if not isinstance(fixtures[key], str) or not SHA256.fullmatch(fixtures[key]):
            raise ValueError("fixture digest")
    security = receipt["security"]
    security_keys = {
        "same_value_update", "user_number_update_rejected", "user_kind_update_rejected",
        "assignment_timestamp_update_rejected", "public_sequence_privileges",
        "anon_sequence_privileges", "authenticated_sequence_privileges",
        "service_role_sequence_select_only", "allocate_attempt_rejected", "reset_attempt_rejected",
        "object_state_before_sha256", "object_state_after_sha256",
    }
    require_keys(security, security_keys)
    for key in security_keys - {"public_sequence_privileges", "anon_sequence_privileges", "authenticated_sequence_privileges", "object_state_before_sha256", "object_state_after_sha256"}:
        if not isinstance(security[key], bool):
            raise ValueError("security boolean")
    for key in ("public_sequence_privileges", "anon_sequence_privileges", "authenticated_sequence_privileges"):
        if security[key] != 0:
            raise ValueError("sequence privilege")
    for key in ("object_state_before_sha256", "object_state_after_sha256"):
        if not isinstance(security[key], str) or not SHA256.fullmatch(security[key]):
            raise ValueError("object digest")
    containment = receipt["containment"]
    containment_keys = {
        "runtime_attested", "private_docker_socket", "no_default_route", "same_network",
        "external_dns_failed", "literal_ip_failed", "metadata_failed", "host_failed",
        "registry_failed", "host_publication_count", "provider_contact_count",
    }
    require_keys(containment, containment_keys)
    for key in containment_keys - {"host_publication_count", "provider_contact_count"}:
        if not isinstance(containment[key], bool):
            raise ValueError("containment boolean")
    if containment["host_publication_count"] != 0 or containment["provider_contact_count"] != 0:
        raise ValueError("containment count")
    cleanup = receipt["cleanup"]
    required_cleanup = {
        "attempted", "succeeded", "containers_remaining", "volumes_remaining",
        "networks_remaining", "listeners_remaining", "source_entries_remaining",
        "runtime_residue_count", "foreign_objects_touched",
    }
    require_keys(cleanup, required_cleanup)
    for key in required_cleanup - {"attempted", "succeeded"}:
        if not isinstance(cleanup[key], int) or cleanup[key] < 0:
            raise ValueError("cleanup count")
    if not isinstance(cleanup["attempted"], bool) or not isinstance(cleanup["succeeded"], bool):
        raise ValueError("cleanup boolean")
    timings = receipt["timings"]
    timing_keys = {"source_stage_ms", "migration_ms", "proof_ms", "cleanup_ms", "total_ms"}
    require_keys(timings, timing_keys)
    for key in timing_keys:
        if not isinstance(timings[key], int) or timings[key] < 0:
            raise ValueError("timing")
    if receipt["status"] == "PASS":
        if not source["staged_before_isolation"] or not source["network_closed_during_replay"]:
            raise ValueError("source isolation proof")
        if migrations["ordered_count"] != 102 or migrations["candidate_applied_count"] != 1 or not migrations["idempotency_rerun"]:
            raise ValueError("migration acceptance")
        if not all(record["applied"] is True for record in records):
            raise ValueError("migration application acceptance")
        if not cleanup["attempted"] or not cleanup["succeeded"] or any(cleanup[key] != 0 for key in required_cleanup - {"attempted", "succeeded"}):
            raise ValueError("cleanup acceptance")
        if not all(value is True for value in containment.values() if isinstance(value, bool)):
            raise ValueError("containment acceptance")
        if not all(security[key] is True for key in security_keys if isinstance(security[key], bool)):
            raise ValueError("security acceptance")
        if not fixtures["deleted_gap_preserved"] or fixtures["concurrent_succeeded"] != 8 or not fixtures["concurrent_distinct"] or not fixtures["automation_null"]:
            raise ValueError("fixture acceptance")
        if fixtures["concurrent_min"] <= fixtures["prior_high_water"] or fixtures["effective_next"] <= fixtures["post_high_water"]:
            raise ValueError("allocator acceptance")
        if security["object_state_before_sha256"] != security["object_state_after_sha256"]:
            raise ValueError("idempotency acceptance")


def git_object(repo: Path, args: list[str], *, input_bytes: bytes | None = None, timeout: float = 120) -> bytes:
    result = run_command(["git", "-C", str(repo), *args], input_bytes=input_bytes, timeout=timeout)
    if result.returncode != 0:
        raise ReplayFailure("SOURCE_STAGE_FAILED")
    return result.stdout


def commit_tree(repo: Path, commit: str) -> str:
    raw = git_object(repo, ["cat-file", "-p", commit]).decode("ascii", "strict")
    first = raw.splitlines()[0]
    if not first.startswith("tree ") or not SHA1.fullmatch(first[5:]):
        raise ReplayFailure("SOURCE_IDENTITY_MISMATCH")
    return first[5:]


def migration_tree_rows(repo: Path, tree: str) -> list[tuple[str, str, int]]:
    raw = git_object(repo, ["ls-tree", "-r", "-l", "-z", tree, "--", "supabase/migrations"])
    rows: list[tuple[str, str, int]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, encoded_path = record.split(b"\t", 1)
            mode, object_type, object_id, size = metadata.decode("ascii", "strict").split()
            path = encoded_path.decode("utf-8", "strict")
        except (ValueError, UnicodeError):
            raise ReplayFailure("SOURCE_IDENTITY_MISMATCH") from None
        if mode != "100644" or object_type != "blob" or not SHA1.fullmatch(object_id):
            raise ReplayFailure("SOURCE_IDENTITY_MISMATCH")
        if not MIGRATION_PATH.fullmatch(path) or not size.isdecimal():
            raise ReplayFailure("SOURCE_IDENTITY_MISMATCH")
        rows.append((path, object_id, int(size)))
    return sorted(rows)


def stage_source(root: Path, manifest: dict[str, Any], contract: dict[str, Any]) -> Path:
    if sha256_file(CONFIG_PATH) != "1b955c23161259dd41f3849f261bab41525b5ffeca83ab3074e44c5cc18ac0c6":
        raise ReplayFailure("SOURCE_MANIFEST_REJECTED")
    if root.exists() or root.is_symlink():
        raise ReplayFailure("SOURCE_STAGE_FAILED")
    root.parent.mkdir(parents=True, exist_ok=True)
    root.mkdir(mode=0o700)
    bare = root / "objects.git"
    project = root / "project"
    migrations_root = project / "supabase" / "migrations"
    bare.mkdir(mode=0o700)
    result = run_command(["git", "-C", str(bare), "init", "--bare", "--quiet"], timeout=20)
    if result.returncode != 0:
        raise ReplayFailure("SOURCE_STAGE_FAILED")
    source = contract["source"]
    remote = f"https://github.com/{source['repository']}.git"
    for commit in (source["base_commit"], source["candidate_commit"]):
        fetched = run_command(
            ["git", "-C", str(bare), "fetch", "--quiet", "--no-tags", "--depth=1", remote, commit],
            timeout=180,
        )
        if fetched.returncode != 0:
            raise ReplayFailure("SOURCE_STAGE_FAILED")
    if commit_tree(bare, source["base_commit"]) != source["base_tree"]:
        raise ReplayFailure("SOURCE_IDENTITY_MISMATCH")
    if commit_tree(bare, source["candidate_commit"]) != source["candidate_tree"]:
        raise ReplayFailure("SOURCE_IDENTITY_MISMATCH")
    expected_base = sorted((row["path"], row["git_blob"], row["bytes"]) for row in manifest["migrations"][:101])
    expected_candidate = sorted((row["path"], row["git_blob"], row["bytes"]) for row in manifest["migrations"])
    if migration_tree_rows(bare, source["base_tree"]) != expected_base:
        raise ReplayFailure("SOURCE_IDENTITY_MISMATCH")
    if migration_tree_rows(bare, source["candidate_tree"]) != expected_candidate:
        raise ReplayFailure("SOURCE_IDENTITY_MISMATCH")
    migrations_root.mkdir(parents=True, mode=0o700)
    for row in manifest["migrations"]:
        object_type = git_object(bare, ["cat-file", "-t", row["git_blob"]]).decode("ascii", "strict").strip()
        if object_type != "blob":
            raise ReplayFailure("SOURCE_IDENTITY_MISMATCH")
        raw = git_object(bare, ["cat-file", "blob", row["git_blob"]])
        if len(raw) != row["bytes"] or sha256_bytes(raw) != row["sha256"]:
            raise ReplayFailure("SOURCE_IDENTITY_MISMATCH")
        relative = Path(row["path"]).relative_to("supabase/migrations")
        if len(relative.parts) != 1:
            raise ReplayFailure("SOURCE_MANIFEST_REJECTED")
        destination = migrations_root / relative
        destination.write_bytes(raw)
        destination.chmod(stat.S_IRUSR)
    config_target = project / "supabase" / "config.toml"
    config_target.write_bytes(CONFIG_PATH.read_bytes())
    config_target.chmod(stat.S_IRUSR)
    actual = sorted(path.name for path in migrations_root.iterdir() if path.is_file() and not path.is_symlink())
    expected = [Path(row["path"]).name for row in manifest["migrations"]]
    if actual != expected or any(path.is_symlink() for path in root.rglob("*")):
        raise ReplayFailure("SOURCE_STAGE_FAILED")
    remove_tree(bare)
    return project


def mapping_digest(rows: Iterable[tuple[str, str, int | None, bool]]) -> str:
    normalized = []
    for label, kind, number, timestamp_present in rows:
        if not re.fullmatch(r"(?:human(?:-concurrent)?-[0-9]{3}|automation-[0-9]{3})", label):
            raise ValueError("fixture label")
        if kind not in {"human", "automation"} or (number is not None and (not isinstance(number, int) or number < 0)):
            raise ValueError("fixture mapping")
        if not isinstance(timestamp_present, bool):
            raise ValueError("fixture timestamp")
        normalized.append([label, kind, number, timestamp_present])
    normalized.sort(key=lambda row: row[0])
    return sha256_bytes(canonical_bytes(normalized))


def default_receipt(contract: dict[str, Any], adapter_head: str, adapter_tree: str) -> dict[str, Any]:
    source = contract["source"]
    return {
        "schema": contract["receipt"]["schema"], "status": "BLOCKED", "failure_class": "INTERNAL_ERROR",
        "adapter": {
            "repository": contract["foundation"]["repository"], "head": adapter_head,
            "tree": adapter_tree, "workflow": WORKFLOW_PATH,
            "private_runtime_label": contract["foundation"]["private_runtime_label"],
        },
        "source": {
            "repository": source["repository"], "base_commit": source["base_commit"], "base_tree": source["base_tree"],
            "candidate_commit": source["candidate_commit"], "candidate_tree": source["candidate_tree"],
            "base_count": 101, "candidate_count": 102,
            "base_chain_sha256": source["base_chain_sha256"], "candidate_chain_sha256": source["candidate_chain_sha256"],
            "candidate_delta_count": 1, "historical_edit_count": 0,
            "source_manifest_sha256": source["source_manifest_sha256"],
            "staged_before_isolation": False, "network_closed_during_replay": False,
        },
        "migrations": {"ordered_count": 0, "candidate_applied_count": 0, "idempotency_rerun": False, "records_digest": sha256_bytes(b"[]"), "records": []},
        "fixtures": {
            "initial_humans": 6, "initial_automations": 1, "deleted_label": "human-003",
            "deleted_gap_preserved": False, "concurrent_requested": 8, "concurrent_succeeded": 0,
            "concurrent_distinct": False, "concurrent_min": 0, "concurrent_max": 0,
            "prior_high_water": 0, "post_high_water": 0, "effective_next": 0,
            "automation_null": False, "mapping_before_sha256": ZERO_SHA256,
            "mapping_after_delete_sha256": ZERO_SHA256, "mapping_final_sha256": ZERO_SHA256,
        },
        "security": {
            "same_value_update": False, "user_number_update_rejected": False,
            "user_kind_update_rejected": False, "assignment_timestamp_update_rejected": False,
            "public_sequence_privileges": 0, "anon_sequence_privileges": 0,
            "authenticated_sequence_privileges": 0, "service_role_sequence_select_only": False,
            "allocate_attempt_rejected": False, "reset_attempt_rejected": False,
            "object_state_before_sha256": ZERO_SHA256, "object_state_after_sha256": ZERO_SHA256,
        },
        "containment": {
            "runtime_attested": False, "private_docker_socket": False, "no_default_route": False,
            "same_network": False, "external_dns_failed": False, "literal_ip_failed": False,
            "metadata_failed": False, "host_failed": False, "registry_failed": False,
            "host_publication_count": 0, "provider_contact_count": 0,
        },
        "cleanup": {
            "attempted": False, "succeeded": False, "containers_remaining": 1,
            "volumes_remaining": 1, "networks_remaining": 1, "listeners_remaining": 1,
            "source_entries_remaining": 1, "runtime_residue_count": 1, "foreign_objects_touched": 0,
        },
        "timings": {"source_stage_ms": 0, "migration_ms": 0, "proof_ms": 0, "cleanup_ms": 0, "total_ms": 0},
        "receipt_sha256": ZERO_SHA256,
    }


def close_receipt(receipt: dict[str, Any]) -> None:
    records = receipt["migrations"]["records"]
    payload = [{key: row[key] for key in ("ordinal", "path", "sha256", "applied")} for row in records]
    receipt["migrations"]["ordered_count"] = len(records)
    receipt["migrations"]["records_digest"] = sha256_bytes(canonical_bytes(payload))
    receipt["receipt_sha256"] = self_digest(receipt, "receipt_sha256")


class PrivateRuntime:
    """Exact private-runtime interface. No host Docker fallback exists."""

    def __init__(self, contract: dict[str, Any], receipt: dict[str, Any]):
        self.contract = contract
        self.receipt = receipt
        self.docker_host = contract["foundation"]["docker_host"]
        self.socket = Path(self.docker_host.removeprefix("unix://"))
        self.cli_observer_host = contract["foundation"]["cli_observer_host"]
        self.cli_observer_socket = Path(self.cli_observer_host.removeprefix("unix://"))
        self.attestation_path = Path(contract["foundation"]["runtime_attestation"])
        self.env = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": str(SOURCE_ROOT / "home"), "DOCKER_HOST": self.docker_host,
            "DO_NOT_TRACK": "1",
        }
        self.project_id = contract["replay"]["project_id"]
        self.network_name = contract["replay"]["network_name"]
        self.db_name = f"supabase_db_{self.project_id}"
        self.owned_ids: list[str] = []

    @property
    def docker(self) -> list[str]:
        return ["docker", "--host", self.docker_host]

    def attest(self) -> None:
        if self.docker_host == "unix:///var/run/docker.sock" or not self.socket.is_socket():
            raise ReplayFailure("PRIVATE_RUNTIME_UNAVAILABLE")
        try:
            value = read_json(self.attestation_path)
            require_keys(value, {"schema", "label", "docker_host", "cli_observer_host", "observer_sha256", "observer_policy", "network_closed", "no_provider_credentials", "packet_vm", "exclusive_daemon", "images", "attestation_sha256"})
            if value["schema"] != "fawxzzy.hosted-replay.jit-attestation.v1":
                raise ValueError("schema")
            if (value["label"] != self.contract["foundation"]["private_runtime_label"]
                    or value["docker_host"] != self.docker_host
                    or value["cli_observer_host"] != self.cli_observer_host
                    or value["observer_sha256"] != self.contract["foundation"]["observer_sha256"]
                    or value["observer_policy"] != self.contract["foundation"]["observer_policy"]):
                raise ValueError("identity")
            if (value["network_closed"] is not True or value["no_provider_credentials"] is not True
                    or value["packet_vm"] is not True or value["exclusive_daemon"] is not True):
                raise ValueError("boundary")
            pins = read_json(PINS_PATH)["images"]
            expected_images = {"postgres": pins["postgres"]["digest"], "gotrue": pins["gotrue"]["digest"]}
            if value["images"] != expected_images:
                raise ValueError("images")
            if value["attestation_sha256"] != self_digest(value, "attestation_sha256"):
                raise ValueError("digest")
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            raise ReplayFailure("PRIVATE_RUNTIME_ATTESTATION_REJECTED") from None
        if not self.cli_observer_socket.is_socket():
            raise ReplayFailure("PRIVATE_RUNTIME_ATTESTATION_REJECTED")
        ping = run_command([*self.docker, "version", "--format", "{{.Server.Version}}"], env=self.env, timeout=15)
        if ping.returncode != 0 or not ping.stdout.strip() or ping.stderr:
            raise ReplayFailure("PRIVATE_RUNTIME_UNAVAILABLE")
        pins = read_json(PINS_PATH)["images"]
        for image in pins.values():
            reference = f"{image['tag'].split(':', 1)[0]}@{image['digest']}"
            inspected = run_command(
                [*self.docker, "image", "inspect", "--format", "{{.Id}}", reference],
                env=self.env, timeout=20,
            )
            if inspected.returncode != 0 or not re.fullmatch(rb"sha256:[0-9a-f]{64}\n?", inspected.stdout) or inspected.stderr:
                raise ReplayFailure("PRIVATE_RUNTIME_ATTESTATION_REJECTED")
        self.receipt["containment"]["runtime_attested"] = True
        self.receipt["containment"]["private_docker_socket"] = True
        self.receipt["containment"]["no_default_route"] = True

    def docker_command(self, args: list[str], *, input_bytes: bytes | None = None, timeout: float = 120) -> subprocess.CompletedProcess[bytes]:
        return run_command([*self.docker, *args], input_bytes=input_bytes, timeout=timeout, env=self.env)

    def psql(self, sql: bytes, *, expect_success: bool = True, timeout: float = 120) -> subprocess.CompletedProcess[bytes]:
        result = self.docker_command(
            ["exec", "-i", self.db_name, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres", "-qAt"],
            input_bytes=sql, timeout=timeout,
        )
        if expect_success != (result.returncode == 0):
            raise ReplayFailure("MIGRATION_REPLAY_FAILED" if expect_success else "IMMUTABILITY_PROOF_FAILED")
        return result

    def start_database(self, project: Path) -> None:
        cli = Path(self.contract["foundation"]["supabase_binary"])
        sidecar = Path(self.contract["foundation"]["supabase_sidecar"])
        pins = read_json(PINS_PATH)["supabase_cli"]["members"]
        expected = {member["name"]: member["sha256"] for member in pins}
        if not cli.is_file() or cli.is_symlink() or not sidecar.is_file() or sidecar.is_symlink():
            raise ReplayFailure("PRIVATE_RUNTIME_UNAVAILABLE")
        if sha256_file(cli) != expected["supabase"] or sha256_file(sidecar) != expected["supabase-go"]:
            raise ReplayFailure("PRIVATE_RUNTIME_ATTESTATION_REJECTED")
        created = self.docker_command([
            "network", "create", "--internal", "--ipv6=false",
            "--label", f"io.fawxzzy.packet={self.contract['replay']['packet_label']}",
            "--label", f"com.supabase.cli.project={self.project_id}",
            "--label", f"com.docker.compose.project={self.project_id}",
            self.network_name,
        ], timeout=30)
        if created.returncode != 0:
            raise ReplayFailure("LOCAL_DATABASE_START_FAILED")
        cli_env = dict(self.env)
        cli_env["HOME"] = str(SOURCE_ROOT / "home")
        cli_env["DOCKER_HOST"] = self.cli_observer_host
        started = run_command([
            str(cli), "--workdir", str(project), "--network-id", self.network_name,
            "--yes", "db", "start",
        ], timeout=180, env=cli_env)
        if started.returncode != 0:
            raise ReplayFailure("LOCAL_DATABASE_START_FAILED")
        inspected = self.docker_command(["inspect", self.db_name], timeout=20)
        if inspected.returncode != 0:
            raise ReplayFailure("LOCAL_DATABASE_START_FAILED")
        try:
            payload = parse_json_bytes(inspected.stdout)
            if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
                raise ValueError("inspect")
            obj = payload[0]
            container_id = obj.get("Id")
            labels = obj.get("Config", {}).get("Labels", {})
            networks = obj["NetworkSettings"]["Networks"]
            ports = obj["NetworkSettings"].get("Ports", {})
            if not isinstance(container_id, str) or not re.fullmatch(r"[0-9a-f]{64}", container_id):
                raise ValueError("identity")
            if not isinstance(labels, dict) or labels.get("com.supabase.cli.project") != self.project_id:
                raise ValueError("ownership")
            if set(networks) != {self.network_name}:
                raise ValueError("network")
            validate_private_database_publication(ports)
            self.owned_ids.append(container_id)
        except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError):
            raise ReplayFailure("CONTAINMENT_PROOF_FAILED") from None
        self.receipt["containment"]["same_network"] = True
        self.receipt["source"]["network_closed_during_replay"] = True

    def apply_migration(self, row: dict[str, Any], project: Path) -> dict[str, Any]:
        path = project / row["path"]
        started = time.monotonic()
        result = self.psql(path.read_bytes(), timeout=self.contract["replay"]["max_migration_seconds"])
        if result.stdout or result.stderr:
            # Migration output may contain object names or dynamic details; never retain it.
            pass
        duration = min(int((time.monotonic() - started) * 1000), 120000)
        return {"ordinal": row["ordinal"], "path": row["path"], "sha256": row["sha256"], "applied": True, "duration_ms": duration}

    def query_lines(self, sql: str) -> list[str]:
        result = self.psql(sql.encode())
        try:
            return result.stdout.decode("utf-8", "strict").splitlines()
        except UnicodeError:
            raise ReplayFailure("FIXTURE_PROOF_FAILED") from None

    def fixture_mapping(self) -> list[tuple[str, str, int | None, bool]]:
        values = []
        for label, identity in synthetic_identities().items():
            values.append(f"('{label}','{identity}'::uuid)")
        sql = (
            "WITH fixture(label,id) AS (VALUES " + ",".join(values) + ") "
            "SELECT fixture.label || '|' || p.user_kind || '|' || coalesce(p.user_number::text,'NULL') || '|' || "
            "(p.user_number_assigned_at IS NOT NULL)::text FROM fixture JOIN public.profiles p USING(id) ORDER BY fixture.label;"
        )
        rows = []
        for line in self.query_lines(sql):
            parts = line.split("|")
            if len(parts) != 4:
                raise ReplayFailure("FIXTURE_PROOF_FAILED")
            rows.append((parts[0], parts[1], None if parts[2] == "NULL" else int(parts[2]), parts[3] == "t"))
        return rows

    def object_state_digest(self) -> str:
        sql = (
            "SELECT coalesce(string_agg(definition,E'\\n' ORDER BY kind,name),'') FROM ("
            "SELECT 'function' kind, p.oid::regprocedure::text name, pg_get_functiondef(p.oid) definition "
            "FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' "
            "AND p.proname IN ('assign_real_user_number_on_profile_insert','enforce_immutable_profile_member_identity') "
            "UNION ALL SELECT 'trigger',tgname,pg_get_triggerdef(oid) FROM pg_trigger "
            "WHERE tgrelid='public.profiles'::regclass AND NOT tgisinternal "
            "AND tgname IN ('profiles_assign_real_user_number_before_insert','profiles_enforce_immutable_member_identity_before_update')) s;"
        )
        result = self.psql(sql.encode())
        return sha256_bytes(result.stdout)

    def run_proofs(self, project: Path, candidate: dict[str, Any]) -> None:
        self.psql(FIXTURE_PATH.read_bytes())
        before_candidate = self.fixture_mapping()
        if sorted(number for _, kind, number, _ in before_candidate if kind == "human") != list(range(6)):
            raise ReplayFailure("FIXTURE_PROOF_FAILED")
        if [(kind, number) for _, kind, number, _ in before_candidate if kind == "automation"] != [("automation", None)]:
            raise ReplayFailure("FIXTURE_PROOF_FAILED")
        self.receipt["fixtures"]["mapping_before_sha256"] = mapping_digest(before_candidate)
        self.receipt["fixtures"]["automation_null"] = True
        self.receipt["migrations"]["records"].append(self.apply_migration(candidate, project))
        self.receipt["migrations"]["candidate_applied_count"] = 1
        state_before = self.object_state_digest()
        self.receipt["security"]["object_state_before_sha256"] = state_before
        high = int(self.query_lines("SELECT max(user_number)::text FROM public.profiles WHERE user_number IS NOT NULL;")[0])
        self.receipt["fixtures"]["prior_high_water"] = high
        self.psql(b"DELETE FROM public.profiles WHERE id='f1000000-0000-4000-8000-000000000003'::uuid;")
        after_delete = self.fixture_mapping()
        self.receipt["fixtures"]["mapping_after_delete_sha256"] = mapping_digest(after_delete)
        self.receipt["fixtures"]["deleted_gap_preserved"] = not any(label == "human-003" for label, *_ in after_delete) and not any(number == 3 for _, _, number, _ in after_delete)
        insert_sql = concurrent_insert_sql()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(self.psql, sql.encode(), timeout=30) for sql in insert_sql]
            for future in futures:
                future.result()
        final_rows = self.fixture_mapping()
        concurrent_numbers = [number for label, kind, number, _ in final_rows if label.startswith("human-concurrent-") and kind == "human" and number is not None]
        self.receipt["fixtures"]["concurrent_succeeded"] = len(concurrent_numbers)
        self.receipt["fixtures"]["concurrent_distinct"] = len(set(concurrent_numbers)) == 8
        self.receipt["fixtures"]["concurrent_min"] = min(concurrent_numbers, default=0)
        self.receipt["fixtures"]["concurrent_max"] = max(concurrent_numbers, default=0)
        self.receipt["fixtures"]["post_high_water"] = max((number or 0 for _, _, number, _ in final_rows), default=0)
        seq = self.query_lines("SELECT CASE WHEN is_called THEN last_value + 1 ELSE last_value END::text FROM public.real_user_number_seq;")
        self.receipt["fixtures"]["effective_next"] = int(seq[0])
        self.receipt["fixtures"]["mapping_final_sha256"] = mapping_digest(final_rows)
        if len(concurrent_numbers) != 8 or len(set(concurrent_numbers)) != 8 or min(concurrent_numbers) <= high:
            raise ReplayFailure("FIXTURE_PROOF_FAILED")
        automation = [row for row in final_rows if row[0] == "automation-000"]
        if len(automation) != 1 or automation[0][2] is not None:
            raise ReplayFailure("FIXTURE_PROOF_FAILED")
        self.receipt["security"]["same_value_update"] = self.psql(
            b"UPDATE public.profiles SET user_number=user_number,user_kind=user_kind,user_number_assigned_at=user_number_assigned_at WHERE id='f1000000-0000-4000-8000-000000000001'::uuid;"
        ).returncode == 0
        negative = {
            "user_number_update_rejected": b"UPDATE public.profiles SET user_number=user_number+1 WHERE id='f1000000-0000-4000-8000-000000000001'::uuid;",
            "user_kind_update_rejected": b"UPDATE public.profiles SET user_kind='automation' WHERE id='f1000000-0000-4000-8000-000000000001'::uuid;",
            "assignment_timestamp_update_rejected": b"UPDATE public.profiles SET user_number_assigned_at=clock_timestamp() WHERE id='f1000000-0000-4000-8000-000000000001'::uuid;",
            "allocate_attempt_rejected": b"SET ROLE anon; SELECT nextval('public.real_user_number_seq');",
            "reset_attempt_rejected": b"SET ROLE authenticated; SELECT setval('public.real_user_number_seq',1,false);",
        }
        for key, sql in negative.items():
            self.receipt["security"][key] = self.psql(sql, expect_success=False).returncode != 0
        privilege = self.query_lines(
            "SELECT rolname || '|' || has_sequence_privilege(rolname,'public.real_user_number_seq','USAGE')::text || '|' || "
            "has_sequence_privilege(rolname,'public.real_user_number_seq','UPDATE')::text || '|' || "
            "has_sequence_privilege(rolname,'public.real_user_number_seq','SELECT')::text FROM pg_roles "
            "WHERE rolname IN ('anon','authenticated','service_role') ORDER BY rolname;"
        )
        parsed = {line.split("|")[0]: line.split("|")[1:] for line in privilege}
        if parsed.get("anon") != ["f", "f", "f"] or parsed.get("authenticated") != ["f", "f", "f"] or parsed.get("service_role") != ["f", "f", "t"]:
            raise ReplayFailure("PRIVILEGE_PROOF_FAILED")
        public_count = self.query_lines(
            "SELECT count(*)::text FROM pg_class c LEFT JOIN LATERAL "
            "aclexplode(coalesce(c.relacl,acldefault('S',c.relowner))) a ON true "
            "WHERE c.oid='public.real_user_number_seq'::regclass AND a.grantee=0;"
        )
        if public_count != ["0"]:
            raise ReplayFailure("PRIVILEGE_PROOF_FAILED")
        self.receipt["security"]["public_sequence_privileges"] = 0
        self.receipt["security"]["anon_sequence_privileges"] = 0
        self.receipt["security"]["authenticated_sequence_privileges"] = 0
        self.receipt["security"]["service_role_sequence_select_only"] = True
        self.apply_migration(candidate, project)
        self.receipt["migrations"]["idempotency_rerun"] = True
        state_after = self.object_state_digest()
        self.receipt["security"]["object_state_after_sha256"] = state_after
        if state_before != state_after or mapping_digest(self.fixture_mapping()) != self.receipt["fixtures"]["mapping_final_sha256"]:
            raise ReplayFailure("IDEMPOTENCY_PROOF_FAILED")

    def network_canaries(self) -> None:
        # The separately attested private runtime has no default route. These fixed
        # canaries still prove attempts execute and fail; no command text is retained.
        canaries = [
            ("external_dns_failed", "timeout 5 getent ahostsv4 example.com", {2, 124}),
            ("literal_ip_failed", "timeout 3 bash -c '</dev/tcp/1.1.1.1/443'", {1, 124}),
            ("metadata_failed", "timeout 3 bash -c '</dev/tcp/169.254.169.254/80'", {1, 124}),
            ("host_failed", "timeout 3 bash -c '</dev/tcp/172.17.0.1/80'", {1, 124}),
            ("registry_failed", "timeout 5 bash -c '</dev/tcp/registry-1.docker.io/443'", {1, 124}),
        ]
        for key, command, accepted in canaries:
            script = "printf 'ATTEMPTED\\n';set +e;" + command + ">/dev/null 2>&1;r=$?;set -e;printf 'RESULT:%s\\n' \"$r\""
            result = self.docker_command(["exec", self.db_name, "bash", "-ceu", script], timeout=10)
            match = re.fullmatch(rb"ATTEMPTED\nRESULT:([0-9]{1,3})\n", result.stdout)
            if result.returncode != 0 or result.stderr or match is None or int(match.group(1)) not in accepted:
                raise ReplayFailure("CONTAINMENT_PROOF_FAILED")
            self.receipt["containment"][key] = True

    def cleanup(self) -> bool:
        self.receipt["cleanup"]["attempted"] = True
        ok = True
        packet = self.contract["replay"]["packet_label"]
        filters = {
            "container": f"label=com.supabase.cli.project={self.project_id}",
            "volume": f"label=com.supabase.cli.project={self.project_id}",
            "network": f"label=io.fawxzzy.packet={packet}",
        }
        for object_type in ("container", "volume", "network"):
            list_flags = ["ls", "-aq"] if object_type == "container" else ["ls", "-q"]
            listed = self.docker_command([object_type, *list_flags, "--filter", filters[object_type]], timeout=20)
            if listed.returncode != 0:
                ok = False
                continue
            identities = [line.decode("ascii", "strict") for line in listed.stdout.splitlines() if line]
            if len(identities) != len(set(identities)) or any(not re.fullmatch(r"[0-9a-f]{12,64}", item) for item in identities):
                ok = False
                continue
            for identity in identities:
                action = ["rm", "-f"] if object_type == "container" else ["rm"]
                removed = self.docker_command([object_type, *action, identity], timeout=30)
                ok = ok and removed.returncode == 0
        counts: dict[str, int] = {}
        for object_type, key in (("container", "containers_remaining"), ("volume", "volumes_remaining"), ("network", "networks_remaining")):
            list_flags = ["ls", "-aq"] if object_type == "container" else ["ls", "-q"]
            listed = self.docker_command([object_type, *list_flags, "--filter", filters[object_type]], timeout=20)
            if listed.returncode != 0:
                counts[key] = 1
                ok = False
            else:
                counts[key] = len([line for line in listed.stdout.splitlines() if line])
                ok = ok and counts[key] == 0
        self.receipt["cleanup"].update(counts)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(("127.0.0.1", int(PRIVATE_DATABASE_PORT)))
            listener_count = 0
        except OSError:
            listener_count = 1
        self.receipt["cleanup"]["listeners_remaining"] = listener_count
        all_containers = self.docker_command(["container", "ls", "-aq"], timeout=20)
        all_volumes = self.docker_command(["volume", "ls", "-q"], timeout=20)
        all_networks = self.docker_command(["network", "ls", "--format", "{{.Name}}"], timeout=20)
        if any(result.returncode != 0 for result in (all_containers, all_volumes, all_networks)):
            private_residue = 1
            ok = False
        else:
            container_count = len([line for line in all_containers.stdout.splitlines() if line])
            volume_count = len([line for line in all_volumes.stdout.splitlines() if line])
            try:
                network_names = {line.decode("ascii", "strict") for line in all_networks.stdout.splitlines() if line}
            except UnicodeError:
                network_names = {"INVALID"}
            extra_network_count = len(network_names - {"bridge", "host", "none"})
            private_residue = container_count + volume_count + extra_network_count
            ok = ok and private_residue == 0
        self.receipt["cleanup"]["runtime_residue_count"] = private_residue
        ok = ok and listener_count == 0
        return ok


def synthetic_identities() -> dict[str, str]:
    result = {f"human-{index:03d}": f"f1000000-0000-4000-8000-{index:012d}" for index in range(6)}
    result["automation-000"] = "fa000000-0000-4000-8000-000000000000"
    result.update({f"human-concurrent-{index:03d}": f"f2000000-0000-4000-8000-{index:012d}" for index in range(8)})
    return result


def concurrent_insert_sql() -> list[str]:
    statements = []
    for index in range(8):
        identity = synthetic_identities()[f"human-concurrent-{index:03d}"]
        statements.append(
            "BEGIN; INSERT INTO auth.users (id,instance_id,aud,role,raw_app_meta_data,raw_user_meta_data,created_at,updated_at) "
            f"VALUES ('{identity}'::uuid,'00000000-0000-0000-0000-000000000000'::uuid,'authenticated','authenticated',"
            "'{\"provider\":\"synthetic\"}'::jsonb,'{}'::jsonb,clock_timestamp(),clock_timestamp()); "
            f"INSERT INTO public.profiles(id) VALUES ('{identity}'::uuid); COMMIT;"
        )
    return statements


def adapter_identity(expected_head: str) -> tuple[str, str]:
    head = run_command(["git", "-C", str(ROOT), "rev-parse", "HEAD"], timeout=10)
    tree = run_command(["git", "-C", str(ROOT), "rev-parse", "HEAD^{tree}"], timeout=10)
    if head.returncode or tree.returncode:
        raise ReplayFailure("ADAPTER_IDENTITY_MISMATCH")
    actual_head = head.stdout.decode("ascii", "strict").strip()
    actual_tree = tree.stdout.decode("ascii", "strict").strip()
    if actual_head != expected_head or not SHA1.fullmatch(actual_tree):
        raise ReplayFailure("ADAPTER_IDENTITY_MISMATCH")
    return actual_head, actual_tree


def source_only_check() -> int:
    try:
        contract = read_json(CONTRACT_PATH)
        manifest = read_json(MANIFEST_PATH)
        validate_manifest(manifest, contract)
        if sha256_file(CONFIG_PATH) != "1b955c23161259dd41f3849f261bab41525b5ffeca83ab3074e44c5cc18ac0c6":
            return 1
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "stage"
            project = stage_source(root, manifest, contract)
            if len(list((project / "supabase" / "migrations").glob("*.sql"))) != 102:
                return 1
            remove_tree(root)
        return 0
    except (OSError, ValueError, UnicodeError, ReplayFailure, subprocess.TimeoutExpired):
        return 1


def execute(expected_head: str) -> int:
    total_started = time.monotonic()
    contract = read_json(CONTRACT_PATH)
    manifest = read_json(MANIFEST_PATH)
    validate_manifest(manifest, contract)
    head, tree = adapter_identity(expected_head)
    receipt = default_receipt(contract, head, tree)
    failure = "NONE"
    runtime: PrivateRuntime | None = None
    try:
        stage_started = time.monotonic()
        project = stage_source(SOURCE_ROOT, manifest, contract)
        receipt["timings"]["source_stage_ms"] = int((time.monotonic() - stage_started) * 1000)
        receipt["source"]["staged_before_isolation"] = True
        runtime = PrivateRuntime(contract, receipt)
        runtime.attest()
        migration_started = time.monotonic()
        runtime.start_database(project)
        for row in manifest["migrations"][:101]:
            receipt["migrations"]["records"].append(runtime.apply_migration(row, project))
        proof_started = time.monotonic()
        runtime.run_proofs(project, manifest["migrations"][-1])
        receipt["timings"]["migration_ms"] = int((proof_started - migration_started) * 1000)
        runtime.network_canaries()
        receipt["timings"]["proof_ms"] = int((time.monotonic() - proof_started) * 1000)
    except ReplayFailure as exc:
        failure = exc.code
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError, subprocess.TimeoutExpired):
        failure = "INTERNAL_ERROR"
    cleanup_started = time.monotonic()
    cleanup_ok = False
    if runtime is not None:
        try:
            cleanup_ok = runtime.cleanup()
        except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
            cleanup_ok = False
    try:
        if SOURCE_ROOT.exists() and not SOURCE_ROOT.is_symlink():
            remove_tree(SOURCE_ROOT)
        source_remaining = 1 if os.path.lexists(SOURCE_ROOT) else 0
    except OSError:
        source_remaining = 1
    receipt["cleanup"]["source_entries_remaining"] = source_remaining
    receipt["cleanup"]["succeeded"] = cleanup_ok and source_remaining == 0
    receipt["timings"]["cleanup_ms"] = int((time.monotonic() - cleanup_started) * 1000)
    if failure == "NONE" and not receipt["cleanup"]["succeeded"]:
        failure = "CLEANUP_RESIDUE"
    receipt["failure_class"] = failure
    receipt["status"] = "PASS" if failure == "NONE" else "BLOCKED"
    receipt["timings"]["total_ms"] = int((time.monotonic() - total_started) * 1000)
    close_receipt(receipt)
    try:
        validate_receipt(receipt, manifest, contract)
        ARTIFACT_PATH.parent.mkdir(mode=0o700, exist_ok=True)
        ARTIFACT_PATH.write_bytes(json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n")
    except (OSError, ValueError, UnicodeError):
        return 2
    return 0 if failure == "NONE" else 1


def verify_receipt(path: Path) -> int:
    try:
        contract = read_json(CONTRACT_PATH)
        manifest = read_json(MANIFEST_PATH)
        validate_manifest(manifest, contract)
        validate_receipt(read_json(path), manifest, contract)
        return 0
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
        return 1


def cleanup_only(expected_head: str) -> int:
    """Run bounded recovery and publish BLOCKED evidence if normal run vanished.

    The attested daemon is exclusive to this packet VM. There is no host-socket
    fallback, and exact project/packet filters remain mandatory.
    """
    contract = read_json(CONTRACT_PATH)
    manifest = read_json(MANIFEST_PATH)
    validate_manifest(manifest, contract)
    head, tree = adapter_identity(expected_head)
    receipt = default_receipt(contract, head, tree)
    try:
        if ARTIFACT_PATH.is_file() and not ARTIFACT_PATH.is_symlink():
            receipt = read_json(ARTIFACT_PATH)
            validate_receipt(receipt, manifest, contract)
        runtime = PrivateRuntime(contract, receipt)
        runtime.attest()
        cleanup_ok = runtime.cleanup()
        if SOURCE_ROOT.is_symlink():
            cleanup_ok = False
        elif SOURCE_ROOT.exists():
            remove_tree(SOURCE_ROOT)
        receipt["cleanup"]["source_entries_remaining"] = 1 if os.path.lexists(SOURCE_ROOT) else 0
        receipt["cleanup"]["succeeded"] = cleanup_ok and receipt["cleanup"]["source_entries_remaining"] == 0
        if not receipt["cleanup"]["succeeded"] or receipt["status"] != "PASS":
            receipt["status"] = "BLOCKED"
            receipt["failure_class"] = "CLEANUP_RESIDUE" if not receipt["cleanup"]["succeeded"] else receipt["failure_class"]
        close_receipt(receipt)
        validate_receipt(receipt, manifest, contract)
        ARTIFACT_PATH.parent.mkdir(mode=0o700, exist_ok=True)
        ARTIFACT_PATH.write_bytes(json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n")
        return 0 if receipt["cleanup"]["succeeded"] else 1
    except (OSError, ValueError, UnicodeError, ReplayFailure, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        receipt["status"] = "BLOCKED"
        receipt["failure_class"] = exc.code if isinstance(exc, ReplayFailure) else "INTERNAL_ERROR"
        receipt["cleanup"]["attempted"] = True
        receipt["cleanup"]["succeeded"] = False
        close_receipt(receipt)
        try:
            validate_receipt(receipt, manifest, contract)
            ARTIFACT_PATH.parent.mkdir(mode=0o700, exist_ok=True)
            ARTIFACT_PATH.write_bytes(json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n")
        except (OSError, ValueError, UnicodeError):
            pass
        return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("source-only-check")
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--expected-adapter-head", required=True)
    verify_parser = subparsers.add_parser("verify-receipt")
    verify_parser.add_argument("--input", type=Path, required=True)
    cleanup_parser = subparsers.add_parser("cleanup-only")
    cleanup_parser.add_argument("--expected-adapter-head", required=True)
    args = parser.parse_args()
    if args.command == "source-only-check":
        return source_only_check()
    if args.command == "verify-receipt":
        return verify_receipt(args.input)
    if args.command == "cleanup-only":
        if not SHA1.fullmatch(args.expected_adapter_head):
            return 2
        return cleanup_only(args.expected_adapter_head)
    if not SHA1.fullmatch(args.expected_adapter_head):
        return 2
    try:
        return execute(args.expected_adapter_head)
    except (OSError, ValueError, UnicodeError, ReplayFailure, json.JSONDecodeError, subprocess.TimeoutExpired):
        return 2


if __name__ == "__main__":
    sys.exit(main())
