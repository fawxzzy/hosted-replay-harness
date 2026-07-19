#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
MODE="${1:-firewall-rehearsal}"
RESULT_PROFILE="${RESULT_PROFILE:-}"
[[ "$#" -le 1 ]] || exit 2
case "$MODE" in
  run|direct-port|firewall-rehearsal|cleanup-only) ;;
  *) exit 2 ;;
esac
case "$RESULT_PROFILE" in
  ""|direct-docker-port-v1|firewall-publication-rehearsal-v1) ;;
  *) exit 2 ;;
esac
CONTAINMENT_PACKET="FP-HOSTED-REPLAY-CONTAINMENT-SMOKE-001"
DIRECT_PACKET="FP-HOSTED-REPLAY-DIRECT-PORT-DIAG-001"
FIREWALL_PACKET="FP-HOSTED-REPLAY-FIREWALL-PUBLICATION-REHEARSAL-001"
PACKET="$CONTAINMENT_PACKET"
[[ "$MODE" != "direct-port" ]] || PACKET="$DIRECT_PACKET"
[[ "$MODE" != "firewall-rehearsal" ]] || PACKET="$FIREWALL_PACKET"
NETWORK_ROLE="containment-network"
[[ "$MODE" != "firewall-rehearsal" ]] || NETWORK_ROLE="firewall-publication-network"
PROJECT="fp-hosted-replay-ro-001"
NETWORK_NAME="fp-hosted-replay-ro-001-net"
SUBNET="172.31.253.0/24"
SUBNET_GATEWAY="172.31.253.1"
DB_NAME="supabase_db_${PROJECT}"
DB_VOLUME="$DB_NAME"
DIRECT_DB_NAME="${PROJECT}-direct-postgres"
FIREWALL_DB_NAME="${PROJECT}-firewall-postgres"
FIREWALL_CLIENT_NAME="${PROJECT}-firewall-client"
FIREWALL_FOREIGN_NAME="${PROJECT}-firewall-foreign"
FIREWALL_BRIDGE_NAME="br-fpro001"
HOST_TEST_PORT="56423"
DB_PORT="56422"
RUNTIME="$ROOT/.smoke-runtime"
RUNTIME_HOME="$RUNTIME/home"
RAW="$RUNTIME/raw"
PROJECT_DIR="$RUNTIME/project"
ROOT_INIT_DIR="$RUNTIME/root-init"
ROOT_INIT_WORKDIR="$ROOT_INIT_DIR/workdir"
ROOT_INIT_HOME="$ROOT_INIT_DIR/home"
ROOT_INIT_XDG_CONFIG="$ROOT_INIT_DIR/xdg-config"
ROOT_INIT_XDG_CACHE="$ROOT_INIT_DIR/xdg-cache"
ROOT_INIT_XDG_DATA="$ROOT_INIT_DIR/xdg-data"
ROOT_INIT_XDG_STATE="$ROOT_INIT_DIR/xdg-state"
ROOT_INIT_TMP="$ROOT_INIT_DIR/tmp"
AUDIT_FILE="$RUNTIME/container-audit.jsonl"
VIOLATION_FILE="$RUNTIME/container-violations.jsonl"
WATCH_READY="$RUNTIME/watcher.ready"
DB_START_DIAGNOSTIC_FILE="$RUNTIME/db-start-diagnostic.tsv"
EVENT_HISTORY_STATE_FILE="$RUNTIME/docker-event-history.tsv"
DOCKER_API_BOUNDARY_STATE_FILE="$RUNTIME/docker-api-boundary.tsv"
DOCKER_API_SOCKET="$RUNTIME/docker-api.sock"
DOCKER_API_READY="$RUNTIME/docker-api.ready"
DOCKER_API_POLICY_FILE="$RUNTIME/docker-api-policy.json"
CONTAINER_EVENTS_FILE="$RAW/docker-container-events.jsonl"
VOLUME_EVENTS_FILE="$RAW/docker-volume-events.jsonl"
NETWORK_EVENTS_FILE="$RAW/docker-network-events.jsonl"
STATE_FILE="$ROOT/artifacts/.state.tsv"
RESULT_FILE="$ROOT/artifacts/containment-smoke.json"
RESULT_STAGE_FILE="$ROOT/artifacts/.containment-smoke.json.stage"
CLEANUP_STATE_FILE="$ROOT/artifacts/.cleanup-state.tsv"
CLEANUP_MODE_FILE="$ROOT/artifacts/.cleanup-mode.tsv"
CLEANUP_MODE_STAGE_FILE="$ROOT/artifacts/.cleanup-mode.tsv.stage"
CLEANUP_MODE_SCHEMA="fawxzzy.hosted-replay-harness.cleanup-mode.v1"
SCRATCH_AUDIT_STAGE_FILE="$ROOT/artifacts/.packet-scratch-audit.jsonl.stage"
SCRATCH_PROOF_STAGE_FILE="$ROOT/artifacts/.packet-scratch-proof.tsv.stage"
SCRATCH_PROOF_SCHEMA="fawxzzy.hosted-replay-harness.packet-scratch-proof.v1"
FIREWALL_LEDGER="$ROOT/artifacts/.firewall-ledger.json"
FIREWALL_COMPLETION="$FIREWALL_LEDGER.restoration-complete"
FIREWALL_COMPLETION_STAGE="$ROOT/artifacts/.$(basename "$FIREWALL_COMPLETION").stage"
FIREWALL_ROLLBACK_RECEIPT="$ROOT/artifacts/.firewall-rollback.tsv"
FIREWALL_STATE_FILE="$RUNTIME/firewall-state.tsv"
FIREWALL_PHASE_MANIFEST="$RUNTIME/firewall-phase-manifest.tsv"
FIREWALL_MARKER_MANIFEST="$RUNTIME/firewall-marker-manifest.tsv"
HOST_TEST_READY="$RUNTIME/host-test-listener.ready"
WATCH_PID=""
DOCKER_API_OBSERVER_PID=""
HOST_TEST_LISTENER_PID=""
NETWORK_ID=""
POSTGRES_IMAGE_ID=""
GOTRUE_IMAGE_ID=""
EVENT_SINCE=""
NATIVE_5432_COUNT=""
NATIVE_5432_SHA256=""
NATIVE_5433_COUNT=""
NATIVE_5433_SHA256=""
LISTENER_FAILURE_CODE=""
LISTENER_LAST_PHASE=""
LISTENER_QUERY_BIN="ss"
LISTENER_NORMALIZE_BIN="awk"
LISTENER_SORT_BIN="sort"
LISTENER_COUNT_BIN="awk"
LISTENER_HASH_BIN="sha256sum"
SMOKE_PASSED=0
FINALIZING=0
CLEANUP_ORIGINAL_MODE=""
CLEANUP_FIREWALL_REQUIRED=""
CLEANUP_DOCKER_QUERY_FAILURE_RECORDED=0
DOCKER_CLEANUP_QUERY_VALUES=()
DOCKER_CLEANUP_QUERY_RECORDS=()
EXPECTED_INPUT_DENIES=0
EXPECTED_FORWARD_DENIES=0
EXPECTED_OUTPUT_DENIES=0
FIREWALL_PHASE_SNAPSHOT_COUNT=0
FIREWALL_PHASE_PREV_INPUT=0
FIREWALL_PHASE_PREV_FORWARD=0
FIREWALL_PHASE_PREV_OUTPUT=0
FIREWALL_PHASE_SUM_INPUT=0
FIREWALL_PHASE_SUM_FORWARD=0
FIREWALL_PHASE_SUM_OUTPUT=0
FIREWALL_FIRST_HIT_FROZEN=0
FIREWALL_FIRST_HIT_CLASS=""
FIREWALL_SETUP_OUTPUT_TOTAL=0
FIREWALL_MARKER_MANIFEST_COUNT=0
FIREWALL_CANARY_BASE_INPUT=0
FIREWALL_CANARY_BASE_FORWARD=0
FIREWALL_CANARY_BASE_OUTPUT=0
declare -A FIREWALL_MARKER_EXPECTED_TOTAL=(
  [same_network]=0
  [external_dns]=0
  [literal_ip]=0
  [metadata]=0
  [gateway]=0
  [host_listener]=0
  [foreign_network]=0
)

CLI_VERSION="2.109.1"
CLI_COMMIT="6d4c19870ed213ba7f682f117d0345c8a40bfa94"
CLI_SHA="36d87b7fe6b4bcfe89ac47a4354e526cff22480224de426d7b370f6934556976"
CLI_BINARY_SHA="e9c1c33233b4341a0475f9acb2ecac35c41f6c9aa6cfdcd4f54b3761cc789c20"
CLI_BINARY_SIZE="109918528"
CLI_SIDECAR_SHA="d10d8059b90d9fd68a69cb808b88dd3fe9f57ec458ffefc79a83083b3e810616"
CLI_SIDECAR_SIZE="100909240"
CLI_MEMBER_MANIFEST_SHA="290ab75309cc2cd39140125f6f408ca2ef06c26ffc9b057aa87299a02041f140"
CLI_ADJACENCY_SHA="889c5d358daebdfd07db6d21bba8460ce002137f1f85b4280d472ead3f290f7d"
CLI_ASSET="supabase_2.109.1_linux_amd64.tar.gz"
CLI_URL="https://github.com/supabase/cli/releases/download/v2.109.1/${CLI_ASSET}"
CONFIG_SHA="1b955c23161259dd41f3849f261bab41525b5ffeca83ab3074e44c5cc18ac0c6"
POSTGRES_TAG="supabase/postgres:17.6.1.143"
POSTGRES_DIGEST="sha256:b021e96054128399f84f24e39d29c21ee7c7169515e5d9e4e99ff15d5043d1d8"
POSTGRES_PULL="supabase/postgres@${POSTGRES_DIGEST}"
POSTGRES_EXPECTED="public.ecr.aws/supabase/postgres:17.6.1.143"
GOTRUE_TAG="supabase/gotrue:v2.192.0"
GOTRUE_DIGEST="sha256:288d880ebc80a1cb5ad52dc7d12328f76e9c90127003306864a270118bba00a8"
GOTRUE_PULL="supabase/gotrue@${GOTRUE_DIGEST}"
GOTRUE_EXPECTED="public.ecr.aws/supabase/gotrue:v2.192.0"
POLICY_MATRIX_SHA256="9669ebd4ae75cfdc3950c9db8b2786270023ce0e26dde993806b3f7b6b2c5492"

record() {
  local key="$1" kind="$2" value="$3"
  value="${value//$'\t'/ }"
  value="${value//$'\r'/ }"
  value="${value//$'\n'/ }"
  printf '%s\t%s\t%s\n' "$key" "$kind" "$value" >>"$STATE_FILE"
}

cleanup_mode_firewall_required() {
  case "$1" in
    run|direct-port) printf 'false\n' ;;
    firewall-rehearsal) printf 'true\n' ;;
    *) return 1 ;;
  esac
}

cleanup_mode_payload() {
  local mode="$1" firewall_required
  firewall_required="$(cleanup_mode_firewall_required "$mode")" || return 1
  printf 'schema\tstr\t%s\nmode\tstr\t%s\nfirewall_required\tbool\t%s\n' \
    "$CLEANUP_MODE_SCHEMA" "$mode" "$firewall_required"
}

write_cleanup_mode_contract() {
  local mode="$1" payload payload_sha
  [[ ! -e "$CLEANUP_MODE_FILE" && ! -L "$CLEANUP_MODE_FILE" \
    && ! -e "$CLEANUP_MODE_STAGE_FILE" && ! -L "$CLEANUP_MODE_STAGE_FILE" ]] || return 1
  payload="$(cleanup_mode_payload "$mode")" || return 1
  payload_sha="$(printf '%s\n' "$payload" | sha256sum | awk '{print $1}')" || return 1
  [[ "$payload_sha" =~ ^[0-9a-f]{64}$ ]] || return 1
  if ! {
    printf '%s\n' "$payload"
    printf 'payload_sha256\tstr\t%s\n' "$payload_sha"
  } >"$CLEANUP_MODE_STAGE_FILE" || ! chmod 0600 "$CLEANUP_MODE_STAGE_FILE"; then
    rm -f -- "$CLEANUP_MODE_STAGE_FILE"
    return 1
  fi
  if ! ln -- "$CLEANUP_MODE_STAGE_FILE" "$CLEANUP_MODE_FILE"; then
    rm -f -- "$CLEANUP_MODE_STAGE_FILE"
    return 1
  fi
  rm -f -- "$CLEANUP_MODE_STAGE_FILE" || return 1
}

read_cleanup_mode_contract() {
  local payload expected_sha observed_sha stored_mode stored_required expected_required
  local -a lines=()
  [[ ! -e "$CLEANUP_MODE_STAGE_FILE" && ! -L "$CLEANUP_MODE_STAGE_FILE" ]] || return 1
  [[ -f "$CLEANUP_MODE_FILE" && ! -L "$CLEANUP_MODE_FILE" ]] || return 1
  [[ "$(stat -c '%a' "$CLEANUP_MODE_FILE" 2>/dev/null)" == "600" ]] || return 1
  mapfile -t lines <"$CLEANUP_MODE_FILE" || return 1
  [[ "${#lines[@]}" == "4" ]] || return 1
  [[ "${lines[0]}" == $'schema\tstr\t'"$CLEANUP_MODE_SCHEMA" ]] || return 1
  [[ "${lines[1]}" =~ ^mode$'\t'str$'\t'(run|direct-port|firewall-rehearsal)$ ]] || return 1
  [[ "${lines[2]}" =~ ^firewall_required$'\t'bool$'\t'(true|false)$ ]] || return 1
  [[ "${lines[3]}" =~ ^payload_sha256$'\t'str$'\t'([0-9a-f]{64})$ ]] || return 1
  stored_mode="${lines[1]##*$'\t'}"
  stored_required="${lines[2]##*$'\t'}"
  observed_sha="${lines[3]##*$'\t'}"
  expected_required="$(cleanup_mode_firewall_required "$stored_mode")" || return 1
  [[ "$stored_required" == "$expected_required" ]] || return 1
  payload="$(printf '%s\n' "${lines[@]:0:3}")"
  expected_sha="$(printf '%s\n' "$payload" | sha256sum | awk '{print $1}')" || return 1
  [[ "$observed_sha" == "$expected_sha" ]] || return 1
  CLEANUP_ORIGINAL_MODE="$stored_mode"
  CLEANUP_FIREWALL_REQUIRED="$stored_required"
}

resolve_cleanup_mode_contract() {
  local invocation_mode="$1"
  CLEANUP_ORIGINAL_MODE=""
  CLEANUP_FIREWALL_REQUIRED=""
  read_cleanup_mode_contract || return 1
  if [[ "$invocation_mode" != "cleanup-only" && "$invocation_mode" != "$CLEANUP_ORIGINAL_MODE" ]]; then
    return 1
  fi
  record cleanup.mode.invocation str "$invocation_mode" || return 1
  record cleanup.mode.original str "$CLEANUP_ORIGINAL_MODE" || return 1
  record cleanup.mode.firewall_required bool "$CLEANUP_FIREWALL_REQUIRED" || return 1
}

retire_cleanup_mode_contract() {
  [[ ! -e "$CLEANUP_MODE_STAGE_FILE" && ! -L "$CLEANUP_MODE_STAGE_FILE" ]] || return 1
  [[ -f "$CLEANUP_MODE_FILE" && ! -L "$CLEANUP_MODE_FILE" ]] || return 1
  rm -f -- "$CLEANUP_MODE_FILE" || return 1
  [[ ! -e "$CLEANUP_MODE_FILE" && ! -L "$CLEANUP_MODE_FILE" ]] || return 1
}

validate_result_receipt() {
  local path="$1" expected_status="$2"
  python3 -B - "$path" "$expected_status" <<'PY'
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
expected = sys.argv[2]
allowed = {
    "BLOCKED",
    "CONTAINMENT_SMOKE_PASS",
    "DIRECT_DOCKER_PORT_PATH_PASS",
    "FIREWALL_PUBLICATION_REHEARSAL_PASS",
}
if expected not in allowed or not path.is_file() or path.is_symlink():
    raise SystemExit(1)
def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result
try:
    result = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=strict_object)
except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
    raise SystemExit(1)
if not isinstance(result, dict) or result.get("status") != expected:
    raise SystemExit(1)
schema = result.get("schema")
if schema not in {
    "fawxzzy.hosted-replay-harness.result.v1",
    "fawxzzy.hosted-replay-harness.direct-port-result.v1",
}:
    raise SystemExit(1)
if expected == "DIRECT_DOCKER_PORT_PATH_PASS" and schema != "fawxzzy.hosted-replay-harness.direct-port-result.v1":
    raise SystemExit(1)
if expected in {"CONTAINMENT_SMOKE_PASS", "FIREWALL_PUBLICATION_REHEARSAL_PASS"} and schema != "fawxzzy.hosted-replay-harness.result.v1":
    raise SystemExit(1)
failure = result.get("failure")
if expected == "BLOCKED":
    if not isinstance(failure, dict) or not re.fullmatch(r"[A-Z0-9_]+", str(failure.get("code", ""))):
        raise SystemExit(1)
elif failure is not None:
    raise SystemExit(1)
PY
}

result_receipt_status() {
  python3 -B - "$RESULT_FILE" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
allowed = {
    "BLOCKED",
    "CONTAINMENT_SMOKE_PASS",
    "DIRECT_DOCKER_PORT_PATH_PASS",
    "FIREWALL_PUBLICATION_REHEARSAL_PASS",
}
def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result
try:
    result = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=strict_object)
    value = result.get("status")
except (AttributeError, OSError, UnicodeError, ValueError, json.JSONDecodeError):
    raise SystemExit(1)
if value not in allowed:
    raise SystemExit(1)
schema = result.get("schema")
if schema not in {
    "fawxzzy.hosted-replay-harness.result.v1",
    "fawxzzy.hosted-replay-harness.direct-port-result.v1",
}:
    raise SystemExit(1)
if value == "DIRECT_DOCKER_PORT_PATH_PASS" and schema != "fawxzzy.hosted-replay-harness.direct-port-result.v1":
    raise SystemExit(1)
if value in {"CONTAINMENT_SMOKE_PASS", "FIREWALL_PUBLICATION_REHEARSAL_PASS"} and schema != "fawxzzy.hosted-replay-harness.result.v1":
    raise SystemExit(1)
print(value)
PY
}

result_receipt_failure_code() {
  python3 -B - "$RESULT_FILE" <<'PY'
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result
try:
    result = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=strict_object)
except (AttributeError, OSError, UnicodeError, ValueError, json.JSONDecodeError):
    raise SystemExit(1)
failure = result.get("failure")
code = failure.get("code") if isinstance(failure, dict) else None
if result.get("status") != "BLOCKED" or not isinstance(code, str) or not re.fullmatch(r"[A-Z0-9_]+", code):
    raise SystemExit(1)
print(code)
PY
}

# BEGIN PACKET_SCRATCH_FUNCTION
validate_packet_scratch_proof() {
  local path="$1" phase="$2"
  python3 -B - "$path" "$phase" "$SCRATCH_PROOF_SCHEMA" >/dev/null 2>&1 <<'PY'
import hashlib
import os
import pathlib
import re
import stat
import sys

path = pathlib.Path(sys.argv[1])
phase = sys.argv[2]
schema = sys.argv[3]
try:
    info = path.lstat()
    effective_uid = os.geteuid() if hasattr(os, "geteuid") else info.st_uid
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != effective_uid
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise SystemExit(1)
    text = path.read_bytes().decode("utf-8", "strict")
except (OSError, UnicodeError):
    raise SystemExit(1)
if not text.endswith("\n") or "\r" in text or "\x00" in text:
    raise SystemExit(1)
rows = text[:-1].split("\n")
names = (
    "schema", "phase", "root_identity_sha256", "allowlist_sha256",
    "allowlist_count", "root_valid", "audit_staged", "cleanup_attempted",
    "cleanup_succeeded", "remaining_entry_count", "escape_count",
    "symlink_count", "reparse_count", "ownership_mismatch_count",
    "allowlist_mismatch_count", "proof_status", "proof_sha256",
)
kinds = (
    "str", "str", "str", "str", "int", "bool", "bool", "bool", "bool",
    "int", "int", "int", "int", "int", "int", "str", "str",
)
if len(rows) != len(names):
    raise SystemExit(1)
parsed = []
for row, name, kind in zip(rows, names, kinds):
    parts = row.split("\t")
    if len(parts) != 3 or parts[:2] != [f"scratch.{phase}.{name}", kind]:
        raise SystemExit(1)
    parsed.append(parts[2])
if parsed[0] != schema or parsed[1] != phase:
    raise SystemExit(1)
for value in (parsed[2], parsed[3], parsed[16]):
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise SystemExit(1)
for index in (4, 9, 10, 11, 12, 13, 14):
    if not re.fullmatch(r"0|[1-9][0-9]*", parsed[index]):
        raise SystemExit(1)
for index in (5, 6, 7, 8):
    if parsed[index] not in {"true", "false"}:
        raise SystemExit(1)
if parsed[15] not in {
    "PASS", "ROOT_INVALID", "AUDIT_INVALID", "OWNERSHIP_OR_ESCAPE_REJECTED",
    "ALLOWLIST_REJECTED", "CLEANUP_FAILED",
}:
    raise SystemExit(1)
expected = hashlib.sha256(("\n".join(rows[:16]) + "\n").encode("utf-8")).hexdigest()
if parsed[16] != expected:
    raise SystemExit(1)
PY
}

cleanup_packet_scratch() {
  local phase="$1" proof_rc=0
  case "$phase" in
    primary|cleanup) ;;
    *) return 1 ;;
  esac
  [[ ! -e "$SCRATCH_AUDIT_STAGE_FILE" && ! -L "$SCRATCH_AUDIT_STAGE_FILE" \
    && ! -e "$SCRATCH_PROOF_STAGE_FILE" && ! -L "$SCRATCH_PROOF_STAGE_FILE" ]] || return 1
  python3 -B - "$RUNTIME" "$AUDIT_FILE" "$SCRATCH_AUDIT_STAGE_FILE" \
    "$SCRATCH_PROOF_STAGE_FILE" "$phase" "$PACKET" "$SCRATCH_PROOF_SCHEMA" \
    >/dev/null 2>&1 <<'PY' || proof_rc=1
import hashlib
import os
import pathlib
import shutil
import stat
import sys

root = pathlib.Path(sys.argv[1])
audit = pathlib.Path(sys.argv[2])
audit_stage = pathlib.Path(sys.argv[3])
proof_stage = pathlib.Path(sys.argv[4])
phase = sys.argv[5]
packet = sys.argv[6]
schema = sys.argv[7]
allowed_roots = (
    "bin/",
    "home/",
    "project/",
    "raw/",
    "root-init/",
)
allowed_files = (
    "cli-archive-contract.tsv",
    "container-violations.jsonl",
    "db-start-diagnostic.tsv",
    "direct-port-probe.tsv",
    "docker-api-boundary.tsv",
    "docker-api-policy.json",
    "docker-api.ready",
    "docker-api.sock",
    "docker-event-history.tsv",
    "firewall-counters.tsv",
    "firewall-install.tsv",
    "firewall-marker-counters.tsv",
    "firewall-marker-install.tsv",
    "firewall-marker-manifest.tsv",
    "firewall-phase-manifest.tsv",
    "firewall-port-probe.tsv",
    "firewall-prepare.tsv",
    "firewall-state.tsv",
    "host-test-listener.ready",
    "publication-firewall_client.tsv",
    "publication-foreign_canary.tsv",
    "supabase_2.109.1_linux_amd64.tar.gz",
    "watcher.ready",
)
allowlist = tuple(sorted((*allowed_roots, *allowed_files)))
root_identity = hashlib.sha256(
    f"{schema}|{packet}|.smoke-runtime".encode("utf-8")
).hexdigest()
allowlist_sha = hashlib.sha256(
    ("\n".join(allowlist) + "\n").encode("utf-8")
).hexdigest()

root_valid = False
audit_staged = False
cleanup_attempted = False
cleanup_succeeded = False
remaining = 0
escape_count = 0
symlink_count = 0
reparse_count = 0
ownership_mismatch_count = 0
allowlist_mismatch_count = 0
status = "ROOT_INVALID"
effective_uid = os.geteuid() if hasattr(os, "geteuid") else root.parent.stat().st_uid

try:
    expected_root = root.parent.resolve(strict=True) / ".smoke-runtime"
    observed = root.lstat()
    root_valid = (
        phase in {"primary", "cleanup"}
        and root == expected_root
        and stat.S_ISDIR(observed.st_mode)
        and not stat.S_ISLNK(observed.st_mode)
        and observed.st_uid == effective_uid
    )
except (OSError, RuntimeError, ValueError):
    root_valid = False

if root_valid:
    try:
        expected_artifacts = root.parent / "artifacts"
        stage_parent = audit_stage.parent.resolve(strict=True)
        proof_parent = proof_stage.parent.resolve(strict=True)
        audit_info = audit.lstat()
        if (
            audit == root / "container-audit.jsonl"
            and stage_parent == expected_artifacts.resolve(strict=True)
            and proof_parent == expected_artifacts.resolve(strict=True)
            and audit_stage == expected_artifacts / ".packet-scratch-audit.jsonl.stage"
            and proof_stage == expected_artifacts / ".packet-scratch-proof.tsv.stage"
            and not os.path.lexists(audit_stage)
            and not os.path.lexists(proof_stage)
            and stat.S_ISREG(audit_info.st_mode)
            and not stat.S_ISLNK(audit_info.st_mode)
            and audit_info.st_uid == effective_uid
        ):
            os.replace(audit, audit_stage)
            audit_staged = True
    except (OSError, RuntimeError, ValueError):
        audit_staged = False

if root_valid and audit_staged:
    root_resolved = root.resolve(strict=True)
    try:
        paths = sorted(root.rglob("*"), key=lambda item: item.as_posix())
    except OSError:
        paths = []
        escape_count += 1
    remaining = len(paths)
    for path in paths:
        try:
            info = path.lstat()
            relative = path.relative_to(root).as_posix()
            resolved = path.resolve(strict=False)
            if os.path.commonpath((str(root_resolved), str(resolved))) != str(root_resolved):
                escape_count += 1
            if stat.S_ISLNK(info.st_mode):
                symlink_count += 1
            if getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
                reparse_count += 1
            if info.st_uid != effective_uid:
                ownership_mismatch_count += 1
            admitted = relative in allowed_files or any(
                relative == root_name[:-1] or relative.startswith(root_name)
                for root_name in allowed_roots
            )
            if not admitted:
                allowlist_mismatch_count += 1
        except (OSError, RuntimeError, ValueError):
            escape_count += 1

    if any((escape_count, symlink_count, reparse_count, ownership_mismatch_count)):
        status = "OWNERSHIP_OR_ESCAPE_REJECTED"
    elif allowlist_mismatch_count:
        status = "ALLOWLIST_REJECTED"
    else:
        cleanup_attempted = True
        try:
            shutil.rmtree(root)
            remaining = 0 if not os.path.lexists(root) else 1
            cleanup_succeeded = remaining == 0
            status = "PASS" if cleanup_succeeded else "CLEANUP_FAILED"
        except OSError:
            remaining = 1 if os.path.lexists(root) else 0
            status = "CLEANUP_FAILED"
elif root_valid:
    status = "AUDIT_INVALID"

fields = [
    (f"scratch.{phase}.schema", "str", schema),
    (f"scratch.{phase}.phase", "str", phase),
    (f"scratch.{phase}.root_identity_sha256", "str", root_identity),
    (f"scratch.{phase}.allowlist_sha256", "str", allowlist_sha),
    (f"scratch.{phase}.allowlist_count", "int", len(allowlist)),
    (f"scratch.{phase}.root_valid", "bool", str(root_valid).lower()),
    (f"scratch.{phase}.audit_staged", "bool", str(audit_staged).lower()),
    (f"scratch.{phase}.cleanup_attempted", "bool", str(cleanup_attempted).lower()),
    (f"scratch.{phase}.cleanup_succeeded", "bool", str(cleanup_succeeded).lower()),
    (f"scratch.{phase}.remaining_entry_count", "int", remaining),
    (f"scratch.{phase}.escape_count", "int", escape_count),
    (f"scratch.{phase}.symlink_count", "int", symlink_count),
    (f"scratch.{phase}.reparse_count", "int", reparse_count),
    (f"scratch.{phase}.ownership_mismatch_count", "int", ownership_mismatch_count),
    (f"scratch.{phase}.allowlist_mismatch_count", "int", allowlist_mismatch_count),
    (f"scratch.{phase}.proof_status", "str", status),
]
payload = "".join(f"{key}\t{kind}\t{value}\n" for key, kind, value in fields)
proof_sha = hashlib.sha256(payload.encode("utf-8")).hexdigest()
payload += f"scratch.{phase}.proof_sha256\tstr\t{proof_sha}\n"
try:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(proof_stage, flags, 0o600)
    try:
        os.write(descriptor, payload.encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
except OSError:
    raise SystemExit(1)
raise SystemExit(0 if status == "PASS" else 1)
PY
  if [[ ! -f "$SCRATCH_PROOF_STAGE_FILE" || -L "$SCRATCH_PROOF_STAGE_FILE" ]]; then
    record "scratch.${phase}.proof_status" str PROOF_INVALID || true
    [[ ! -e "$SCRATCH_AUDIT_STAGE_FILE" ]] || AUDIT_FILE="$SCRATCH_AUDIT_STAGE_FILE"
    return 1
  fi
  if ! validate_packet_scratch_proof "$SCRATCH_PROOF_STAGE_FILE" "$phase"; then
    rm -f -- "$SCRATCH_PROOF_STAGE_FILE"
    record "scratch.${phase}.proof_status" str PROOF_INVALID || true
    [[ ! -e "$SCRATCH_AUDIT_STAGE_FILE" ]] || AUDIT_FILE="$SCRATCH_AUDIT_STAGE_FILE"
    return 1
  fi
  cat "$SCRATCH_PROOF_STAGE_FILE" >>"$STATE_FILE" || return 1
  rm -f -- "$SCRATCH_PROOF_STAGE_FILE" || return 1
  [[ ! -e "$SCRATCH_AUDIT_STAGE_FILE" ]] || AUDIT_FILE="$SCRATCH_AUDIT_STAGE_FILE"
  [[ "$proof_rc" == "0" ]]
}
# END PACKET_SCRATCH_FUNCTION

publish_result_receipt() {
  local expected_status="$1" operation="$2" writer_rc=0
  local -a writer_args=(
    --root "$ROOT" --state "$STATE_FILE" --audit "$AUDIT_FILE" --output "$RESULT_STAGE_FILE"
  )
  [[ ! -e "$SCRATCH_PROOF_STAGE_FILE" && ! -L "$SCRATCH_PROOF_STAGE_FILE" ]] || return 1
  if [[ "$AUDIT_FILE" == "$SCRATCH_AUDIT_STAGE_FILE" ]]; then
    [[ -f "$SCRATCH_AUDIT_STAGE_FILE" && ! -L "$SCRATCH_AUDIT_STAGE_FILE" ]] || return 1
  fi
  rm -f -- "$RESULT_STAGE_FILE" || return 1
  case "$operation" in
    replace) ;;
    merge)
      validate_result_receipt "$RESULT_FILE" "$(result_receipt_status)" || return 1
      cp -- "$RESULT_FILE" "$RESULT_STAGE_FILE" || return 1
      writer_args+=(--merge-existing)
      ;;
    *) return 1 ;;
  esac
  python3 "$ROOT/scripts/write_result.py" "${writer_args[@]}" \
    >/dev/null 2>&1 || writer_rc=1
  if [[ "$AUDIT_FILE" == "$SCRATCH_AUDIT_STAGE_FILE" ]]; then
    rm -f -- "$SCRATCH_AUDIT_STAGE_FILE" || writer_rc=1
    [[ ! -e "$SCRATCH_AUDIT_STAGE_FILE" && ! -L "$SCRATCH_AUDIT_STAGE_FILE" ]] || writer_rc=1
  fi
  if [[ "$writer_rc" != "0" ]]; then
    rm -f -- "$RESULT_STAGE_FILE"
    return 1
  fi
  validate_result_receipt "$RESULT_STAGE_FILE" "$expected_status" || {
    rm -f -- "$RESULT_STAGE_FILE"
    return 1
  }
  mv -f -- "$RESULT_STAGE_FILE" "$RESULT_FILE" || {
    rm -f -- "$RESULT_STAGE_FILE"
    return 1
  }
  validate_result_receipt "$RESULT_FILE" "$expected_status" || {
    rm -f -- "$RESULT_FILE"
    return 1
  }
}

block() {
  local code="$1" detail="${2:-gate-rejected}"
  record status str BLOCKED
  record failure.code str "$code"
  record failure.detail str "$detail"
  exit 1
}

version_at_least() {
  local actual="$1" minimum="$2"
  [[ "$(printf '%s\n%s\n' "$minimum" "$actual" | sort -V | head -n1)" == "$minimum" ]]
}

validate_extract_cli_archive() {
  local archive="$1" destination="$2"
  python3 -B - "$archive" "$destination" <<'PY'
# BEGIN CLI_ARCHIVE_VALIDATOR_PYTHON
from __future__ import annotations

import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import struct
import sys


EXPECTED = (
    {
        "name": "supabase",
        "size": 109918528,
        "sha256": "e9c1c33233b4341a0475f9acb2ecac35c41f6c9aa6cfdcd4f54b3761cc789c20",
        "mode": 0o755,
        "uid": 1001,
        "gid": 1001,
        "uname": "runner",
        "gname": "runner",
        "mtime": 1783414360,
    },
    {
        "name": "supabase-go",
        "size": 100909240,
        "sha256": "d10d8059b90d9fd68a69cb808b88dd3fe9f57ec458ffefc79a83083b3e810616",
        "mode": 0o755,
        "uid": 1001,
        "gid": 1001,
        "uname": "runner",
        "gname": "runner",
        "mtime": 1783414369,
    },
)
EXPECTED_MEMBER_MANIFEST_SHA256 = "290ab75309cc2cd39140125f6f408ca2ef06c26ffc9b057aa87299a02041f140"
EXPECTED_ADJACENCY_SHA256 = "889c5d358daebdfd07db6d21bba8460ce002137f1f85b4280d472ead3f290f7d"


class ArchiveContractError(ValueError):
    pass


def parse_octal(field: bytes, label: str) -> int:
    if field and field[0] & 0x80:
        raise ArchiveContractError(f"{label}: base-256 is not admitted")
    value = field.rstrip(b"\0 ").lstrip(b" ")
    if value and any(byte not in b"01234567" for byte in value):
        raise ArchiveContractError(f"{label}: invalid octal")
    return int(value or b"0", 8)


def parse_text(field: bytes, label: str) -> str:
    try:
        return field.split(b"\0", 1)[0].decode("ascii")
    except UnicodeDecodeError as error:
        raise ArchiveContractError(f"{label}: non-ASCII") from error


def validate_elf(header: bytes, name: str) -> dict[str, int | str]:
    if len(header) < 64 or header[:4] != b"\x7fELF" or header[:2] == b"#!":
        raise ArchiveContractError(f"{name}: ELF magic mismatch")
    if header[4:7] != bytes((2, 1, 1)):
        raise ArchiveContractError(f"{name}: ELF class/data/version mismatch")
    elf_type, machine, version = struct.unpack_from("<HHI", header, 16)
    header_size = struct.unpack_from("<H", header, 52)[0]
    if elf_type not in (2, 3) or machine != 62 or version != 1 or header_size != 64:
        raise ArchiveContractError(f"{name}: ELF64 x86-64 header mismatch")
    return {
        "class": "ELF64",
        "endian": "little",
        "machine": "x86-64",
        "machine_id": machine,
        "elf_type": elf_type,
        "osabi": header[7],
    }


def validate_archive(
    archive: Path,
    destination: Path,
    *,
    expected: tuple[dict[str, object], ...] = EXPECTED,
    expected_member_manifest_sha256: str | None = EXPECTED_MEMBER_MANIFEST_SHA256,
    expected_adjacency_sha256: str | None = EXPECTED_ADJACENCY_SHA256,
) -> dict[str, object]:
    archive_stat = archive.lstat()
    destination_stat = destination.lstat()
    if not stat.S_ISREG(archive_stat.st_mode) or stat.S_ISLNK(archive_stat.st_mode):
        raise ArchiveContractError("archive must be a regular file")
    if not stat.S_ISDIR(destination_stat.st_mode) or stat.S_ISLNK(destination_stat.st_mode):
        raise ArchiveContractError("destination must be a regular directory")
    if list(destination.iterdir()):
        raise ArchiveContractError("destination must be empty")
    if tuple(item["name"] for item in expected) != ("supabase", "supabase-go"):
        raise ArchiveContractError("expected member denominator is invalid")

    rows: list[dict[str, object]] = []
    created: list[Path] = []
    try:
        with gzip.open(archive, "rb") as stream:
            for expected_member in expected:
                header = stream.read(512)
                if len(header) != 512 or header == b"\0" * 512:
                    raise ArchiveContractError("archive member is missing")
                stored_checksum = parse_octal(header[148:156], "checksum")
                calculated_checksum = sum(header[:148]) + sum(b" " * 8) + sum(header[156:])
                if stored_checksum != calculated_checksum:
                    raise ArchiveContractError("tar header checksum mismatch")

                name = parse_text(header[:100], "name")
                member_path = PurePosixPath(name)
                size = parse_octal(header[124:136], "size")
                mode = parse_octal(header[100:108], "mode")
                uid = parse_octal(header[108:116], "uid")
                gid = parse_octal(header[116:124], "gid")
                mtime = parse_octal(header[136:148], "mtime")
                uname = parse_text(header[265:297], "uname")
                gname = parse_text(header[297:329], "gname")
                if (
                    member_path.is_absolute()
                    or len(member_path.parts) != 1
                    or name in ("", ".", "..")
                    or "/" in name
                    or "\\" in name
                ):
                    raise ArchiveContractError("member path is not a unique root basename")
                if header[156:157] != b"0":
                    raise ArchiveContractError("only regular-file tar entries are admitted")
                if header[157:257].rstrip(b"\0") or header[345:500].rstrip(b"\0"):
                    raise ArchiveContractError("links and prefixed paths are forbidden")
                if header[257:263] != b"ustar " or header[263:265] != b" \0":
                    raise ArchiveContractError("PAX and long-name formats are forbidden")
                if mode & 0o7000 or mode != int(expected_member["mode"]):
                    raise ArchiveContractError("member mode is not the exact executable mode")
                observed_identity = (name, size, uid, gid, uname, gname, mtime)
                expected_identity = (
                    expected_member["name"],
                    expected_member["size"],
                    expected_member["uid"],
                    expected_member["gid"],
                    expected_member["uname"],
                    expected_member["gname"],
                    expected_member["mtime"],
                )
                if observed_identity != expected_identity:
                    raise ArchiveContractError("member identity, size, owner, or order mismatch")

                target = destination / name
                flags = (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_BINARY", 0)
                )
                descriptor = os.open(target, flags, 0o555)
                created.append(target)
                digest = hashlib.sha256()
                first = b""
                remaining = size
                try:
                    while remaining:
                        chunk = stream.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise ArchiveContractError("member body is truncated")
                        if len(first) < 64:
                            first = (first + chunk)[:64]
                        digest.update(chunk)
                        view = memoryview(chunk)
                        while view:
                            written = os.write(descriptor, view)
                            if written <= 0:
                                raise ArchiveContractError("member extraction write failed")
                            view = view[written:]
                        remaining -= len(chunk)
                finally:
                    os.close(descriptor)
                padding = (-size) % 512
                if padding and stream.read(padding) != b"\0" * padding:
                    raise ArchiveContractError("member padding is not zero")
                os.chmod(target, 0o555)
                actual_sha256 = digest.hexdigest()
                if actual_sha256 != expected_member["sha256"] or target.stat().st_size != size:
                    raise ArchiveContractError("member size or digest mismatch")
                rows.append(
                    {
                        "name": name,
                        "size": size,
                        "sha256": actual_sha256,
                        "mode": "0755",
                        "archive_uid": uid,
                        "archive_gid": gid,
                        "archive_uname": uname,
                        "archive_gname": gname,
                        "mtime": mtime,
                        **validate_elf(first, name),
                    }
                )

            if stream.read(512) != b"\0" * 512 or stream.read(512) != b"\0" * 512:
                raise ArchiveContractError("archive has an additional or malformed member")
            if any(stream.read()):
                raise ArchiveContractError("archive trailing bytes are not zero")

        if sorted(path.name for path in destination.iterdir()) != ["supabase", "supabase-go"]:
            raise ArchiveContractError("extracted adjacency denominator mismatch")
        for path in destination.iterdir():
            path_stat = path.lstat()
            observed_mode = stat.S_IMODE(path_stat.st_mode)
            runtime_mode_valid = observed_mode == 0o555
            if os.name == "nt":
                runtime_mode_valid = observed_mode in (0o444, 0o555)
            if not stat.S_ISREG(path_stat.st_mode) or stat.S_ISLNK(path_stat.st_mode) or not runtime_mode_valid:
                raise ArchiveContractError("extracted member is not an adjacent read-only executable")

        member_manifest = (json.dumps(rows, sort_keys=True, separators=(",", ":")) + "\n").encode()
        member_manifest_sha256 = hashlib.sha256(member_manifest).hexdigest()
        adjacency_manifest = "".join(
            f"{row['name']}|{row['sha256']}|{row['size']}\n" for row in rows
        ).encode()
        adjacency_sha256 = hashlib.sha256(adjacency_manifest).hexdigest()
        if (
            expected_member_manifest_sha256 is not None
            and member_manifest_sha256 != expected_member_manifest_sha256
        ):
            raise ArchiveContractError("member manifest digest mismatch")
        if expected_adjacency_sha256 is not None and adjacency_sha256 != expected_adjacency_sha256:
            raise ArchiveContractError("adjacency digest mismatch")
        return {
            "member_count": len(rows),
            "member_manifest_sha256": member_manifest_sha256,
            "adjacency_sha256": adjacency_sha256,
            "members": rows,
        }
    except Exception:
        for path in created:
            try:
                os.chmod(path, 0o700)
                path.unlink()
            except FileNotFoundError:
                pass
        raise


def main() -> None:
    result = validate_archive(Path(sys.argv[1]), Path(sys.argv[2]))
    members = {member["name"]: member for member in result["members"]}
    fields = (
        ("archive_member_count", "int", result["member_count"]),
        ("member_manifest_sha256", "str", result["member_manifest_sha256"]),
        ("adjacency_sha256", "str", result["adjacency_sha256"]),
        ("binary_size", "int", members["supabase"]["size"]),
        ("binary_sha256", "str", members["supabase"]["sha256"]),
        ("sidecar_size", "int", members["supabase-go"]["size"]),
        ("sidecar_sha256", "str", members["supabase-go"]["sha256"]),
    )
    for key, kind, value in fields:
        print(f"{key}\t{kind}\t{value}")


if __name__ == "__main__":
    main()
# END CLI_ARCHIVE_VALIDATOR_PYTHON
PY
}

hash_identifier() {
  printf 'sha256:%s' "$(printf '%s' "$1" | sha256sum | awk '{print $1}')"
}

gateway_contract() {
  python3 -B - "$@" <<'PY'
# BEGIN GATEWAY_CONTRACT_PYTHON
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import sys


def validate_pair(subnet_text: str, gateway_text: str) -> tuple[ipaddress.IPv4Network, ipaddress.IPv4Address]:
    subnet = ipaddress.ip_network(subnet_text, strict=True)
    gateway = ipaddress.ip_address(gateway_text)
    if not isinstance(subnet, ipaddress.IPv4Network) or not isinstance(gateway, ipaddress.IPv4Address):
        raise ValueError("IPv4 required")
    if gateway not in subnet or gateway in (subnet.network_address, subnet.broadcast_address):
        raise ValueError("gateway is not a usable address in subnet")
    return subnet, gateway


def validate_ipam(path: Path, subnet_text: str, gateway_text: str) -> None:
    subnet, gateway = validate_pair(subnet_text, gateway_text)
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list) or len(payload) != 1:
        raise ValueError("exactly one IPAM config row required")
    row = payload[0]
    if not isinstance(row, dict):
        raise ValueError("IPAM config row must be an object")
    allowed = {"Subnet", "IPRange", "Gateway", "AuxiliaryAddresses"}
    if not set(row).issubset(allowed):
        raise ValueError("unexpected IPAM field")
    if row.get("IPRange") not in (None, "") or row.get("AuxiliaryAddresses") not in (None, {}):
        raise ValueError("extra IPAM allocation data is not admitted")
    if row.get("Subnet") != str(subnet) or row.get("Gateway") != str(gateway):
        raise ValueError("IPAM subnet or gateway mismatch")


try:
    mode, subnet_text, gateway_text = sys.argv[1:4]
    validate_pair(subnet_text, gateway_text)
    if mode == "request":
        if len(sys.argv) != 4:
            raise ValueError("unexpected request arguments")
    elif mode == "readback":
        if len(sys.argv) != 5:
            raise ValueError("unexpected readback arguments")
        validate_ipam(Path(sys.argv[4]), subnet_text, gateway_text)
    else:
        raise ValueError("unknown gateway contract mode")
except (IndexError, OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
    raise SystemExit(1)
# END GATEWAY_CONTRACT_PYTHON
PY
}

validate_network_ipam_contract() {
  local network_ref stage ipam_path
  network_ref="$1"
  stage="$2"
  ipam_path="$RAW/network-ipam-${stage}.json"
  docker network inspect --format '{{json .IPAM.Config}}' "$network_ref" \
    >"$ipam_path" 2>>"$RAW/network-contract.log" \
    || return 1
  gateway_contract readback "$SUBNET" "$SUBNET_GATEWAY" "$ipam_path"
}

# BEGIN LISTENER_DIAGNOSTIC_FUNCTIONS
listener_record() {
  local key kind value
  key="$1"
  kind="$2"
  value="$3"
  if ! record "$key" "$kind" "$value"; then
    LISTENER_FAILURE_CODE=LISTENER_RECEIPT_WRITE_FAILED
    return 1
  fi
}

listener_set_phase() {
  local phase
  phase="$1"
  LISTENER_LAST_PHASE="$phase"
  listener_record listener_diagnostic.last_phase str "$phase"
}

listener_fail() {
  local code phase
  code="$1"
  phase="$2"
  LISTENER_FAILURE_CODE="$code"
  if ! listener_set_phase "$phase"; then
    LISTENER_FAILURE_CODE=LISTENER_RECEIPT_WRITE_FAILED
  fi
  return 1
}

listener_phase_is_unexpected() {
  local phase
  phase="$1"
  [[ "$phase" == PRE_CLI_* && "$phase" != "PRE_CLI_PREFLIGHT_COMPLETE" ]]
}

capture_listener_snapshot() {
  local stage port prefix raw_file normalized_unsorted snapshot count_file hash_file
  local listener_command precheck_rc query_rc normalize_rc count_rc hash_rc count_value hash_value ignored
  stage="$1"
  port="$2"
  prefix="${stage^^}_PORT_${port}"
  raw_file="$RAW/listeners-${stage}-${port}.raw"
  normalized_unsorted="$RAW/listeners-${stage}-${port}.normalized-unsorted"
  snapshot="$RAW/listeners-${stage}-${port}.normalized"
  count_file="$RAW/listeners-${stage}-${port}.count"
  hash_file="$RAW/listeners-${stage}-${port}.sha256"
  LISTENER_FAILURE_CODE=LISTENER_UNEXPECTED_INTERRUPTION
  LISTENER_LAST_PHASE="${prefix}_COMMAND_PRECHECK_BEGIN"

  listener_set_phase "${prefix}_COMMAND_PRECHECK_BEGIN" || return 1
  precheck_rc=0
  for listener_command in \
    "$LISTENER_QUERY_BIN" \
    "$LISTENER_NORMALIZE_BIN" \
    "$LISTENER_SORT_BIN" \
    "$LISTENER_COUNT_BIN" \
    "$LISTENER_HASH_BIN"; do
    if ! command -v "$listener_command" >/dev/null 2>&1; then
      precheck_rc=127
      break
    fi
  done
  listener_record "listener_diagnostic.${stage}.port_${port}.command_precheck_exit_code" int "$precheck_rc" || return 1
  if [[ "$precheck_rc" != "0" ]]; then
    listener_fail LISTENER_COMMAND_UNAVAILABLE "${prefix}_COMMAND_UNAVAILABLE"
    return 1
  fi
  listener_set_phase "${prefix}_COMMAND_PRECHECK_COMPLETE" || return 1

  listener_set_phase "${prefix}_QUERY_BEGIN" || return 1
  if "$LISTENER_QUERY_BIN" -H -ltn "sport = :${port}" >"$raw_file" 2>"$RAW/listeners-${stage}-${port}.log"; then
    query_rc=0
  else
    query_rc="$?"
  fi
  listener_record "listener_diagnostic.${stage}.port_${port}.query_exit_code" int "$query_rc" || return 1
  if [[ "$query_rc" != "0" ]]; then
    listener_fail LISTENER_QUERY_NONZERO "${prefix}_QUERY_FAILED"
    return 1
  fi
  listener_set_phase "${prefix}_QUERY_COMPLETE" || return 1

  listener_set_phase "${prefix}_NORMALIZATION_BEGIN" || return 1
  if "$LISTENER_NORMALIZE_BIN" 'NF{print $1 "|" $4 "|" $5}' "$raw_file" >"$normalized_unsorted"; then
    normalize_rc=0
  else
    normalize_rc="$?"
  fi
  if [[ "$normalize_rc" == "0" ]]; then
    if LC_ALL=C "$LISTENER_SORT_BIN" -u "$normalized_unsorted" >"$snapshot"; then
      normalize_rc=0
    else
      normalize_rc="$?"
    fi
  fi
  listener_record "listener_diagnostic.${stage}.port_${port}.normalization_exit_code" int "$normalize_rc" || return 1
  if [[ "$normalize_rc" != "0" ]]; then
    listener_fail LISTENER_NORMALIZATION_FAILED "${prefix}_NORMALIZATION_FAILED"
    return 1
  fi
  listener_set_phase "${prefix}_NORMALIZATION_COMPLETE" || return 1

  listener_set_phase "${prefix}_COUNT_BEGIN" || return 1
  if "$LISTENER_COUNT_BIN" 'NF{count++} END{print count+0}' "$snapshot" >"$count_file"; then
    count_rc=0
  else
    count_rc="$?"
  fi
  count_value=""
  if [[ "$count_rc" == "0" ]]; then
    IFS= read -r count_value <"$count_file" || count_rc=65
    [[ "$count_value" =~ ^[0-9]+$ ]] || count_rc=65
  fi
  listener_record "listener_diagnostic.${stage}.port_${port}.count_exit_code" int "$count_rc" || return 1
  if [[ "$count_rc" != "0" ]]; then
    listener_fail LISTENER_COUNT_FAILED "${prefix}_COUNT_FAILED"
    return 1
  fi
  LISTENER_SNAPSHOT_COUNT="$count_value"
  listener_set_phase "${prefix}_COUNT_COMPLETE" || return 1

  listener_set_phase "${prefix}_HASH_BEGIN" || return 1
  if "$LISTENER_HASH_BIN" "$snapshot" >"$hash_file"; then
    hash_rc=0
  else
    hash_rc="$?"
  fi
  hash_value=""
  ignored=""
  if [[ "$hash_rc" == "0" ]]; then
    IFS=' ' read -r hash_value ignored <"$hash_file" || hash_rc=65
    [[ "$hash_value" =~ ^[0-9a-f]{64}$ ]] || hash_rc=65
  fi
  listener_record "listener_diagnostic.${stage}.port_${port}.hash_exit_code" int "$hash_rc" || return 1
  if [[ "$hash_rc" != "0" ]]; then
    listener_fail LISTENER_HASH_FAILED "${prefix}_HASH_FAILED"
    return 1
  fi
  LISTENER_SNAPSHOT_SHA256="$hash_value"
  listener_set_phase "${prefix}_HASH_COMPLETE" || return 1

  listener_set_phase "${prefix}_RECEIPT_BEGIN" || return 1
  listener_record "listener_diagnostic.${stage}.port_${port}.normalized_count" int "$LISTENER_SNAPSHOT_COUNT" || return 1
  listener_record "listener_diagnostic.${stage}.port_${port}.normalized_sha256" str "$LISTENER_SNAPSHOT_SHA256" || return 1
  listener_set_phase "${prefix}_RECEIPT_COMPLETE" || return 1
}
# END LISTENER_DIAGNOSTIC_FUNCTIONS

freeze_precli_objects_and_listeners() {
  local container_count volume_count
  listener_set_phase PRE_CLI_BOUNDARY_BEGIN || block LISTENER_RECEIPT_WRITE_FAILED PRE_CLI_BOUNDARY_BEGIN
  container_count="$({
    docker ps -aq --no-trunc --filter "name=^/${DB_NAME}$" 2>/dev/null
    docker ps -aq --no-trunc --filter "label=com.supabase.cli.project=${PROJECT}" 2>/dev/null
  } | awk 'NF' | sort -u | wc -l)"
  volume_count="$({
    docker volume ls -q --filter "name=^${DB_VOLUME}$" 2>/dev/null
    docker volume ls -q --filter "label=com.supabase.cli.project=${PROJECT}" 2>/dev/null
  } | awk 'NF' | sort -u | wc -l)"
  record pre_cli.packet_db_container_count int "$container_count"
  record pre_cli.packet_db_volume_count int "$volume_count"
  [[ "$container_count" == "0" ]] || block PRESTART_DB_CONTAINER_PRESENT
  [[ "$volume_count" == "0" ]] || block PRESTART_DB_VOLUME_PRESENT

  capture_listener_snapshot pre_cli "$DB_PORT" || block "${LISTENER_FAILURE_CODE:-LISTENER_UNEXPECTED_INTERRUPTION}" "${LISTENER_LAST_PHASE:-PRE_CLI_PORT_56422_UNKNOWN}"
  listener_record pre_cli.db_listener_count int "$LISTENER_SNAPSHOT_COUNT" || block LISTENER_RECEIPT_WRITE_FAILED "$LISTENER_LAST_PHASE"
  [[ "$LISTENER_SNAPSHOT_COUNT" == "0" ]] || block PRESTART_DB_PORT_LISTENER_PRESENT

  capture_listener_snapshot pre_cli 5432 || block "${LISTENER_FAILURE_CODE:-LISTENER_UNEXPECTED_INTERRUPTION}" "${LISTENER_LAST_PHASE:-PRE_CLI_PORT_5432_UNKNOWN}"
  NATIVE_5432_COUNT="$LISTENER_SNAPSHOT_COUNT"
  NATIVE_5432_SHA256="$LISTENER_SNAPSHOT_SHA256"
  listener_record native_listeners.port_5432.pre_cli_count int "$NATIVE_5432_COUNT" || block LISTENER_RECEIPT_WRITE_FAILED "$LISTENER_LAST_PHASE"
  listener_record native_listeners.port_5432.pre_cli_sha256 str "$NATIVE_5432_SHA256" || block LISTENER_RECEIPT_WRITE_FAILED "$LISTENER_LAST_PHASE"

  capture_listener_snapshot pre_cli 5433 || block "${LISTENER_FAILURE_CODE:-LISTENER_UNEXPECTED_INTERRUPTION}" "${LISTENER_LAST_PHASE:-PRE_CLI_PORT_5433_UNKNOWN}"
  NATIVE_5433_COUNT="$LISTENER_SNAPSHOT_COUNT"
  NATIVE_5433_SHA256="$LISTENER_SNAPSHOT_SHA256"
  listener_record native_listeners.port_5433.pre_cli_count int "$NATIVE_5433_COUNT" || block LISTENER_RECEIPT_WRITE_FAILED "$LISTENER_LAST_PHASE"
  listener_record native_listeners.port_5433.pre_cli_sha256 str "$NATIVE_5433_SHA256" || block LISTENER_RECEIPT_WRITE_FAILED "$LISTENER_LAST_PHASE"
  listener_set_phase PRE_CLI_PREFLIGHT_COMPLETE || block LISTENER_RECEIPT_WRITE_FAILED PRE_CLI_PREFLIGHT_COMPLETE
}

native_listener_contract() {
  local stage matched
  stage="$1"
  matched=true
  [[ -n "$NATIVE_5432_COUNT" && -n "$NATIVE_5433_COUNT" ]] || return 0

  if ! capture_listener_snapshot "$stage" 5432; then
    record "native_listeners.${stage}_failure_code" str "${LISTENER_FAILURE_CODE:-LISTENER_UNEXPECTED_INTERRUPTION}" || true
    return 1
  fi
  listener_record "native_listeners.port_5432.${stage}_count" int "$LISTENER_SNAPSHOT_COUNT" || return 1
  listener_record "native_listeners.port_5432.${stage}_sha256" str "$LISTENER_SNAPSHOT_SHA256" || return 1
  [[ "$LISTENER_SNAPSHOT_COUNT" == "$NATIVE_5432_COUNT" && "$LISTENER_SNAPSHOT_SHA256" == "$NATIVE_5432_SHA256" ]] \
    || matched=false

  if ! capture_listener_snapshot "$stage" 5433; then
    record "native_listeners.${stage}_failure_code" str "${LISTENER_FAILURE_CODE:-LISTENER_UNEXPECTED_INTERRUPTION}" || true
    return 1
  fi
  listener_record "native_listeners.port_5433.${stage}_count" int "$LISTENER_SNAPSHOT_COUNT" || return 1
  listener_record "native_listeners.port_5433.${stage}_sha256" str "$LISTENER_SNAPSHOT_SHA256" || return 1
  [[ "$LISTENER_SNAPSHOT_COUNT" == "$NATIVE_5433_COUNT" && "$LISTENER_SNAPSHOT_SHA256" == "$NATIVE_5433_SHA256" ]] \
    || matched=false

  listener_record "native_listeners.${stage}_unchanged" bool "$matched" || return 1
  [[ "$matched" == "true" ]]
}

network_contract_code() {
  local endpoint_mode="${1:-active}" resolved_ids correlated_ids endpoint_ids allowed_ids
  local resolved_count correlated_count endpoint_count id

  resolved_ids="$(docker network ls --no-trunc \
    --filter "name=^${NETWORK_NAME}$" --format '{{.ID}}' 2>"$RAW/network-name-resolution.log")" \
    || { printf 'NETWORK_NAME_ID_MAPPING_FAILED\n'; return 1; }
  resolved_count="$(printf '%s\n' "$resolved_ids" | awk 'NF' | sort -u | wc -l)"
  [[ "$resolved_count" == "1" && "$(printf '%s\n' "$resolved_ids" | awk 'NF{print; exit}')" == "$NETWORK_ID" ]] \
    || { printf 'NETWORK_NAME_ID_MAPPING_FAILED\n'; return 1; }

  correlated_ids="$({
    docker network ls --no-trunc -q --filter "label=io.fawxzzy.packet=${PACKET}" 2>/dev/null
    docker network ls --no-trunc -q --filter "label=com.supabase.cli.project=${PROJECT}" 2>/dev/null
  } | awk 'NF' | sort -u)"
  correlated_count="$(printf '%s\n' "$correlated_ids" | awk 'NF' | wc -l)"
  [[ "$correlated_count" == "1" && "$(printf '%s\n' "$correlated_ids" | awk 'NF{print; exit}')" == "$NETWORK_ID" ]] \
    || { printf 'SECOND_PACKET_NETWORK_DETECTED\n'; return 1; }

  [[ "$(docker network inspect --format '{{.Id}}' "$NETWORK_NAME" 2>"$RAW/network-contract.log")" == "$NETWORK_ID" ]] \
    || { printf 'NETWORK_NAME_ID_MAPPING_FAILED\n'; return 1; }
  [[ "$(docker network inspect --format '{{.Name}}' "$NETWORK_NAME" 2>>"$RAW/network-contract.log")" == "$NETWORK_NAME" ]] \
    || { printf 'NETWORK_NAME_ID_MAPPING_FAILED\n'; return 1; }
  [[ "$(docker network inspect --format '{{.Driver}}' "$NETWORK_NAME" 2>>"$RAW/network-contract.log")" == "bridge" ]] \
    || { printf 'NETWORK_DRIVER_MISMATCH\n'; return 1; }
  [[ "$(docker network inspect --format '{{.Scope}}' "$NETWORK_NAME" 2>>"$RAW/network-contract.log")" == "local" ]] \
    || { printf 'NETWORK_SCOPE_MISMATCH\n'; return 1; }
  if [[ "$MODE" == "firewall-rehearsal" ]]; then
    [[ "$(docker network inspect --format '{{.Internal}}' "$NETWORK_NAME" 2>>"$RAW/network-contract.log")" == "false" ]] \
      || { printf 'NETWORK_UNEXPECTEDLY_INTERNAL\n'; return 1; }
  else
    [[ "$(docker network inspect --format '{{.Internal}}' "$NETWORK_NAME" 2>>"$RAW/network-contract.log")" == "true" ]] \
      || { printf 'NETWORK_NOT_INTERNAL\n'; return 1; }
  fi
  [[ "$(docker network inspect --format '{{.EnableIPv6}}' "$NETWORK_NAME" 2>>"$RAW/network-contract.log")" == "false" ]] \
    || { printf 'NETWORK_IPV6_ENABLED\n'; return 1; }
  if [[ "$MODE" == "firewall-rehearsal" ]]; then
    validate_network_ipam_contract "$NETWORK_NAME" contract \
      || { printf 'NETWORK_IPAM_CONTRACT_MISMATCH\n'; return 1; }
  else
    [[ "$(docker network inspect --format '{{(index .IPAM.Config 0).Subnet}}' "$NETWORK_NAME" 2>>"$RAW/network-contract.log")" == "$SUBNET" ]] \
      || { printf 'NETWORK_SUBNET_MISMATCH\n'; return 1; }
  fi
  [[ "$(docker network inspect --format '{{index .Options "com.docker.network.bridge.host_binding_ipv4"}}' "$NETWORK_NAME" 2>>"$RAW/network-contract.log")" == "127.0.0.1" ]] \
    || { printf 'NETWORK_HOST_BINDING_MISMATCH\n'; return 1; }
  if [[ "$MODE" == "firewall-rehearsal" ]]; then
    [[ "$(docker network inspect --format '{{index .Options "com.docker.network.bridge.gateway_mode_ipv4"}}' "$NETWORK_NAME" 2>>"$RAW/network-contract.log")" == "nat" ]] \
      || { printf 'NETWORK_GATEWAY_MODE_MISMATCH\n'; return 1; }
    [[ "$(docker network inspect --format '{{index .Options "com.docker.network.bridge.name"}}' "$NETWORK_NAME" 2>>"$RAW/network-contract.log")" == "$FIREWALL_BRIDGE_NAME" ]] \
      || { printf 'NETWORK_BRIDGE_NAME_MISMATCH\n'; return 1; }
  else
    [[ "$(docker network inspect --format '{{index .Options "com.docker.network.bridge.gateway_mode_ipv4"}}' "$NETWORK_NAME" 2>>"$RAW/network-contract.log")" == "isolated" ]] \
      || { printf 'NETWORK_GATEWAY_MODE_MISMATCH\n'; return 1; }
  fi
  [[ "$(docker network inspect --format '{{index .Labels "io.fawxzzy.packet"}}' "$NETWORK_NAME" 2>>"$RAW/network-contract.log")" == "$PACKET" ]] \
    || { printf 'NETWORK_LABEL_MISMATCH\n'; return 1; }
  [[ "$(docker network inspect --format '{{index .Labels "io.fawxzzy.role"}}' "$NETWORK_NAME" 2>>"$RAW/network-contract.log")" == "$NETWORK_ROLE" ]] \
    || { printf 'NETWORK_LABEL_MISMATCH\n'; return 1; }
  [[ "$(docker network inspect --format '{{index .Labels "com.supabase.cli.project"}}' "$NETWORK_NAME" 2>>"$RAW/network-contract.log")" == "$PROJECT" ]] \
    || { printf 'NETWORK_LABEL_MISMATCH\n'; return 1; }
  [[ "$(docker network inspect --format '{{index .Labels "com.docker.compose.project"}}' "$NETWORK_NAME" 2>>"$RAW/network-contract.log")" == "$PROJECT" ]] \
    || { printf 'NETWORK_LABEL_MISMATCH\n'; return 1; }

  endpoint_ids="$(docker network inspect \
    --format '{{range $id, $_ := .Containers}}{{println $id}}{{end}}' \
    "$NETWORK_NAME" 2>>"$RAW/network-contract.log")" \
    || { printf 'NETWORK_NAME_ID_MAPPING_FAILED\n'; return 1; }
  endpoint_count="$(printf '%s\n' "$endpoint_ids" | awk 'NF' | wc -l)"
  if [[ "$endpoint_mode" == "empty" ]]; then
    [[ "$endpoint_count" == "0" ]] || { printf 'NETWORK_PRESTART_ENDPOINTS_PRESENT\n'; return 1; }
  else
    allowed_ids="$(docker ps -aq --no-trunc --filter "label=com.supabase.cli.project=${PROJECT}" 2>/dev/null | awk 'NF' | sort -u)"
    while IFS= read -r id; do
      [[ -z "$id" ]] || grep -Fxq "$id" <<<"$allowed_ids" \
        || { printf 'UNEXPECTED_NETWORK_ENDPOINT\n'; return 1; }
    done <<<"$endpoint_ids"
  fi

  printf 'PASS\n'
}

assert_frozen_network() {
  local stage="$1" endpoint_mode="${2:-active}" code
  code="$(network_contract_code "$endpoint_mode")" || true
  [[ "$code" == "PASS" ]] || block "${code:-NETWORK_NAME_ID_MAPPING_FAILED}" "$stage"
  record "network.${stage}_exact_id" bool true
}

first_observer_violation() {
  local code
  code="$(python3 -c 'import json,sys; print(json.loads(open(sys.argv[1]).readline())["violations"][0])' "$VIOLATION_FILE" 2>/dev/null || printf UNKNOWN)"
  [[ "$code" =~ ^[A-Z0-9_]+$ ]] || code=CONTAINER_AUDIT_REJECTED
  printf '%s\n' "$code"
}

current_failure_code() {
  awk -F $'\t' '$1=="failure.code"{code=$3} END{print code}' "$STATE_FILE" 2>/dev/null
}

current_listener_phase() {
  awk -F $'\t' '$1=="listener_diagnostic.last_phase"{phase=$3} END{print phase}' "$STATE_FILE" 2>/dev/null
}

stop_watcher() {
  if [[ -n "$WATCH_PID" ]] && kill -0 "$WATCH_PID" 2>/dev/null; then
    kill "$WATCH_PID" 2>/dev/null || true
    for _ in $(seq 1 50); do
      kill -0 "$WATCH_PID" 2>/dev/null || break
      sleep 0.1
    done
    kill -KILL "$WATCH_PID" 2>/dev/null || true
    wait "$WATCH_PID" 2>/dev/null || true
  fi
  WATCH_PID=""
}

stop_docker_api_observer() {
  local observer_rc=0 forced=0
  if [[ -z "$DOCKER_API_OBSERVER_PID" ]]; then
    return 0
  fi
  if kill -0 "$DOCKER_API_OBSERVER_PID" 2>/dev/null; then
    kill "$DOCKER_API_OBSERVER_PID" 2>/dev/null || true
    for _ in $(seq 1 50); do
      kill -0 "$DOCKER_API_OBSERVER_PID" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$DOCKER_API_OBSERVER_PID" 2>/dev/null; then
      forced=1
      kill -KILL "$DOCKER_API_OBSERVER_PID" 2>/dev/null || true
    fi
  fi
  wait "$DOCKER_API_OBSERVER_PID" 2>/dev/null || observer_rc="$?"
  DOCKER_API_OBSERVER_PID=""
  [[ "$forced" == "0" ]] || return 124
  return "$observer_rc"
}

stop_host_test_listener() {
  if [[ -n "$HOST_TEST_LISTENER_PID" ]] && kill -0 "$HOST_TEST_LISTENER_PID" 2>/dev/null; then
    kill "$HOST_TEST_LISTENER_PID" 2>/dev/null || true
    for _ in $(seq 1 30); do
      kill -0 "$HOST_TEST_LISTENER_PID" 2>/dev/null || break
      sleep 0.1
    done
    kill -KILL "$HOST_TEST_LISTENER_PID" 2>/dev/null || true
    wait "$HOST_TEST_LISTENER_PID" 2>/dev/null || true
  fi
  HOST_TEST_LISTENER_PID=""
  rm -f -- "$HOST_TEST_READY"
}

cleanup_firewall_boundary() {
  local pre_firewall_container_count="$1" cleanup_mode_rc="$2" pre_firewall_network_count="$3"
  local pre_firewall_volume_count="$4" firewall_code
  record cleanup.containers_before_firewall_remove int "$pre_firewall_container_count"
  record cleanup.volumes_before_firewall_remove int "$pre_firewall_volume_count"
  record cleanup.networks_before_firewall_remove int "$pre_firewall_network_count"
  if [[ "$pre_firewall_container_count" != "0" ]]; then
    record cleanup.firewall.failure_code str FIREWALL_REMOVE_BLOCKED_BY_CONTAINER_RESIDUE
    return 1
  fi
  if [[ "$pre_firewall_network_count" != "0" ]]; then
    record cleanup.firewall.failure_code str FIREWALL_REMOVE_BLOCKED_BY_NETWORK_RESIDUE
    return 1
  fi
  if [[ "$pre_firewall_volume_count" != "0" ]]; then
    record cleanup.firewall.failure_code str FIREWALL_REMOVE_BLOCKED_BY_VOLUME_RESIDUE
    return 1
  fi
  if [[ "$cleanup_mode_rc" != "0" ]]; then
    record cleanup.firewall.failure_code str CLEANUP_MODE_CONTRACT_INVALID
    return 1
  fi
  if [[ "$CLEANUP_FIREWALL_REQUIRED" == "true" ]]; then
    record cleanup.firewall.required bool true
    if python3 -B "$ROOT/scripts/firewall_boundary.py" remove --ledger "$FIREWALL_LEDGER" \
      >"$FIREWALL_STATE_FILE" 2>"$RAW/firewall-rollback.log"; then
      sed 's/^firewall\./cleanup.firewall./' "$FIREWALL_STATE_FILE" >>"$STATE_FILE"
      if [[ "$MODE" != "cleanup-only" ]]; then
        sed 's/^firewall\./cleanup.firewall./' "$FIREWALL_STATE_FILE" >"$FIREWALL_ROLLBACK_RECEIPT"
        chmod 0600 "$FIREWALL_ROLLBACK_RECEIPT"
      elif [[ -f "$FIREWALL_ROLLBACK_RECEIPT" ]]; then
        cat "$FIREWALL_ROLLBACK_RECEIPT" >>"$STATE_FILE"
      fi
      return 0
    fi
    sed 's/^firewall\./cleanup.firewall./' "$FIREWALL_STATE_FILE" >>"$STATE_FILE" 2>/dev/null || true
    firewall_code="$(awk -F '\t' '$1=="firewall.failure_code"{print $3; exit}' "$FIREWALL_STATE_FILE" 2>/dev/null || true)"
    [[ "$firewall_code" =~ ^FIREWALL_[A-Z0-9_]+$ ]] || firewall_code=FIREWALL_ROLLBACK_FAILED
    record cleanup.firewall.failure_code str "$firewall_code"
    return 1
  fi
  record cleanup.firewall.required bool false
  if [[ -e "$FIREWALL_LEDGER" || -L "$FIREWALL_LEDGER" \
    || -e "$FIREWALL_COMPLETION" || -L "$FIREWALL_COMPLETION" \
    || -e "$FIREWALL_COMPLETION_STAGE" || -L "$FIREWALL_COMPLETION_STAGE" \
    || -e "$FIREWALL_ROLLBACK_RECEIPT" || -L "$FIREWALL_ROLLBACK_RECEIPT" ]]; then
    record cleanup.firewall.failure_code str CLEANUP_MODE_FIREWALL_STATE_MISMATCH
    return 1
  fi
  record cleanup.firewall.skipped_mode str "$CLEANUP_ORIGINAL_MODE"
}

record_cleanup_docker_query_failure() {
  local phase="$1" resource="$2" operation="$3" failure_class="$4"
  [[ "$CLEANUP_DOCKER_QUERY_FAILURE_RECORDED" == "0" ]] || return 0
  CLEANUP_DOCKER_QUERY_FAILURE_RECORDED=1
  record cleanup.docker_query.phase str "$phase"
  record cleanup.docker_query.resource str "$resource"
  record cleanup.docker_query.operation str "$operation"
  record cleanup.docker_query.failure_class str "$failure_class"
}

docker_cleanup_parse_query_file() {
  local resource="$1" phase="$2" query_output="$3" size last_byte value framed_size=0
  local -a records=()
  local -A query_seen=()
  DOCKER_CLEANUP_QUERY_RECORDS=()
  if [[ ! -f "$query_output" || -L "$query_output" ]]; then
    record_cleanup_docker_query_failure "$phase" "$resource" LIST MALFORMED_OUTPUT
    return 1
  fi
  if ! size="$(stat -c '%s' -- "$query_output" 2>>"$RAW/cleanup-docker-query.log")" \
    || [[ ! "$size" =~ ^[0-9]+$ ]]; then
    record_cleanup_docker_query_failure "$phase" "$resource" LIST MALFORMED_OUTPUT
    return 1
  fi
  [[ "$size" != "0" ]] || return 0
  if ! last_byte="$(od -An -tu1 -j "$((size - 1))" -N 1 -- "$query_output" \
    2>>"$RAW/cleanup-docker-query.log" | tr -d '[:space:]')" \
    || [[ "$last_byte" != "10" ]]; then
    record_cleanup_docker_query_failure "$phase" "$resource" LIST MALFORMED_OUTPUT
    return 1
  fi
  if ! mapfile -t records <"$query_output" || [[ "${#records[@]}" == "0" ]]; then
    record_cleanup_docker_query_failure "$phase" "$resource" LIST MALFORMED_OUTPUT
    return 1
  fi
  for value in "${records[@]}"; do
    case "$resource" in
      CONTAINER|NETWORK) [[ "$value" =~ ^[0-9a-f]{64}$ ]] ;;
      VOLUME) [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$ ]] ;;
      *) return 1 ;;
    esac || {
      record_cleanup_docker_query_failure "$phase" "$resource" LIST MALFORMED_OUTPUT
      return 1
    }
    if [[ -n "${query_seen[$value]+present}" ]]; then
      record_cleanup_docker_query_failure "$phase" "$resource" LIST MALFORMED_OUTPUT
      return 1
    fi
    query_seen["$value"]=1
    framed_size=$((framed_size + ${#value} + 1))
  done
  if [[ "$framed_size" != "$size" ]]; then
    record_cleanup_docker_query_failure "$phase" "$resource" LIST MALFORMED_OUTPUT
    return 1
  fi
  DOCKER_CLEANUP_QUERY_RECORDS=("${records[@]}")
}

docker_cleanup_query_ids() {
  local resource="$1" phase="$2" filter query_output parse_rc value
  local -a values=()
  local -A seen=()
  case "$resource" in CONTAINER|VOLUME|NETWORK) ;; *) return 1 ;; esac
  DOCKER_CLEANUP_QUERY_VALUES=()
  for filter in \
    "label=io.fawxzzy.packet=${CONTAINMENT_PACKET}" \
    "label=io.fawxzzy.packet=${DIRECT_PACKET}" \
    "label=io.fawxzzy.packet=${FIREWALL_PACKET}" \
    "label=com.supabase.cli.project=${PROJECT}"; do
    if ! query_output="$(mktemp "$RAW/cleanup-docker-query.XXXXXX")"; then
      record_cleanup_docker_query_failure "$phase" "$resource" LIST COMMAND_FAILED
      return 1
    fi
    case "$resource" in
      CONTAINER)
        if ! docker ps -aq --no-trunc --filter "$filter" >"$query_output" \
          2>>"$RAW/cleanup-docker-query.log"; then
          record_cleanup_docker_query_failure "$phase" "$resource" LIST COMMAND_FAILED
          rm -f -- "$query_output" 2>>"$RAW/cleanup-docker-query.log" || return 1
          return 1
        fi
        ;;
      VOLUME)
        if ! docker volume ls -q --filter "$filter" >"$query_output" \
          2>>"$RAW/cleanup-docker-query.log"; then
          record_cleanup_docker_query_failure "$phase" "$resource" LIST COMMAND_FAILED
          rm -f -- "$query_output" 2>>"$RAW/cleanup-docker-query.log" || return 1
          return 1
        fi
        ;;
      NETWORK)
        if ! docker network ls --no-trunc -q --filter "$filter" >"$query_output" \
          2>>"$RAW/cleanup-docker-query.log"; then
          record_cleanup_docker_query_failure "$phase" "$resource" LIST COMMAND_FAILED
          rm -f -- "$query_output" 2>>"$RAW/cleanup-docker-query.log" || return 1
          return 1
        fi
        ;;
    esac
    parse_rc=0
    docker_cleanup_parse_query_file "$resource" "$phase" "$query_output" || parse_rc=1
    if ! rm -f -- "$query_output" 2>>"$RAW/cleanup-docker-query.log"; then
      record_cleanup_docker_query_failure "$phase" "$resource" LIST COMMAND_FAILED
      return 1
    fi
    [[ "$parse_rc" == "0" ]] || return 1
    for value in "${DOCKER_CLEANUP_QUERY_RECORDS[@]}"; do
      if [[ -z "${seen[$value]+present}" ]]; then
        seen["$value"]=1
        values+=("$value")
      fi
    done
  done
  DOCKER_CLEANUP_QUERY_VALUES=("${values[@]}")
}

docker_cleanup_verify_ownership() {
  local resource="$1" reference="$2" phase="$3" packet_label project_label
  case "$resource" in
    CONTAINER)
      if ! packet_label="$(docker inspect --format '{{index .Config.Labels "io.fawxzzy.packet"}}' "$reference" 2>>"$RAW/cleanup-docker-query.log")"; then
        record_cleanup_docker_query_failure "$phase" "$resource" PACKET_LABEL_INSPECT COMMAND_FAILED
        return 1
      fi
      if ! project_label="$(docker inspect --format '{{index .Config.Labels "com.supabase.cli.project"}}' "$reference" 2>>"$RAW/cleanup-docker-query.log")"; then
        record_cleanup_docker_query_failure "$phase" "$resource" PROJECT_LABEL_INSPECT COMMAND_FAILED
        return 1
      fi
      ;;
    VOLUME)
      if ! packet_label="$(docker volume inspect --format '{{index .Labels "io.fawxzzy.packet"}}' "$reference" 2>>"$RAW/cleanup-docker-query.log")"; then
        record_cleanup_docker_query_failure "$phase" "$resource" PACKET_LABEL_INSPECT COMMAND_FAILED
        return 1
      fi
      if ! project_label="$(docker volume inspect --format '{{index .Labels "com.supabase.cli.project"}}' "$reference" 2>>"$RAW/cleanup-docker-query.log")"; then
        record_cleanup_docker_query_failure "$phase" "$resource" PROJECT_LABEL_INSPECT COMMAND_FAILED
        return 1
      fi
      ;;
    NETWORK)
      if ! packet_label="$(docker network inspect --format '{{index .Labels "io.fawxzzy.packet"}}' "$reference" 2>>"$RAW/cleanup-docker-query.log")"; then
        record_cleanup_docker_query_failure "$phase" "$resource" PACKET_LABEL_INSPECT COMMAND_FAILED
        return 1
      fi
      if ! project_label="$(docker network inspect --format '{{index .Labels "com.supabase.cli.project"}}' "$reference" 2>>"$RAW/cleanup-docker-query.log")"; then
        record_cleanup_docker_query_failure "$phase" "$resource" PROJECT_LABEL_INSPECT COMMAND_FAILED
        return 1
      fi
      ;;
    *) return 1 ;;
  esac
  case "$packet_label" in
    ""|"<no value>"|"$CONTAINMENT_PACKET"|"$DIRECT_PACKET"|"$FIREWALL_PACKET") ;;
    *)
      record_cleanup_docker_query_failure "$phase" "$resource" PACKET_LABEL_INSPECT MALFORMED_OUTPUT
      return 1
      ;;
  esac
  case "$project_label" in
    ""|"<no value>"|"$PROJECT") ;;
    *)
      record_cleanup_docker_query_failure "$phase" "$resource" PROJECT_LABEL_INSPECT MALFORMED_OUTPUT
      return 1
      ;;
  esac
  if [[ "$packet_label" != "$CONTAINMENT_PACKET" && "$packet_label" != "$DIRECT_PACKET" \
    && "$packet_label" != "$FIREWALL_PACKET" && "$project_label" != "$PROJECT" ]]; then
    record_cleanup_docker_query_failure "$phase" "$resource" OWNERSHIP OWNERSHIP_MISMATCH
    return 1
  fi
}

cleanup_exact() {
  local id listener_count="" container_count="" volume_count="" network_count=""
  local pre_firewall_container_count="" pre_firewall_volume_count="" pre_firewall_network_count=""
  local cleanup_mode_rc=0 cleanup_query_rc=0 firewall_rc=0 firewall_code
  local -a container_ids=() volume_names=() network_ids=()
  CLEANUP_DOCKER_QUERY_FAILURE_RECORDED=0
  if ! resolve_cleanup_mode_contract "$MODE"; then
    cleanup_mode_rc=1
    record cleanup.mode.failure_code str CLEANUP_MODE_CONTRACT_INVALID || true
  fi
  stop_docker_api_observer || true
  stop_watcher

  if docker_cleanup_query_ids CONTAINER ENUMERATE; then
    container_ids=("${DOCKER_CLEANUP_QUERY_VALUES[@]}")
  else
    cleanup_query_rc=1
  fi
  for id in "${container_ids[@]:-}"; do
    [[ -n "$id" ]] || continue
    if ! docker_cleanup_verify_ownership CONTAINER "$id" ENUMERATE; then
      cleanup_query_rc=1
      continue
    fi
    timeout --signal=TERM --kill-after=5s 20s docker rm -f "$id" >"$RAW/cleanup-container-${id:0:12}.log" 2>&1 || true
  done

  if docker_cleanup_query_ids VOLUME ENUMERATE; then
    volume_names=("${DOCKER_CLEANUP_QUERY_VALUES[@]}")
  else
    cleanup_query_rc=1
  fi
  for id in "${volume_names[@]:-}"; do
    [[ -n "$id" ]] || continue
    if ! docker_cleanup_verify_ownership VOLUME "$id" ENUMERATE; then
      cleanup_query_rc=1
      continue
    fi
    timeout --signal=TERM --kill-after=5s 20s docker volume rm "$id" >"$RAW/cleanup-volume.log" 2>&1 || true
  done

  stop_host_test_listener
  if docker_cleanup_query_ids NETWORK ENUMERATE; then
    network_ids=("${DOCKER_CLEANUP_QUERY_VALUES[@]}")
  else
    cleanup_query_rc=1
  fi
  for id in "${network_ids[@]:-}"; do
    [[ -n "$id" ]] || continue
    if ! docker_cleanup_verify_ownership NETWORK "$id" ENUMERATE; then
      cleanup_query_rc=1
      continue
    fi
    timeout --signal=TERM --kill-after=5s 20s docker network rm "$id" >"$RAW/cleanup-network-${id:0:12}.log" 2>&1 || true
  done

  if docker_cleanup_query_ids CONTAINER PRE_FIREWALL; then
    pre_firewall_container_count="${#DOCKER_CLEANUP_QUERY_VALUES[@]}"
  else
    cleanup_query_rc=1
  fi
  if docker_cleanup_query_ids VOLUME PRE_FIREWALL; then
    pre_firewall_volume_count="${#DOCKER_CLEANUP_QUERY_VALUES[@]}"
  else
    cleanup_query_rc=1
  fi
  if docker_cleanup_query_ids NETWORK PRE_FIREWALL; then
    pre_firewall_network_count="${#DOCKER_CLEANUP_QUERY_VALUES[@]}"
  else
    cleanup_query_rc=1
  fi
  if [[ "$cleanup_query_rc" == "0" && -n "$pre_firewall_container_count" \
    && -n "$pre_firewall_volume_count" && -n "$pre_firewall_network_count" ]]; then
    cleanup_firewall_boundary "$pre_firewall_container_count" "$cleanup_mode_rc" \
      "$pre_firewall_network_count" "$pre_firewall_volume_count" || firewall_rc=1
  else
    firewall_rc=1
    record cleanup.firewall.failure_code str FIREWALL_REMOVE_BLOCKED_BY_DOCKER_QUERY_FAILURE
  fi

  if docker_cleanup_query_ids CONTAINER FINAL_RESIDUE; then
    container_count="${#DOCKER_CLEANUP_QUERY_VALUES[@]}"
    record cleanup.containers_remaining int "$container_count"
  else
    cleanup_query_rc=1
  fi
  if docker_cleanup_query_ids VOLUME FINAL_RESIDUE; then
    volume_count="${#DOCKER_CLEANUP_QUERY_VALUES[@]}"
    record cleanup.volumes_remaining int "$volume_count"
  else
    cleanup_query_rc=1
  fi
  if docker_cleanup_query_ids NETWORK FINAL_RESIDUE; then
    network_count="${#DOCKER_CLEANUP_QUERY_VALUES[@]}"
    record cleanup.networks_remaining int "$network_count"
  else
    cleanup_query_rc=1
  fi
  if capture_listener_snapshot cleanup "$DB_PORT"; then
    listener_count="$LISTENER_SNAPSHOT_COUNT"
    record cleanup.listeners_remaining int "$listener_count"
  else
    listener_count=""
    record cleanup.listener_failure_code str "${LISTENER_FAILURE_CODE:-LISTENER_UNEXPECTED_INTERRUPTION}" || true
    record cleanup.listener_failure_phase str "${LISTENER_LAST_PHASE:-CLEANUP_PORT_56422_UNKNOWN}" || true
  fi

  [[ "$container_count" == "0" ]] || return 1
  [[ "$volume_count" == "0" ]] || return 1
  [[ "$network_count" == "0" ]] || return 1
  [[ "$cleanup_query_rc" == "0" ]] || return 1
  [[ "$cleanup_mode_rc" == "0" ]] || return 1
  [[ "$firewall_rc" == "0" && ! -e "$FIREWALL_LEDGER" ]] || return 1
  [[ "$listener_count" == "0" ]] || return 1
  timeout 2 bash -c "</dev/tcp/127.0.0.1/${DB_PORT}" >/dev/null 2>&1 && return 1
  native_listener_contract cleanup || return 1
  return 0
}

finalize() {
  local original_rc="$?" final_rc=1 final_status=BLOCKED network_code=PASS network_contract_ok=1
  local primary_failure listener_phase receipt_failure=0 cleanup_rc=0 scratch_rc=0
  [[ "$FINALIZING" == "0" ]] || return
  FINALIZING=1
  set +e

  primary_failure="$(current_failure_code)"
  listener_phase="$(current_listener_phase)"
  if [[ -z "$primary_failure" || "$primary_failure" == "HARNESS_INTERRUPTED" ]]; then
    if listener_phase_is_unexpected "$listener_phase"; then
      record status str BLOCKED
      record failure.code str LISTENER_UNEXPECTED_INTERRUPTION
      record failure.detail str "$listener_phase"
      record listener_diagnostic.unexpected_interruption_phase str "$listener_phase"
    fi
  fi

  if [[ ( "$MODE" == "run" || "$MODE" == "firewall-rehearsal" ) && -n "$NETWORK_ID" ]]; then
    network_code="$(network_contract_code active)" || true
    if [[ "$network_code" != "PASS" ]]; then
      network_contract_ok=0
      network_code="${network_code:-NETWORK_NAME_ID_MAPPING_FAILED}"
      record network.pre_cleanup_failure_code str "$network_code"
      primary_failure="$(current_failure_code)"
      if [[ -z "$primary_failure" || "$primary_failure" == "HARNESS_INTERRUPTED" ]]; then
        record status str BLOCKED
        record failure.code str "$network_code"
        record failure.detail str pre-cleanup-network-contract
      fi
    else
      record network.pre_cleanup_exact_id bool true
    fi
  fi

  if ! cleanup_exact; then
    cleanup_rc=1
    record cleanup.failure_code str CLEANUP_RESIDUE
    primary_failure="$(current_failure_code)"
    if [[ -z "$primary_failure" || "$primary_failure" == "HARNESS_INTERRUPTED" ]]; then
      record status str BLOCKED
      record failure.code str CLEANUP_RESIDUE
      record failure.detail str exact-packet-resource-remains
    fi
  fi
  if ! cleanup_packet_scratch primary; then
    scratch_rc=1
    record cleanup.scratch_failure_code str PACKET_SCRATCH_PROOF_FAILED || true
    primary_failure="$(current_failure_code)"
    if [[ -z "$primary_failure" || "$primary_failure" == "HARNESS_INTERRUPTED" ]]; then
      record status str BLOCKED || true
      record failure.code str PACKET_SCRATCH_PROOF_FAILED || true
      record failure.detail str packet-scratch-not-proven || true
    fi
  fi
  if [[ "$cleanup_rc" == "0" && "$scratch_rc" == "0" \
    && "$SMOKE_PASSED" == "1" && "$original_rc" == "0" && "$network_contract_ok" == "1" ]]; then
    if [[ "$MODE" == "direct-port" ]]; then
      record status str DIRECT_DOCKER_PORT_PATH_PASS
      final_status=DIRECT_DOCKER_PORT_PATH_PASS
    elif [[ "$MODE" == "firewall-rehearsal" ]]; then
      record status str FIREWALL_PUBLICATION_REHEARSAL_PASS
      record failure json null
      final_status=FIREWALL_PUBLICATION_REHEARSAL_PASS
    else
      record status str CONTAINMENT_SMOKE_PASS
      final_status=CONTAINMENT_SMOKE_PASS
    fi
    final_rc=0
  elif [[ "$cleanup_rc" == "0" && "$scratch_rc" == "0" ]]; then
    if ! grep -q $'^status\tstr\tBLOCKED$' "$STATE_FILE" 2>/dev/null; then
      record status str BLOCKED
      record failure.code str HARNESS_INTERRUPTED
      record failure.detail str unexpected-nonzero-exit
    fi
  fi

  if ! publish_result_receipt "$final_status" replace; then
    receipt_failure=1
    primary_failure="$(current_failure_code)"
    record receipt.authoritative bool false || true
    record receipt.publication_failure_code str RESULT_RECEIPT_PUBLICATION_FAILED || true
    if [[ "$final_status" != "BLOCKED" ]]; then
      record status str BLOCKED || true
      record failure.code str RESULT_RECEIPT_PUBLICATION_FAILED || true
      record failure.detail str authoritative-result-publication-failed || true
    else
      record receipt.original_failure_code str "${primary_failure:-UNKNOWN}" || true
    fi
    rm -f -- "$RESULT_FILE" "$RESULT_STAGE_FILE"
    final_status=BLOCKED
    final_rc=1
    printf 'BLOCKED: RESULT_RECEIPT_PUBLICATION_FAILED\n'
  elif [[ "$final_status" == "BLOCKED" ]]; then
    failure_code="$(python3 -c 'import json,sys; print((json.load(open(sys.argv[1])).get("failure") or {}).get("code","UNKNOWN"))' "$RESULT_FILE" 2>/dev/null || printf UNKNOWN)"
    printf 'BLOCKED: %s\n' "$failure_code"
  else
    printf '%s\n' "$final_status"
  fi

  [[ "$receipt_failure" != "0" ]] || rm -f -- "$STATE_FILE"
  trap - EXIT
  exit "$final_rc"
}

cleanup_only() {
  local cleanup_rc=0 recovery_state=0 expected_status=BLOCKED publish_operation=merge scratch_rc=0
  local primary_failure existing_status="" existing_failure=""
  mkdir -p -- "$RAW" "$RUNTIME_HOME" "$PROJECT_DIR/supabase" "$ROOT/artifacts"
  if [[ -e "$STATE_FILE" || -L "$STATE_FILE" ]]; then
    [[ -f "$STATE_FILE" && ! -L "$STATE_FILE" ]] || {
      printf 'BLOCKED: RESULT_RECEIPT_RECOVERY_STATE_INVALID\n'
      exit 1
    }
    recovery_state=1
    publish_operation=replace
  elif [[ -e "$CLEANUP_STATE_FILE" || -L "$CLEANUP_STATE_FILE" ]]; then
    [[ -f "$CLEANUP_STATE_FILE" && ! -L "$CLEANUP_STATE_FILE" ]] || {
      printf 'BLOCKED: RESULT_RECEIPT_RECOVERY_STATE_INVALID\n'
      exit 1
    }
    STATE_FILE="$CLEANUP_STATE_FILE"
    recovery_state=1
    publish_operation=replace
  else
    STATE_FILE="$CLEANUP_STATE_FILE"
    : >"$STATE_FILE"
  fi
  if [[ "$recovery_state" == "1" ]]; then
    record receipt.recovery_attempted bool true || cleanup_rc=1
    record receipt.authoritative bool true || cleanup_rc=1
  fi
  [[ -e "$AUDIT_FILE" ]] || : >"$AUDIT_FILE"

  if [[ -f "$RESULT_FILE" && ! -L "$RESULT_FILE" ]]; then
    if ! existing_status="$(result_receipt_status)"; then
      cleanup_rc=1
      publish_operation=replace
      record status str BLOCKED || true
      record failure.code str RESULT_RECEIPT_VALIDATION_FAILED || true
      record failure.detail str authoritative-result-invalid || true
    elif [[ "$existing_status" == "BLOCKED" ]]; then
      if ! existing_failure="$(result_receipt_failure_code)"; then
        cleanup_rc=1
        publish_operation=replace
        record status str BLOCKED || true
        record failure.code str RESULT_RECEIPT_VALIDATION_FAILED || true
        record failure.detail str authoritative-result-invalid || true
      else
        record status str BLOCKED || cleanup_rc=1
        record failure.code str "$existing_failure" || cleanup_rc=1
        record failure.detail str prior-run-failure-preserved || cleanup_rc=1
      fi
    fi
  elif [[ -e "$RESULT_FILE" || -L "$RESULT_FILE" ]]; then
    cleanup_rc=1
    publish_operation=replace
    record status str BLOCKED || true
    record failure.code str RESULT_RECEIPT_VALIDATION_FAILED || true
    record failure.detail str authoritative-result-invalid || true
  fi

  if ! cleanup_exact; then
    record cleanup.failure_code str CLEANUP_RESIDUE
    primary_failure="$(current_failure_code)"
    record status str BLOCKED
    if [[ -z "$primary_failure" || "$primary_failure" == "HARNESS_INTERRUPTED" ]]; then
      record failure.code str CLEANUP_RESIDUE
      record failure.detail str exact-packet-resource-remains
    fi
    cleanup_rc=1
  fi
  if ! cleanup_packet_scratch cleanup; then
    scratch_rc=1
    cleanup_rc=1
    record cleanup.scratch_failure_code str PACKET_SCRATCH_PROOF_FAILED || true
    primary_failure="$(current_failure_code)"
    record status str BLOCKED || true
    if [[ -z "$primary_failure" || "$primary_failure" == "HARNESS_INTERRUPTED" ]]; then
      record failure.code str PACKET_SCRATCH_PROOF_FAILED || true
      record failure.detail str packet-scratch-not-proven || true
    fi
  fi
  if [[ ! -f "$RESULT_FILE" ]]; then
    publish_operation=replace
    if [[ "$recovery_state" == "1" && "$cleanup_rc" == "0" ]]; then
      record status str BLOCKED
      record receipt.recovered_by_cleanup bool true
    elif [[ "$recovery_state" == "0" && "$cleanup_rc" == "0" && "$RESULT_PROFILE" == "direct-docker-port-v1" ]]; then
      record result.profile str direct-docker-port-v1
      record status str BLOCKED
      record failure.code str HARNESS_INTERRUPTED
      record failure.detail str cleanup-step-recovered-interrupted-run
    elif [[ "$recovery_state" == "0" && "$cleanup_rc" == "0" ]]; then
      record status str BLOCKED
      record failure.code str HARNESS_INTERRUPTED
      record failure.detail str cleanup-step-recovered-interrupted-run
    fi
  fi

  if [[ "$cleanup_rc" == "0" && -n "$existing_status" ]]; then
    expected_status="$existing_status"
  fi
  [[ "$cleanup_rc" == "0" ]] || expected_status=BLOCKED
  if ! publish_result_receipt "$expected_status" "$publish_operation"; then
    cleanup_rc=1
    primary_failure="$(current_failure_code)"
    record receipt.authoritative bool false || true
    record receipt.publication_failure_code str RESULT_RECEIPT_PUBLICATION_FAILED || true
    if [[ -z "$primary_failure" || "$primary_failure" == "HARNESS_INTERRUPTED" ]]; then
      record status str BLOCKED || true
      record failure.code str RESULT_RECEIPT_PUBLICATION_FAILED || true
      record failure.detail str cleanup-result-publication-failed || true
    else
      record receipt.original_failure_code str "$primary_failure" || true
    fi
    [[ "$existing_status" == "BLOCKED" ]] || rm -f -- "$RESULT_FILE"
    rm -f -- "$RESULT_STAGE_FILE"
  fi
  if [[ "$cleanup_rc" == "0" ]]; then
    retire_cleanup_mode_contract || cleanup_rc=1
  fi

  if [[ "$cleanup_rc" == "0" ]]; then
    rm -f -- "$STATE_FILE" "$CLEANUP_STATE_FILE"
    rm -f -- "$FIREWALL_ROLLBACK_RECEIPT"
  fi
  [[ "$cleanup_rc" == "0" ]] || exit "$cleanup_rc"
  printf 'CLEANUP_EXACT_PASS\n'
  exit 0
}

run_direct_port_probe() {
  local db_password db_id create_rc correlated_count probe_rc failure_code
  local probe_state="$RUNTIME/direct-port-probe.tsv"

  record diagnostic.timing.started_at str "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  db_password="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" || block DIRECT_CREDENTIAL_GENERATION_FAILED
  [[ -n "$db_password" ]] || block DIRECT_CREDENTIAL_GENERATION_FAILED
  printf '::add-mask::%s\n' "$db_password"
  export POSTGRES_PASSWORD="$db_password"

  set +e
  db_id="$(timeout --signal=TERM --kill-after=5s 30s docker run -d \
    --pull=never \
    --platform linux/amd64 \
    --name "$DIRECT_DB_NAME" \
    --label "io.fawxzzy.packet=${DIRECT_PACKET}" \
    --label "io.fawxzzy.role=direct-postgres" \
    --label "com.supabase.cli.project=${PROJECT}" \
    --label "com.docker.compose.project=${PROJECT}" \
    --network "$NETWORK_ID" \
    --publish "${DB_PORT}:5432" \
    --tmpfs "/var/lib/postgresql/data:rw,nosuid,nodev,noexec,size=1g" \
    --restart=no \
    --health-cmd='pg_isready -U postgres -h 127.0.0.1' \
    --health-interval=1s \
    --health-timeout=2s \
    --health-start-period=30s \
    --health-retries=30 \
    --env POSTGRES_PASSWORD \
    "$POSTGRES_PULL" 2>"$RAW/direct-container-create.log")"
  create_rc="$?"
  set -e
  unset POSTGRES_PASSWORD db_password
  [[ "$create_rc" != "124" ]] || block DIRECT_CONTAINER_CREATE_TIMEOUT
  [[ "$create_rc" == "0" && -n "$db_id" ]] || block DIRECT_CONTAINER_CREATE_FAILED "docker-exit-${create_rc}"

  correlated_count="$(docker ps -q \
    --filter "label=io.fawxzzy.packet=${DIRECT_PACKET}" \
    --filter "label=io.fawxzzy.role=direct-postgres" | awk 'NF' | wc -l)"
  [[ "$correlated_count" == "1" ]] || block DIRECT_CONTAINER_COUNT_MISMATCH

  set +e
  python3 -B "$ROOT/scripts/direct_port_probe.py" \
    --container-id "$db_id" \
    --network-id "$NETWORK_ID" \
    --image-id "$POSTGRES_IMAGE_ID" \
    --image-reference "$POSTGRES_PULL" \
    --health-timeout-seconds 120 \
    --stable-seconds 10 >"$probe_state" 2>"$RAW/direct-port-probe.log"
  probe_rc="$?"
  set -e
  [[ -f "$probe_state" ]] || block DIRECT_PROBE_RESULT_MISSING
  cat "$probe_state" >>"$STATE_FILE"
  if [[ "$probe_rc" != "0" ]]; then
    failure_code="$(awk -F '\t' '$1=="diagnostic.probe.failure_code"{print $3; exit}' "$probe_state")"
    [[ "$failure_code" =~ ^[A-Z0-9_]+$ ]] || failure_code=DIRECT_PROBE_FAILED
    block "$failure_code"
  fi

  record diagnostic.timing.completed_at str "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  SMOKE_PASSED=1
}

firewall_counter_value() {
  local counter="$1" counter_file="$RUNTIME/firewall-counters.tsv" value
  python3 -B "$ROOT/scripts/firewall_boundary.py" counters --ledger "$FIREWALL_LEDGER" \
    >"$counter_file" 2>"$RAW/firewall-counters.log" || block FIREWALL_COUNTER_READ_FAILED
  [[ "$(wc -l <"$counter_file" | tr -d ' ')" == "3" ]] || block FIREWALL_COUNTER_INVALID
  value="$(awk -F '\t' -v key="firewall.counters.${counter}" '$1==key && $2=="int"{print $3; exit}' "$counter_file")"
  [[ "$value" =~ ^[0-9]+$ ]] || block FIREWALL_COUNTER_INVALID
  printf '%s\n' "$value"
}

firewall_phase_finish() {
  local terminal_class="$1" manifest_count manifest_sha accounting_matches=true setup_class
  manifest_count="$(wc -l <"$FIREWALL_PHASE_MANIFEST" | tr -d ' ')"
  [[ "$manifest_count" =~ ^[0-9]+$ && "$manifest_count" == "$FIREWALL_PHASE_SNAPSHOT_COUNT" ]] \
    || block FIREWALL_PHASE_MANIFEST_INVALID
  manifest_sha="$(sha256sum <"$FIREWALL_PHASE_MANIFEST" | awk '{print $1}')"
  [[ "$manifest_sha" =~ ^[0-9a-f]{64}$ ]] || block FIREWALL_PHASE_MANIFEST_INVALID
  record diagnostic.precanary.phase_manifest_count int "$manifest_count"
  record diagnostic.precanary.phase_manifest_sha256 str "$manifest_sha"
  record diagnostic.precanary.enforcement_manifest_count int "$manifest_count"
  record diagnostic.precanary.enforcement_manifest_sha256 str "$manifest_sha"
  record diagnostic.precanary.final_input_count int "$FIREWALL_PHASE_PREV_INPUT"
  record diagnostic.precanary.final_forward_count int "$FIREWALL_PHASE_PREV_FORWARD"
  record diagnostic.precanary.final_output_count int "$FIREWALL_PHASE_PREV_OUTPUT"
  if [[ "$FIREWALL_PHASE_SUM_INPUT" != "$FIREWALL_PHASE_PREV_INPUT" \
    || "$FIREWALL_PHASE_SUM_FORWARD" != "$FIREWALL_PHASE_PREV_FORWARD" \
    || "$FIREWALL_PHASE_SUM_OUTPUT" != "$FIREWALL_PHASE_PREV_OUTPUT" ]]; then
    accounting_matches=false
  fi
  record diagnostic.precanary.delta_sum_matches_final bool "$accounting_matches"
  record diagnostic.precanary.terminal_class str "$terminal_class"
  [[ "$accounting_matches" == "true" ]] || block FIREWALL_PHASE_ACCOUNTING_FAILED
  if [[ "$terminal_class" == "PRECANARY_SETUP_QUIESCENT" ]]; then
    [[ "$manifest_count" == "10" ]] || block FIREWALL_PHASE_MANIFEST_INVALID
    if [[ "$FIREWALL_FIRST_HIT_FROZEN" == "1" ]]; then
      [[ "$FIREWALL_FIRST_HIT_CLASS" == "ROOT_DNS_OUTPUT_SETUP_OR_AMBIENT_HIT" ]] \
        || block FIREWALL_SETUP_CLASS_INVALID
      setup_class="$FIREWALL_FIRST_HIT_CLASS"
    else
      setup_class=NO_SETUP_ENFORCEMENT_HIT
    fi
    record diagnostic.precanary.setup_class str "$setup_class"
    record diagnostic.precanary.setup_output_total int "$FIREWALL_SETUP_OUTPUT_TOTAL"
    record diagnostic.precanary.quiescent bool true
    record diagnostic.precanary.complete bool true
    return 0
  fi
  block "$terminal_class"
}

firewall_phase_snapshot() {
  local phase="$1" input_absolute forward_absolute output_absolute
  local input_delta forward_delta output_delta monotonic=true chain terminal_class expected_phase
  case "$phase" in
    post_install|host_listener_ready|foreign_container_started|published_service_started|packet_client_started|shape_network_health_validated|publication_probes_complete|client_tool_preflight_complete|quiescence_first|quiescence_second) ;;
    *) block FIREWALL_PHASE_ENUM_INVALID ;;
  esac
  case "$(( FIREWALL_PHASE_SNAPSHOT_COUNT + 1 ))" in
    1) expected_phase=post_install ;;
    2) expected_phase=host_listener_ready ;;
    3) expected_phase=foreign_container_started ;;
    4) expected_phase=published_service_started ;;
    5) expected_phase=packet_client_started ;;
    6) expected_phase=shape_network_health_validated ;;
    7) expected_phase=publication_probes_complete ;;
    8) expected_phase=client_tool_preflight_complete ;;
    9) expected_phase=quiescence_first ;;
    10) expected_phase=quiescence_second ;;
    *) block FIREWALL_PHASE_ORDER_INVALID ;;
  esac
  [[ "$phase" == "$expected_phase" ]] || block FIREWALL_PHASE_ORDER_INVALID
  if [[ "$FIREWALL_PHASE_SNAPSHOT_COUNT" == "0" ]]; then
    [[ ! -e "$FIREWALL_PHASE_MANIFEST" ]] || block FIREWALL_PHASE_MANIFEST_COLLISION
    : >"$FIREWALL_PHASE_MANIFEST"
  fi
  input_absolute="$(firewall_counter_value input_deny)"
  forward_absolute="$(firewall_counter_value forward_deny)"
  output_absolute="$(firewall_counter_value output_deny)"
  input_delta="$(( input_absolute - FIREWALL_PHASE_PREV_INPUT ))"
  forward_delta="$(( forward_absolute - FIREWALL_PHASE_PREV_FORWARD ))"
  output_delta="$(( output_absolute - FIREWALL_PHASE_PREV_OUTPUT ))"
  if (( input_delta < 0 || forward_delta < 0 || output_delta < 0 )); then
    monotonic=false
  fi
  FIREWALL_PHASE_SNAPSHOT_COUNT="$(( FIREWALL_PHASE_SNAPSHOT_COUNT + 1 ))"
  FIREWALL_PHASE_SUM_INPUT="$(( FIREWALL_PHASE_SUM_INPUT + input_delta ))"
  FIREWALL_PHASE_SUM_FORWARD="$(( FIREWALL_PHASE_SUM_FORWARD + forward_delta ))"
  FIREWALL_PHASE_SUM_OUTPUT="$(( FIREWALL_PHASE_SUM_OUTPUT + output_delta ))"
  printf '%02d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$FIREWALL_PHASE_SNAPSHOT_COUNT" "$phase" \
    "$input_absolute" "$forward_absolute" "$output_absolute" \
    "$input_delta" "$forward_delta" "$output_delta" "$monotonic" \
    >>"$FIREWALL_PHASE_MANIFEST"
  record "diagnostic.precanary.phases.${phase}.index" int "$FIREWALL_PHASE_SNAPSHOT_COUNT"
  record "diagnostic.precanary.phases.${phase}.input_absolute" int "$input_absolute"
  record "diagnostic.precanary.phases.${phase}.forward_absolute" int "$forward_absolute"
  record "diagnostic.precanary.phases.${phase}.output_absolute" int "$output_absolute"
  record "diagnostic.precanary.phases.${phase}.input_delta" int "$input_delta"
  record "diagnostic.precanary.phases.${phase}.forward_delta" int "$forward_delta"
  record "diagnostic.precanary.phases.${phase}.output_delta" int "$output_delta"
  record "diagnostic.precanary.phases.${phase}.monotonic" bool "$monotonic"
  FIREWALL_PHASE_PREV_INPUT="$input_absolute"
  FIREWALL_PHASE_PREV_FORWARD="$forward_absolute"
  FIREWALL_PHASE_PREV_OUTPUT="$output_absolute"

  if [[ "$monotonic" != "true" ]]; then
    firewall_phase_finish FIREWALL_COUNTER_NONMONOTONIC
    return $?
  fi
  if (( input_delta > 0 || forward_delta > 0 || output_delta > 0 )); then
    if (( (input_delta > 0) + (forward_delta > 0) + (output_delta > 0) > 1 )); then
      chain=MULTIPLE
      terminal_class=MULTICHAIN_SETUP_HIT
    elif (( output_delta > 0 )); then
      chain=OUTPUT
      terminal_class=ROOT_DNS_OUTPUT_SETUP_OR_AMBIENT_HIT
    elif (( input_delta > 0 )); then
      chain=INPUT
      terminal_class=PACKET_INPUT_SETUP_HIT
    else
      chain=FORWARD
      terminal_class=PACKET_FORWARD_SETUP_HIT
    fi
    if [[ "$phase" == "post_install" ]]; then
      terminal_class=INSTALL_WINDOW_HIT
    elif [[ "$phase" == "quiescence_second" ]]; then
      terminal_class=QUIESCENCE_HIT
    fi
    if [[ "$FIREWALL_FIRST_HIT_FROZEN" == "0" ]]; then
      FIREWALL_FIRST_HIT_FROZEN=1
      FIREWALL_FIRST_HIT_CLASS="$terminal_class"
      record diagnostic.precanary.first_hit_phase str "$phase"
      record diagnostic.precanary.first_hit_chain str "$chain"
      record diagnostic.precanary.first_hit_input_delta int "$input_delta"
      record diagnostic.precanary.first_hit_forward_delta int "$forward_delta"
      record diagnostic.precanary.first_hit_output_delta int "$output_delta"
      record diagnostic.precanary.first_hit_monotonic bool true
    fi
    if [[ "$terminal_class" != "ROOT_DNS_OUTPUT_SETUP_OR_AMBIENT_HIT" ]]; then
      firewall_phase_finish "$terminal_class"
      return $?
    fi
    FIREWALL_SETUP_OUTPUT_TOTAL="$(( FIREWALL_SETUP_OUTPUT_TOTAL + output_delta ))"
  fi
}

firewall_marker_snapshot() {
  local target_name="$1" marker_file="$RUNTIME/firewall-marker-counters.tsv" name value
  local -n target="$target_name"
  python3 -B "$ROOT/scripts/firewall_boundary.py" marker-counters --ledger "$FIREWALL_LEDGER" \
    >"$marker_file" 2>"$RAW/firewall-marker-counters.log" || block FIREWALL_MARKER_COUNTER_READ_FAILED
  [[ "$(wc -l <"$marker_file" | tr -d ' ')" == "7" ]] || block FIREWALL_MARKER_COUNTER_INVALID
  target=()
  for name in same_network external_dns literal_ip metadata gateway host_listener foreign_network; do
    value="$(awk -F '\t' -v key="firewall.markers.counters.${name}" \
      '$1==key && $2=="int"{print $3; exit}' "$marker_file")"
    [[ "$value" =~ ^[0-9]+$ ]] || block FIREWALL_MARKER_COUNTER_INVALID
    target["$name"]="$value"
  done
}

firewall_install_marker_boundary() {
  local client_ip="$1" service_ip="$2" foreign_ip="$3"
  local marker_install_state="$RUNTIME/firewall-marker-install.tsv" failure_code
  local input_before forward_before output_before input_after forward_after output_after
  local gap_input_delta gap_forward_delta gap_output_delta
  local input_delta forward_delta output_delta baseline_sha name
  local -A marker_baseline=()
  input_before="$(firewall_counter_value input_deny)"
  forward_before="$(firewall_counter_value forward_deny)"
  output_before="$(firewall_counter_value output_deny)"
  gap_input_delta="$(( input_before - FIREWALL_PHASE_PREV_INPUT ))"
  gap_forward_delta="$(( forward_before - FIREWALL_PHASE_PREV_FORWARD ))"
  gap_output_delta="$(( output_before - FIREWALL_PHASE_PREV_OUTPUT ))"
  record firewall.markers.preinstall_gap_input_delta int "$gap_input_delta"
  record firewall.markers.preinstall_gap_forward_delta int "$gap_forward_delta"
  record firewall.markers.preinstall_gap_output_delta int "$gap_output_delta"
  (( gap_input_delta >= 0 && gap_forward_delta >= 0 && gap_output_delta >= 0 )) \
    || block FIREWALL_COUNTER_NONMONOTONIC
  (( gap_input_delta == 0 && gap_forward_delta == 0 && gap_output_delta == 0 )) \
    || block FIREWALL_QUIESCENCE_LOST_BEFORE_MARKER_INSTALL
  python3 -B "$ROOT/scripts/firewall_boundary.py" install-markers \
    --ledger "$FIREWALL_LEDGER" \
    --client-ip "$client_ip" \
    --service-ip "$service_ip" \
    --foreign-ip "$foreign_ip" \
    --gateway-ip "$SUBNET_GATEWAY" \
    --host-port "$HOST_TEST_PORT" >"$marker_install_state" 2>"$RAW/firewall-marker-install.log" \
    || {
      failure_code="$(awk -F '\t' '$1=="firewall.failure_code"{print $3; exit}' "$marker_install_state" 2>/dev/null || true)"
      [[ "$failure_code" =~ ^FIREWALL_[A-Z0-9_]+$ ]] || failure_code=FIREWALL_MARKER_INSTALL_FAILED
      block "$failure_code"
    }
  cat "$marker_install_state" >>"$STATE_FILE"
  input_after="$(firewall_counter_value input_deny)"
  forward_after="$(firewall_counter_value forward_deny)"
  output_after="$(firewall_counter_value output_deny)"
  input_delta="$(( input_after - input_before ))"
  forward_delta="$(( forward_after - forward_before ))"
  output_delta="$(( output_after - output_before ))"
  record firewall.markers.install_enforcement_input_delta int "$input_delta"
  record firewall.markers.install_enforcement_forward_delta int "$forward_delta"
  record firewall.markers.install_enforcement_output_delta int "$output_delta"
  (( input_delta >= 0 && forward_delta >= 0 && output_delta >= 0 )) || block FIREWALL_COUNTER_NONMONOTONIC
  (( input_delta == 0 && forward_delta == 0 && output_delta == 0 )) \
    || block FIREWALL_ENFORCEMENT_MOVED_DURING_MARKER_INSTALL
  firewall_marker_snapshot marker_baseline
  for name in same_network external_dns literal_ip metadata gateway host_listener foreign_network; do
    record "firewall.markers.baseline.${name}" int "${marker_baseline[$name]}"
    [[ "${marker_baseline[$name]}" == "0" ]] || block FIREWALL_MARKER_BASELINE_NONZERO
  done
  baseline_sha="$(printf '%s\n' \
    "same_network=${marker_baseline[same_network]}" \
    "external_dns=${marker_baseline[external_dns]}" \
    "literal_ip=${marker_baseline[literal_ip]}" \
    "metadata=${marker_baseline[metadata]}" \
    "gateway=${marker_baseline[gateway]}" \
    "host_listener=${marker_baseline[host_listener]}" \
    "foreign_network=${marker_baseline[foreign_network]}" \
    | sha256sum | awk '{print $1}')"
  [[ "$baseline_sha" =~ ^[0-9a-f]{64}$ ]] || block FIREWALL_MARKER_BASELINE_INVALID
  record firewall.markers.baseline_zero bool true
  record firewall.markers.baseline_sha256 str "$baseline_sha"
  FIREWALL_CANARY_BASE_INPUT="$input_after"
  FIREWALL_CANARY_BASE_FORWARD="$forward_after"
  FIREWALL_CANARY_BASE_OUTPUT="$output_after"
  record firewall.enforcement.canary_baseline_input int "$FIREWALL_CANARY_BASE_INPUT"
  record firewall.enforcement.canary_baseline_forward int "$FIREWALL_CANARY_BASE_FORWARD"
  record firewall.enforcement.canary_baseline_output int "$FIREWALL_CANARY_BASE_OUTPUT"
}

firewall_record_canary_evidence() {
  local receipt_key="$1" command_rc="$2" command_exit_class="$3"
  local input_delta="$4" forward_delta="$5" output_delta="$6"
  local before_name="$7" after_name="$8" marker_delta name
  local -n before_ref="$before_name" after_ref="$after_name"
  FIREWALL_MARKER_MANIFEST_COUNT="$(( FIREWALL_MARKER_MANIFEST_COUNT + 1 ))"
  if [[ "$FIREWALL_MARKER_MANIFEST_COUNT" == "1" ]]; then
    [[ ! -e "$FIREWALL_MARKER_MANIFEST" ]] || block FIREWALL_MARKER_MANIFEST_COLLISION
    : >"$FIREWALL_MARKER_MANIFEST"
  fi
  record "canaries.firewall.${receipt_key}.command_exit_code" int "$command_rc"
  record "canaries.firewall.${receipt_key}.command_exit_class" str "$command_exit_class"
  record "canaries.firewall.${receipt_key}.enforcement_input_delta" int "$input_delta"
  record "canaries.firewall.${receipt_key}.enforcement_forward_delta" int "$forward_delta"
  record "canaries.firewall.${receipt_key}.enforcement_output_delta" int "$output_delta"
  for name in same_network external_dns literal_ip metadata gateway host_listener foreign_network; do
    marker_delta="$(( after_ref[$name] - before_ref[$name] ))"
    record "canaries.firewall.${receipt_key}.markers.${name}_delta" int "$marker_delta"
  done
  printf '%02d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$FIREWALL_MARKER_MANIFEST_COUNT" "$receipt_key" "$command_exit_class" "$command_rc" \
    "$input_delta" "$forward_delta" "$output_delta" \
    "$(( after_ref[same_network] - before_ref[same_network] ))" \
    "$(( after_ref[external_dns] - before_ref[external_dns] ))" \
    "$(( after_ref[literal_ip] - before_ref[literal_ip] ))" \
    "$(( after_ref[metadata] - before_ref[metadata] ))" \
    "$(( after_ref[gateway] - before_ref[gateway] ))" \
    "$(( after_ref[host_listener] - before_ref[host_listener] ))" \
    "$(( after_ref[foreign_network] - before_ref[foreign_network] ))" \
    >>"$FIREWALL_MARKER_MANIFEST"
}

firewall_validate_marker_deltas() {
  local receipt_key="$1" expected_marker="$2" before_name="$3" after_name="$4" result_name="$5"
  local name delta expected_delta=0 unexpected_delta=0
  local -n before_ref="$before_name" after_ref="$after_name"
  for name in same_network external_dns literal_ip metadata gateway host_listener foreign_network; do
    delta="$(( after_ref[$name] - before_ref[$name] ))"
    (( delta >= 0 )) || block FIREWALL_MARKER_COUNTER_NONMONOTONIC
    if [[ "$name" == "$expected_marker" ]]; then
      expected_delta="$delta"
    else
      unexpected_delta="$(( unexpected_delta + delta ))"
    fi
  done
  record "canaries.firewall.${receipt_key}.expected_marker_delta" int "$expected_delta"
  record "canaries.firewall.${receipt_key}.unexpected_marker_delta" int "$unexpected_delta"
  (( unexpected_delta == 0 )) || block FIREWALL_MARKER_UNEXPECTED_DELTA
  printf -v "$result_name" '%s' "$expected_delta"
}

expect_firewall_block() {
  local receipt_key="$1" counter="$2" expected_marker="$3" success_code="$4" correlation_code="$5"
  shift 5
  local before_input before_forward before_output after_input after_forward after_output command_rc
  local input_delta forward_delta output_delta command_exit_class marker_delta
  local -A marker_before=() marker_after=()
  before_input="$(firewall_counter_value input_deny)"
  before_forward="$(firewall_counter_value forward_deny)"
  before_output="$(firewall_counter_value output_deny)"
  firewall_marker_snapshot marker_before
  set +e
  "$@" >"$RAW/canary-${receipt_key}.log" 2>&1
  command_rc="$?"
  set -e
  after_input="$(firewall_counter_value input_deny)"
  after_forward="$(firewall_counter_value forward_deny)"
  after_output="$(firewall_counter_value output_deny)"
  firewall_marker_snapshot marker_after
  input_delta="$(( after_input - before_input ))"
  forward_delta="$(( after_forward - before_forward ))"
  output_delta="$(( after_output - before_output ))"
  if [[ "$command_rc" == "0" ]]; then
    command_exit_class=SUCCESS
  elif [[ "$receipt_key" == "gateway" && "$command_rc" == "1" ]]; then
    command_exit_class=NO_REPLY
  elif [[ "$receipt_key" == "gateway" ]]; then
    command_exit_class=RUNTIME_ERROR
  else
    command_exit_class=BLOCKED
  fi
  firewall_record_canary_evidence "$receipt_key" "$command_rc" "$command_exit_class" \
    "$input_delta" "$forward_delta" "$output_delta" marker_before marker_after

  if [[ "$receipt_key" == "gateway" ]]; then
    record canaries.firewall.gateway_command_exit_code int "$command_rc"
    record canaries.firewall.gateway_command_exit_class str "$command_exit_class"
    record canaries.firewall.gateway_input_deny_delta int "$input_delta"
    record canaries.firewall.gateway_forward_deny_delta int "$forward_delta"
    record canaries.firewall.gateway_output_deny_delta int "$output_delta"

    [[ "$command_exit_class" != "SUCCESS" ]] || block PACKET_GATEWAY_REACHABLE
    (( input_delta >= 0 && forward_delta >= 0 && output_delta >= 0 )) || block FIREWALL_COUNTER_NONMONOTONIC
    [[ "$command_exit_class" != "RUNTIME_ERROR" ]] || block GATEWAY_COMMAND_RUNTIME_FAILED
    (( forward_delta == 0 && output_delta == 0 )) || block GATEWAY_UNEXPECTED_COUNTER_DELTA
    (( input_delta > 0 )) || block GATEWAY_INPUT_COUNTER_DELTA_MISSING
  fi

  [[ "$command_rc" != "0" ]] || block "$success_code"
  (( input_delta >= 0 && forward_delta >= 0 && output_delta >= 0 )) || block FIREWALL_COUNTER_NONMONOTONIC
  firewall_validate_marker_deltas "$receipt_key" "$expected_marker" marker_before marker_after marker_delta
  (( marker_delta > 0 )) || block "$correlation_code"
  case "$counter" in
    input_deny)
      (( input_delta == marker_delta && forward_delta == 0 && output_delta == 0 )) || block "$correlation_code"
      ;;
    forward_deny)
      (( forward_delta == marker_delta && input_delta == 0 && output_delta == 0 )) || block "$correlation_code"
      ;;
    output_deny)
      (( output_delta == marker_delta && input_delta == 0 && forward_delta == 0 )) || block "$correlation_code"
      ;;
    *) block FIREWALL_COUNTER_INVALID ;;
  esac
  record "canaries.firewall.${receipt_key}_failed" bool true
  record "canaries.firewall.${receipt_key}_deny_delta" int "$marker_delta"
  FIREWALL_MARKER_EXPECTED_TOTAL["$expected_marker"]="$(( FIREWALL_MARKER_EXPECTED_TOTAL[$expected_marker] + marker_delta ))"
  if [[ "$counter" == "input_deny" ]]; then
    EXPECTED_INPUT_DENIES="$(( EXPECTED_INPUT_DENIES + marker_delta ))"
  elif [[ "$counter" == "forward_deny" ]]; then
    EXPECTED_FORWARD_DENIES="$(( EXPECTED_FORWARD_DENIES + marker_delta ))"
  else
    EXPECTED_OUTPUT_DENIES="$(( EXPECTED_OUTPUT_DENIES + marker_delta ))"
  fi
}

expect_same_network_positive() {
  local receipt_key="$1" expected_marker="$2" failure_code="$3" deny_code="$4"
  shift 4
  local before_input before_forward before_output after_input after_forward after_output command_rc marker_delta name
  local input_delta forward_delta output_delta unexpected_delta=0
  local -A marker_before=() marker_after=()
  before_input="$(firewall_counter_value input_deny)"
  before_forward="$(firewall_counter_value forward_deny)"
  before_output="$(firewall_counter_value output_deny)"
  firewall_marker_snapshot marker_before
  set +e
  "$@" >"$RAW/canary-${receipt_key}.log" 2>&1
  command_rc="$?"
  set -e
  after_input="$(firewall_counter_value input_deny)"
  after_forward="$(firewall_counter_value forward_deny)"
  after_output="$(firewall_counter_value output_deny)"
  firewall_marker_snapshot marker_after
  input_delta="$(( after_input - before_input ))"
  forward_delta="$(( after_forward - before_forward ))"
  output_delta="$(( after_output - before_output ))"
  firewall_record_canary_evidence "$receipt_key" "$command_rc" \
    "$([[ "$command_rc" == "0" ]] && printf SUCCESS || printf RUNTIME_ERROR)" \
    "$input_delta" "$forward_delta" "$output_delta" marker_before marker_after
  (( input_delta >= 0 && forward_delta >= 0 && output_delta >= 0 )) || block FIREWALL_COUNTER_NONMONOTONIC
  [[ "$command_rc" == "0" ]] || block "$failure_code"
  (( input_delta == 0 && forward_delta == 0 && output_delta == 0 )) || block "$deny_code"
  for name in same_network external_dns literal_ip metadata gateway host_listener foreign_network; do
    marker_delta="$(( marker_after[$name] - marker_before[$name] ))"
    (( marker_delta >= 0 )) || block FIREWALL_MARKER_COUNTER_NONMONOTONIC
    if [[ "$expected_marker" == "none" ]]; then
      unexpected_delta="$(( unexpected_delta + marker_delta ))"
    elif [[ "$name" == "$expected_marker" ]]; then
      FIREWALL_MARKER_EXPECTED_TOTAL["$name"]="$(( FIREWALL_MARKER_EXPECTED_TOTAL[$name] + marker_delta ))"
      (( marker_delta > 0 )) || block SAME_NETWORK_MARKER_DELTA_MISSING
    else
      unexpected_delta="$(( unexpected_delta + marker_delta ))"
    fi
  done
  (( unexpected_delta == 0 )) || block FIREWALL_MARKER_UNEXPECTED_DELTA
  record "canaries.firewall.${receipt_key}" bool true
}

firewall_marker_finish() {
  local manifest_count manifest_sha input_final forward_final output_final name
  local -A marker_final=()
  manifest_count="$(wc -l <"$FIREWALL_MARKER_MANIFEST" | tr -d ' ')"
  [[ "$manifest_count" == "8" && "$manifest_count" == "$FIREWALL_MARKER_MANIFEST_COUNT" ]] \
    || block FIREWALL_MARKER_MANIFEST_INVALID
  manifest_sha="$(sha256sum <"$FIREWALL_MARKER_MANIFEST" | awk '{print $1}')"
  [[ "$manifest_sha" =~ ^[0-9a-f]{64}$ ]] || block FIREWALL_MARKER_MANIFEST_INVALID
  record canaries.firewall.marker_manifest_count int "$manifest_count"
  record canaries.firewall.marker_manifest_sha256 str "$manifest_sha"
  firewall_marker_snapshot marker_final
  for name in same_network external_dns literal_ip metadata gateway host_listener foreign_network; do
    record "canaries.firewall.markers.final.${name}" int "${marker_final[$name]}"
    record "canaries.firewall.markers.expected.${name}" int "${FIREWALL_MARKER_EXPECTED_TOTAL[$name]}"
    [[ "${marker_final[$name]}" == "${FIREWALL_MARKER_EXPECTED_TOTAL[$name]}" ]] \
      || block FIREWALL_MARKER_FINAL_MISMATCH
  done
  input_final="$(firewall_counter_value input_deny)"
  forward_final="$(firewall_counter_value forward_deny)"
  output_final="$(firewall_counter_value output_deny)"
  [[ "$input_final" == "$(( FIREWALL_CANARY_BASE_INPUT + EXPECTED_INPUT_DENIES ))" \
    && "$forward_final" == "$(( FIREWALL_CANARY_BASE_FORWARD + EXPECTED_FORWARD_DENIES ))" \
    && "$output_final" == "$(( FIREWALL_CANARY_BASE_OUTPUT + EXPECTED_OUTPUT_DENIES ))" ]] \
    || block FIREWALL_UNEXPECTED_DENY_HIT
  record firewall.final_input_deny_count int "$input_final"
  record firewall.final_forward_deny_count int "$forward_final"
  record firewall.final_output_deny_count int "$output_final"
  record firewall.unexpected_deny_hit_count int 0
}

wait_healthy_container() {
  local container_id="$1" failure_code="$2" status="" running=""
  for _ in $(seq 1 120); do
    status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$container_id" 2>/dev/null || true)"
    running="$(docker inspect --format '{{.State.Running}}' "$container_id" 2>/dev/null || true)"
    [[ "$running" == "true" ]] || block "$failure_code"
    [[ "$status" != "unhealthy" ]] || block "$failure_code"
    [[ "$status" == "healthy" ]] && return 0
    sleep 1
  done
  block "$failure_code"
}

validate_unpublished_container() {
  local container_id="$1" expected_network_mode="$2" expected_tmpfs_size="$3" code_prefix="$4"
  local tmpfs_json
  local publication_key publication_state publication_class publication_rc
  [[ "$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$container_id")" == "$expected_network_mode" ]] \
    || block "${code_prefix}_NETWORK_MISMATCH"
  [[ "$(docker inspect --format '{{.HostConfig.Privileged}}' "$container_id")" == "false" ]] \
    || block "${code_prefix}_PRIVILEGE_REJECTED"
  [[ "$(docker inspect --format '{{.HostConfig.PidMode}}' "$container_id")" =~ ^(|private)$ ]] \
    || block "${code_prefix}_PID_MODE_REJECTED"
  [[ "$(docker inspect --format '{{.HostConfig.IpcMode}}' "$container_id")" =~ ^(|private)$ ]] \
    || block "${code_prefix}_IPC_MODE_REJECTED"
  [[ "$(docker inspect --format '{{len .NetworkSettings.Networks}}' "$container_id")" == "1" ]] \
    || block "${code_prefix}_EXTRA_NETWORK_REJECTED"
  [[ "$(docker inspect --format '{{len .HostConfig.Binds}}' "$container_id")" == "0" ]] \
    || block "${code_prefix}_BIND_REJECTED"
  [[ "$(docker inspect --format '{{len .HostConfig.Mounts}}' "$container_id")" == "0" ]] \
    || block "${code_prefix}_MOUNT_REJECTED"
  [[ "$(docker inspect --format '{{len .HostConfig.VolumesFrom}}' "$container_id")" == "0" ]] \
    || block "${code_prefix}_MOUNT_REJECTED"
  [[ "$(docker inspect --format '{{len .HostConfig.CapAdd}}' "$container_id")" == "0" ]] \
    || block "${code_prefix}_CAPABILITY_REJECTED"
  [[ "$(docker inspect --format '{{len .HostConfig.Devices}}' "$container_id")" == "0" ]] \
    || block "${code_prefix}_DEVICE_REJECTED"
  [[ "$(docker inspect --format '{{len .HostConfig.SecurityOpt}}' "$container_id")" == "0" ]] \
    || block "${code_prefix}_SECURITY_OPTION_REJECTED"
  [[ "$(docker inspect --format '{{len .Mounts}}' "$container_id")" == "0" ]] \
    || block "${code_prefix}_MOUNT_REJECTED"
  tmpfs_json="$(docker inspect --format '{{json .HostConfig.Tmpfs}}' "$container_id")" \
    || block "${code_prefix}_MOUNT_REJECTED"
  printf '%s' "$tmpfs_json" | python3 -B -c '
import json
import sys

sys.path.insert(0, sys.argv[1])
from direct_port_probe import legacy_tmpfs_matches

try:
    payload = json.load(sys.stdin)
except (TypeError, ValueError):
    raise SystemExit(1)
raise SystemExit(0 if legacy_tmpfs_matches(payload, sys.argv[2]) else 1)
' "$ROOT/scripts" "$expected_tmpfs_size" || block "${code_prefix}_MOUNT_REJECTED"
  case "$code_prefix" in
    FIREWALL_CLIENT) publication_key=firewall_client ;;
    FOREIGN_CANARY) publication_key=foreign_canary ;;
    *) block "${code_prefix}_PUBLICATION_SCHEMA_REJECTED" ;;
  esac
  publication_state="$RUNTIME/publication-${publication_key}.tsv"
  set +e
  python3 -B "$ROOT/scripts/direct_port_probe.py" validate-unpublished \
    --container-id "$container_id" \
    --subject "$code_prefix" \
    --receipt-prefix "$publication_key" \
    >"$publication_state" 2>"$RAW/publication-${publication_key}.log"
  publication_rc="$?"
  set -e
  [[ -s "$publication_state" ]] || block "${code_prefix}_PUBLICATION_INSPECT_FAILED"
  cat "$publication_state" >>"$STATE_FILE"
  publication_class="$(awk -F '\t' -v key="diagnostic.publication.${publication_key}.class" \
    '$1==key && $2=="str"{print $3; exit}' "$publication_state")"
  [[ "$publication_class" =~ ^${code_prefix}_PUBLICATION_[A-Z0-9_]+$ ]] \
    || block "${code_prefix}_PUBLICATION_SCHEMA_REJECTED"
  [[ "$publication_rc" == "0" ]] || block "$publication_class"
  [[ "$publication_class" == "${code_prefix}_PUBLICATION_SHAPE_SAFE" ]] \
    || block "$publication_class"
}

run_firewall_publication_rehearsal() {
  local db_password service_id foreign_id client_id client_ip service_ip foreign_ip probe_rc failure_code
  local probe_state="$RUNTIME/firewall-port-probe.tsv" firewall_install_state="$RUNTIME/firewall-install.tsv"
  local input_before forward_before output_before input_after forward_after output_after

  record diagnostic.timing.started_at str "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  freeze_precli_objects_and_listeners
  [[ -f "$FIREWALL_LEDGER" && ! -L "$FIREWALL_LEDGER" ]] || block FIREWALL_LEDGER_INVALID
  python3 -B "$ROOT/scripts/firewall_boundary.py" install \
    --ledger "$FIREWALL_LEDGER" \
    --interface "$FIREWALL_BRIDGE_NAME" \
    --subnet "$SUBNET" >"$firewall_install_state" 2>"$RAW/firewall-install.log" \
    || {
      failure_code="$(awk -F '\t' '$1=="firewall.failure_code"{print $3; exit}' "$firewall_install_state" 2>/dev/null || true)"
      [[ "$failure_code" =~ ^FIREWALL_[A-Z0-9_]+$ ]] || failure_code=FIREWALL_INSTALL_FAILED
      block "$failure_code"
    }
  cat "$firewall_install_state" >>"$STATE_FILE"
  record firewall.active_before_first_container bool true
  firewall_phase_snapshot post_install

  python3 -B -c '
import pathlib, socket, sys
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind((sys.argv[1], int(sys.argv[2])))
listener.listen(8)
listener.settimeout(0.5)
pathlib.Path(sys.argv[3]).write_text("ready\n", encoding="utf-8")
while True:
    try:
        connection, _ = listener.accept()
    except TimeoutError:
        continue
    connection.close()
' "$SUBNET_GATEWAY" "$HOST_TEST_PORT" "$HOST_TEST_READY" \
    >"$RAW/host-test-listener.log" 2>&1 &
  HOST_TEST_LISTENER_PID="$!"
  for _ in $(seq 1 50); do
    [[ -f "$HOST_TEST_READY" ]] && break
    kill -0 "$HOST_TEST_LISTENER_PID" 2>/dev/null || break
    sleep 0.1
  done
  [[ -f "$HOST_TEST_READY" ]] || block HOST_TEST_LISTENER_UNAVAILABLE
  firewall_phase_snapshot host_listener_ready

  db_password="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" \
    || block DIRECT_CREDENTIAL_GENERATION_FAILED
  [[ -n "$db_password" ]] || block DIRECT_CREDENTIAL_GENERATION_FAILED
  printf '::add-mask::%s\n' "$db_password"
  export POSTGRES_PASSWORD="$db_password"

  foreign_id="$(timeout --signal=TERM --kill-after=5s 30s docker run -d \
    --pull=never \
    --platform linux/amd64 \
    --name "$FIREWALL_FOREIGN_NAME" \
    --label "io.fawxzzy.packet=${FIREWALL_PACKET}" \
    --label "io.fawxzzy.role=foreign-network-canary" \
    --label "com.supabase.cli.project=${PROJECT}" \
    --label "com.docker.compose.project=${PROJECT}" \
    --network bridge \
    --tmpfs "/var/lib/postgresql/data:rw,nosuid,nodev,noexec,size=1g" \
    --restart=no \
    --health-cmd='pg_isready -U postgres -h 127.0.0.1' \
    --health-interval=1s \
    --health-timeout=2s \
    --health-start-period=30s \
    --health-retries=30 \
    --env POSTGRES_PASSWORD \
    "$POSTGRES_PULL" 2>"$RAW/foreign-container-create.log")" \
    || block FOREIGN_CANARY_CONTAINER_CREATE_FAILED
  firewall_phase_snapshot foreign_container_started

  service_id="$(timeout --signal=TERM --kill-after=5s 30s docker run -d \
    --pull=never \
    --platform linux/amd64 \
    --name "$FIREWALL_DB_NAME" \
    --label "io.fawxzzy.packet=${FIREWALL_PACKET}" \
    --label "io.fawxzzy.role=firewall-postgres" \
    --label "com.supabase.cli.project=${PROJECT}" \
    --label "com.docker.compose.project=${PROJECT}" \
    --network "$NETWORK_ID" \
    --publish "${DB_PORT}:5432" \
    --tmpfs "/var/lib/postgresql/data:rw,nosuid,nodev,noexec,size=1g" \
    --restart=no \
    --health-cmd='pg_isready -U postgres -h 127.0.0.1' \
    --health-interval=1s \
    --health-timeout=2s \
    --health-start-period=30s \
    --health-retries=30 \
    --env POSTGRES_PASSWORD \
    "$POSTGRES_PULL" 2>"$RAW/firewall-container-create.log")" \
    || block FIREWALL_SERVICE_CONTAINER_CREATE_FAILED
  firewall_phase_snapshot published_service_started
  unset POSTGRES_PASSWORD db_password

  client_id="$(timeout --signal=TERM --kill-after=5s 30s docker run -d \
    --pull=never \
    --platform linux/amd64 \
    --name "$FIREWALL_CLIENT_NAME" \
    --label "io.fawxzzy.packet=${FIREWALL_PACKET}" \
    --label "io.fawxzzy.role=firewall-canary-client" \
    --label "com.supabase.cli.project=${PROJECT}" \
    --label "com.docker.compose.project=${PROJECT}" \
    --network "$NETWORK_ID" \
    --tmpfs "/var/lib/postgresql/data:rw,nosuid,nodev,noexec,size=64m" \
    "$POSTGRES_PULL" sleep 300 2>"$RAW/firewall-client-create.log")" \
    || block FIREWALL_CLIENT_CONTAINER_CREATE_FAILED
  firewall_phase_snapshot packet_client_started

  validate_unpublished_container "$client_id" "$NETWORK_ID" 64m FIREWALL_CLIENT
  validate_unpublished_container "$foreign_id" bridge 1g FOREIGN_CANARY

  wait_healthy_container "$foreign_id" FOREIGN_CANARY_NOT_HEALTHY
  wait_healthy_container "$service_id" FIREWALL_SERVICE_NOT_HEALTHY
  assert_frozen_network rehearsal_active active
  firewall_phase_snapshot shape_network_health_validated

  set +e
  python3 -B "$ROOT/scripts/direct_port_probe.py" \
    --container-id "$service_id" \
    --network-id "$NETWORK_ID" \
    --image-id "$POSTGRES_IMAGE_ID" \
    --image-reference "$POSTGRES_PULL" \
    --packet "$FIREWALL_PACKET" \
    --role firewall-postgres \
    --container-name "$FIREWALL_DB_NAME" \
    --health-timeout-seconds 120 \
    --stable-seconds 10 >"$probe_state" 2>"$RAW/firewall-port-probe.log"
  probe_rc="$?"
  set -e
  [[ -f "$probe_state" ]] || block FIREWALL_PORT_PROBE_RESULT_MISSING
  cat "$probe_state" >>"$STATE_FILE"
  if [[ "$probe_rc" != "0" ]]; then
    failure_code="$(awk -F '\t' '$1=="diagnostic.probe.failure_code"{print $3; exit}' "$probe_state")"
    [[ "$failure_code" =~ ^[A-Z0-9_]+$ ]] || failure_code=FIREWALL_PORT_PROBE_FAILED
    block "$failure_code"
  fi
  firewall_phase_snapshot publication_probes_complete

  docker exec "$client_id" bash -ceu '
    command -v ip >/dev/null
    command -v getent >/dev/null
    command -v ping >/dev/null
    command -v timeout >/dev/null
    command -v pg_isready >/dev/null
    test -n "$(ip -4 route show default)"
  ' >"$RAW/firewall-client-preflight.log" 2>&1 || block FIREWALL_CLIENT_TOOLING_MISMATCH
  record network.default_route_present bool true
  firewall_phase_snapshot client_tool_preflight_complete

  client_ip="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$client_id" 2>/dev/null || true)"
  service_ip="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$service_id" 2>/dev/null || true)"
  foreign_ip="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$foreign_id" 2>/dev/null || true)"
  [[ "$client_ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ \
    && "$service_ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ \
    && "$foreign_ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] \
    || block FIREWALL_MARKER_IDENTITY_UNAVAILABLE
  firewall_phase_snapshot quiescence_first
  sleep 2
  firewall_phase_snapshot quiescence_second
  firewall_phase_finish PRECANARY_SETUP_QUIESCENT
  firewall_install_marker_boundary "$client_ip" "$service_ip" "$foreign_ip"

  expect_same_network_positive same_network_resolution none SAME_NETWORK_SERVICE_DISCOVERY_FAILED \
    SAME_NETWORK_RESOLUTION_HIT_DENY_RULE \
    docker exec "$client_id" getent ahostsv4 "$FIREWALL_DB_NAME"
  expect_same_network_positive same_network_connect same_network SAME_NETWORK_CONTAINER_CONNECT_FAILED \
    SAME_NETWORK_TRAFFIC_HIT_DENY_RULE \
    docker exec "$client_id" pg_isready -h "$FIREWALL_DB_NAME" -p 5432 -t 5

  expect_firewall_block external_dns output_deny external_dns EXTERNAL_DNS_SUCCEEDED EXTERNAL_DNS_NOT_FIREWALL_CORRELATED \
    docker exec "$client_id" timeout 5 getent ahostsv4 example.com.
  expect_firewall_block literal_ip forward_deny literal_ip LITERAL_IP_EGRESS_SUCCEEDED LITERAL_IP_NOT_FIREWALL_CORRELATED \
    docker exec "$client_id" timeout 3 bash -ceu '</dev/tcp/1.1.1.1/443'
  expect_firewall_block metadata forward_deny metadata METADATA_EGRESS_SUCCEEDED METADATA_NOT_FIREWALL_CORRELATED \
    docker exec "$client_id" timeout 3 bash -ceu '</dev/tcp/169.254.169.254/80'
  expect_firewall_block gateway input_deny gateway PACKET_GATEWAY_REACHABLE GATEWAY_NOT_FIREWALL_CORRELATED \
    docker exec "$client_id" ping -c 1 -W 1 "$SUBNET_GATEWAY"
  expect_firewall_block host_listener input_deny host_listener HOST_TEST_LISTENER_REACHABLE HOST_TEST_LISTENER_NOT_FIREWALL_CORRELATED \
    docker exec "$client_id" timeout 3 bash -ceu "</dev/tcp/${SUBNET_GATEWAY}/${HOST_TEST_PORT}"

  expect_firewall_block foreign_network forward_deny foreign_network FOREIGN_NETWORK_REACHABLE FOREIGN_NETWORK_NOT_FIREWALL_CORRELATED \
    docker exec "$client_id" timeout 3 bash -ceu "</dev/tcp/${foreign_ip}/5432"
  unset client_ip service_ip foreign_ip

  docker version --format '{{.Server.Version}}' >"$RAW/docker-control-after-firewall.log" 2>&1 \
    || block DOCKER_CONTROL_UNAVAILABLE_UNDER_FIREWALL
  record canaries.firewall.docker_control_available bool true
  firewall_marker_finish
  native_listener_contract post_cli \
    || block "${LISTENER_FAILURE_CODE:-NATIVE_LISTENER_DRIFT}" "${LISTENER_LAST_PHASE:-POST_CLI_LISTENER_UNKNOWN}"
  record source_contract.supabase_cli_invoked bool false
  record source_contract.gotrue_invoked bool false
  record source_contract.application_replay_invoked bool false
  record diagnostic.timing.completed_at str "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  SMOKE_PASSED=1
}

packet_object_counts() {
  local stage container_count volume_count network_count
  stage="$1"
  container_count="$({
    docker ps -aq --no-trunc --filter "label=io.fawxzzy.packet=${CONTAINMENT_PACKET}" 2>/dev/null
    docker ps -aq --no-trunc --filter "label=com.supabase.cli.project=${PROJECT}" 2>/dev/null
  } | awk 'NF' | sort -u | wc -l)"
  volume_count="$({
    docker volume ls -q --filter "label=io.fawxzzy.packet=${CONTAINMENT_PACKET}" 2>/dev/null
    docker volume ls -q --filter "label=com.supabase.cli.project=${PROJECT}" 2>/dev/null
  } | awk 'NF' | sort -u | wc -l)"
  network_count="$({
    docker network ls -q --filter "label=io.fawxzzy.packet=${CONTAINMENT_PACKET}" 2>/dev/null
    docker network ls -q --filter "label=com.supabase.cli.project=${PROJECT}" 2>/dev/null
  } | awk 'NF' | sort -u | wc -l)"
  record "root_init.objects.${stage}.containers" int "$container_count"
  record "root_init.objects.${stage}.volumes" int "$volume_count"
  record "root_init.objects.${stage}.networks" int "$network_count"
  [[ "$container_count" == "0" && "$volume_count" == "0" && "$network_count" == "0" ]]
}

prepare_root_init_scratch() {
  [[ ! -e "$ROOT_INIT_DIR" ]] || block ROOT_INIT_SCRATCH_PREEXISTING
  install -d -m 0700 \
    "$ROOT_INIT_WORKDIR/supabase/.temp" \
    "$ROOT_INIT_HOME" \
    "$ROOT_INIT_XDG_CONFIG" \
    "$ROOT_INIT_XDG_CACHE" \
    "$ROOT_INIT_XDG_DATA" \
    "$ROOT_INIT_XDG_STATE" \
    "$ROOT_INIT_TMP"
  cp -- "$ROOT/supabase/config.toml" "$ROOT_INIT_WORKDIR/supabase/config.toml" \
    || block CONFIG_FILE_READ_FAILED
  printf 'v%s' "$CLI_VERSION" >"$ROOT_INIT_WORKDIR/supabase/.temp/cli-latest"
  chmod 0600 "$ROOT_INIT_WORKDIR/supabase/config.toml"
  chmod 0600 "$ROOT_INIT_WORKDIR/supabase/.temp/cli-latest"
  record loader.scratch.redirected_location_count int 6
  record root_init.scratch.upgrade_cache_preseeded bool true

  local config_sha config_bytes env_file_count
  config_sha="$(sha256sum "$ROOT_INIT_WORKDIR/supabase/config.toml" | awk '{print $1}')"
  config_bytes="$(wc -c <"$ROOT_INIT_WORKDIR/supabase/config.toml" | tr -d ' ')"
  [[ "$config_sha" == "$CONFIG_SHA" ]] || block CONFIG_FILE_MERGE_FAILED config-digest-mismatch
  [[ -r "$ROOT_INIT_WORKDIR/supabase/config.toml" ]] || block CONFIG_FILE_READ_FAILED
  if LC_ALL=C grep -q $'\r' "$ROOT_INIT_WORKDIR/supabase/config.toml"; then
    block CONFIG_FILE_MERGE_FAILED config-not-lf
  fi
  env_file_count="$(find "$ROOT_INIT_WORKDIR" -xdev -type f -name '.env*' -print | wc -l)"
  [[ "$env_file_count" == "0" ]] || block CONFIG_ENV_TRAVERSAL_FAILED unexpected-env-file
  [[ ! -e "$ROOT_INIT_WORKDIR/supabase/.temp/project-ref" ]] \
    || block UNEXPECTED_DOCKER_OR_PROVIDER_BOUNDARY linked-state-present
  [[ ! -e "$ROOT_INIT_HOME/.supabase/access-token" ]] \
    || block UNEXPECTED_DOCKER_OR_PROVIDER_BOUNDARY access-token-present
  [[ ! -e "$ROOT_INIT_WORKDIR/supabase/migrations" ]] \
    || block UNEXPECTED_DOCKER_OR_PROVIDER_BOUNDARY migrations-present
  [[ ! -e "$ROOT_INIT_WORKDIR/supabase/seed.sql" ]] \
    || block UNEXPECTED_DOCKER_OR_PROVIDER_BOUNDARY seed-present
  record loader.config.public_sha256 str "$config_sha"
  record loader.config.byte_count int "$config_bytes"
  record loader.config.readable bool true
  record loader.config.lf_only bool true
  record loader.config.env_file_count int 0
  record loader.provider.linked_state_absent bool true
  record loader.provider.access_token_absent bool true
  record loader.provider.inherited_supabase_environment bool false
  record loader.application.migrations_absent bool true
  record loader.application.seed_absent bool true
}

audit_root_init_scratch() {
  local manifest="$RAW/root-init-scratch-manifest.tsv"
  local file relative class digest update_count=0 telemetry_count=0 config_count=0 file_count=0
  : >"$manifest"
  while IFS= read -r -d '' file; do
    relative="${file#"$ROOT_INIT_DIR"/}"
    case "$relative" in
      workdir/supabase/.temp/cli-latest)
        class=CLI_UPDATE_CACHE
        update_count="$((update_count + 1))"
        ;;
      home/.supabase/telemetry.json)
        class=TELEMETRY_STATE
        telemetry_count="$((telemetry_count + 1))"
        ;;
      workdir/supabase/config.toml)
        class=PROJECT_CONFIG
        config_count="$((config_count + 1))"
        ;;
      *) block ROOT_INIT_STATE_ESCAPE "unexpected-scratch-class" ;;
    esac
    digest="$(sha256sum "$file" | awk '{print $1}')"
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || block ROOT_INIT_SCRATCH_AUDIT_FAILED
    printf '%s\t%s\n' "$class" "$digest" >>"$manifest"
    file_count="$((file_count + 1))"
  done < <(find "$ROOT_INIT_DIR" -xdev -type f -print0)
  LC_ALL=C sort -o "$manifest" "$manifest"
  record loader.scratch.file_count int "$file_count"
  record loader.scratch.class_counts.cli_update_cache int "$update_count"
  record loader.scratch.class_counts.telemetry_state int "$telemetry_count"
  record loader.scratch.class_counts.project_config int "$config_count"
  record loader.scratch.class_digest_sha256 str "$(sha256sum "$manifest" | awk '{print $1}')"
  [[ "$update_count" == "1" ]] || block ROOT_INIT_SCRATCH_AUDIT_FAILED
  [[ "$config_count" == "1" ]] || block ROOT_INIT_SCRATCH_AUDIT_FAILED
  (( telemetry_count <= 1 )) || block ROOT_INIT_SCRATCH_AUDIT_FAILED
}

# BEGIN LOADCONFIG_CLASSIFIER_FUNCTION
classify_loadconfig_result() {
  local cli_rc="$1" stderr_file="$2" stdout_schema_valid="$3" secret_shape="$4"
  if [[ "$secret_shape" == "true" ]]; then
    printf 'CONFIG_UNKNOWN_SANITIZED\n'
  elif grep -Eqi 'failed to (get repo directory|change directory|restore directory|parse environment file|load \.env)' "$stderr_file"; then
    printf 'CONFIG_ENV_TRAVERSAL_FAILED\n'
  elif grep -Eqi 'failed to read file config' "$stderr_file"; then
    printf 'CONFIG_FILE_READ_FAILED\n'
  elif grep -Eqi 'failed to (merge default values|merge file config|merge remote config)|duplicate project_id' "$stderr_file"; then
    printf 'CONFIG_FILE_MERGE_FAILED\n'
  elif grep -Eqi 'failed to parse config' "$stderr_file"; then
    printf 'CONFIG_DECODE_FAILED\n'
  elif grep -Eqi 'failed to (generate JWT|convert JWK|sign JWT)|Invalid config for auth\.jwt_secret' "$stderr_file"; then
    printf 'CONFIG_KEY_GENERATION_FAILED\n'
  elif grep -Eqi 'Missing required field in config: project_id|Invalid config for remotes\.' "$stderr_file"; then
    printf 'CONFIG_VALIDATION_PROJECT_FAILED\n'
  elif grep -Eqi 'Missing required field in config: db\.|Failed reading config: Invalid db\.|Postgres version 12\.x is unsupported' "$stderr_file"; then
    printf 'CONFIG_VALIDATION_DB_FAILED\n'
  elif grep -Eqi 'Missing required (field in config|config section): auth\.|Invalid config for auth\.|failed to (read|decode) signing keys' "$stderr_file"; then
    printf 'CONFIG_VALIDATION_AUTH_FAILED\n'
  elif [[ "$cli_rc" == "0" && ! -s "$stderr_file" && "$stdout_schema_valid" == "true" ]]; then
    printf 'CONFIG_LOAD_PASS_UNDER_CLEAN_ENV\n'
  else
    printf 'CONFIG_UNKNOWN_SANITIZED\n'
  fi
}
# END LOADCONFIG_CLASSIFIER_FUNCTION

run_loadconfig_services_split() {
  local cli_rc observer_rc=0 observer_state_present=true observer_classification
  local stdout_bytes stdout_lines stdout_sha stderr_bytes stderr_lines stderr_sha
  local request_count response_count write_count forwarding_errors parser_errors
  local stdout_schema_valid=false stdout_schema_rc=0 secret_shape=false loader_classification

  prepare_root_init_scratch
  packet_object_counts pre_cli || block ROOT_INIT_PREEXISTING_OBJECT
  freeze_precli_objects_and_listeners
  EVENT_SINCE="$(date -u +%s)"
  record docker_event_history.boundary_frozen bool true

  [[ ! -e "$DOCKER_API_SOCKET" && ! -e "$DOCKER_API_READY" && ! -e "$DOCKER_API_BOUNDARY_STATE_FILE" ]] \
    || block DOCKER_API_OBSERVER_PREEXISTING_STATE
  python3 -B "$ROOT/scripts/docker_api_boundary.py" \
    --listen "$DOCKER_API_SOCKET" \
    --upstream /var/run/docker.sock \
    --state "$DOCKER_API_BOUNDARY_STATE_FILE" \
    --ready "$DOCKER_API_READY" \
    >"$RAW/docker-api-observer.log" 2>&1 &
  DOCKER_API_OBSERVER_PID="$!"
  for _ in $(seq 1 50); do
    [[ -S "$DOCKER_API_SOCKET" && -f "$DOCKER_API_READY" ]] && break
    kill -0 "$DOCKER_API_OBSERVER_PID" 2>/dev/null || break
    sleep 0.1
  done
  [[ -S "$DOCKER_API_SOCKET" && -f "$DOCKER_API_READY" ]] || block DOCKER_API_OBSERVER_NOT_READY
  [[ "$(stat -c '%a' "$DOCKER_API_SOCKET")" == "600" ]] || block DOCKER_API_OBSERVER_SOCKET_PERMISSIONS
  [[ "$(stat -c '%a' "$DOCKER_API_READY")" == "600" ]] || block DOCKER_API_OBSERVER_READY_PERMISSIONS

  set +e
  (
    cd -- "$ROOT_INIT_WORKDIR"
    env -i \
      PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
      HOME="$ROOT_INIT_HOME" \
      XDG_CONFIG_HOME="$ROOT_INIT_XDG_CONFIG" \
      XDG_CACHE_HOME="$ROOT_INIT_XDG_CACHE" \
      XDG_DATA_HOME="$ROOT_INIT_XDG_DATA" \
      XDG_STATE_HOME="$ROOT_INIT_XDG_STATE" \
      TMPDIR="$ROOT_INIT_TMP" \
      DO_NOT_TRACK=1 \
      DOCKER_HOST="unix://$DOCKER_API_SOCKET" \
      timeout --signal=TERM --kill-after=10s 120s "$RUNTIME/bin/supabase" \
      --workdir "$ROOT_INIT_WORKDIR" \
      --network-id "$NETWORK_NAME" \
      --output json \
      services
  ) >"$RAW/supabase-services.stdout" 2>"$RAW/supabase-services.stderr"
  cli_rc="$?"
  set -e

  observer_rc=0
  stop_docker_api_observer || observer_rc="$?"
  if [[ ! -f "$DOCKER_API_BOUNDARY_STATE_FILE" ]]; then
    observer_state_present=false
    observer_classification=OBSERVER_STATE_MISSING
  else
    cat "$DOCKER_API_BOUNDARY_STATE_FILE" >>"$STATE_FILE"
    observer_classification="$(awk -F '\t' '$1=="docker_api_boundary.classification"{print $3; exit}' "$DOCKER_API_BOUNDARY_STATE_FILE")"
  fi
  record docker_api_boundary.observer_exit_code int "$observer_rc"
  record docker_api_boundary.state_present bool "$observer_state_present"

  stdout_bytes="$(wc -c <"$RAW/supabase-services.stdout" | tr -d ' ')"
  stdout_lines="$(wc -l <"$RAW/supabase-services.stdout" | tr -d ' ')"
  stdout_sha="$(sha256sum "$RAW/supabase-services.stdout" | awk '{print $1}')"
  stderr_bytes="$(wc -c <"$RAW/supabase-services.stderr" | tr -d ' ')"
  stderr_lines="$(wc -l <"$RAW/supabase-services.stderr" | tr -d ' ')"
  stderr_sha="$(sha256sum "$RAW/supabase-services.stderr" | awk '{print $1}')"
  for value in "$stdout_bytes" "$stdout_lines" "$stderr_bytes" "$stderr_lines"; do
    [[ "$value" =~ ^[0-9]+$ ]] || block CONFIG_UNKNOWN_SANITIZED output-count-invalid
  done
  [[ "$stdout_sha" =~ ^[0-9a-f]{64}$ && "$stderr_sha" =~ ^[0-9a-f]{64}$ ]] \
    || block CONFIG_UNKNOWN_SANITIZED output-digest-invalid

  set +e
  python3 -B - "$RAW/supabase-services.stdout" <<'PY'
import json
import sys

try:
    value = json.load(open(sys.argv[1], encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError):
    raise SystemExit(10)
if not isinstance(value, list) or len(value) != 10:
    raise SystemExit(10)
for item in value:
    if not isinstance(item, dict) or set(item) != {"name", "local", "remote"}:
        raise SystemExit(10)
    if not all(isinstance(item[key], str) for key in ("name", "local", "remote")):
        raise SystemExit(10)
    if not item["name"] or not item["local"]:
        raise SystemExit(10)
    if item["remote"]:
        raise SystemExit(11)
PY
  stdout_schema_rc="$?"
  set -e
  case "$stdout_schema_rc" in
    0) stdout_schema_valid=true ;;
    11) block UNEXPECTED_DOCKER_OR_PROVIDER_BOUNDARY remote-service-version-observed ;;
    *) stdout_schema_valid=false ;;
  esac

  if grep -Eqi 'authorization:[[:space:]]*bearer|postgres(ql)?://|-----BEGIN [A-Z ]*PRIVATE KEY-----|sbp_(oauth_)?[0-9a-f]{40}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|("?(password|secret|token|api[_-]?key)"?[[:space:]]*[:=][[:space:]]*"[^"[:space:]]+)' \
    "$RAW/supabase-services.stdout" "$RAW/supabase-services.stderr"; then
    secret_shape=true
  fi
  loader_classification="$(classify_loadconfig_result "$cli_rc" "$RAW/supabase-services.stderr" "$stdout_schema_valid" "$secret_shape")"
  record supabase_cli.loadconfig.exit_code int "$cli_rc"
  record supabase_cli.loadconfig.stdout_raw_byte_count int "$stdout_bytes"
  record supabase_cli.loadconfig.stdout_raw_line_count int "$stdout_lines"
  record supabase_cli.loadconfig.stdout_raw_sha256 str "$stdout_sha"
  record supabase_cli.loadconfig.stderr_raw_byte_count int "$stderr_bytes"
  record supabase_cli.loadconfig.stderr_raw_line_count int "$stderr_lines"
  record supabase_cli.loadconfig.stderr_raw_sha256 str "$stderr_sha"
  record diagnostic.classification str "$loader_classification"
  rm -f -- "$RAW/supabase-services.stdout" "$RAW/supabase-services.stderr" \
    || block CONFIG_UNKNOWN_SANITIZED raw-output-delete-failed
  [[ ! -e "$RAW/supabase-services.stdout" && ! -e "$RAW/supabase-services.stderr" ]] \
    || block CONFIG_UNKNOWN_SANITIZED raw-output-delete-failed
  record supabase_cli.loadconfig.raw_deleted bool true

  audit_root_init_scratch
  case "$ROOT_INIT_DIR" in
    "$RUNTIME"/root-init) rm -rf -- "$ROOT_INIT_DIR" || block ROOT_INIT_SCRATCH_DELETE_FAILED ;;
    *) block ROOT_INIT_SCRATCH_DELETE_FAILED invalid-root-init-path ;;
  esac
  [[ ! -e "$ROOT_INIT_DIR" ]] || block ROOT_INIT_SCRATCH_DELETE_FAILED
  record loader.scratch.deleted bool true

  [[ "$observer_state_present" == "true" ]] || block DOCKER_API_OBSERVER_STATE_MISSING
  [[ "$observer_classification" =~ ^[A-Z0-9_]+$ ]] || block DOCKER_API_OBSERVER_STATE_INVALID
  [[ "$observer_rc" == "0" || "$observer_rc" == "2" ]] \
    || block DOCKER_API_OBSERVER_FAILED "observer-exit-${observer_rc}"
  [[ "$cli_rc" != "124" ]] || block CONFIG_UNKNOWN_SANITIZED command-timeout

  request_count="$(awk -F '\t' '$1=="docker_api_boundary.request_count"{print $3; exit}' "$DOCKER_API_BOUNDARY_STATE_FILE")"
  response_count="$(awk -F '\t' '$1=="docker_api_boundary.response_count"{print $3; exit}' "$DOCKER_API_BOUNDARY_STATE_FILE")"
  write_count="$(awk -F '\t' '$1=="docker_api_boundary.write_attempt_count"{print $3; exit}' "$DOCKER_API_BOUNDARY_STATE_FILE")"
  forwarding_errors="$(awk -F '\t' '$1=="docker_api_boundary.forwarding_error_count"{print $3; exit}' "$DOCKER_API_BOUNDARY_STATE_FILE")"
  parser_errors="$(awk -F '\t' '$1=="docker_api_boundary.parser_error_count"{print $3; exit}' "$DOCKER_API_BOUNDARY_STATE_FILE")"
  for count in "$request_count" "$response_count" "$write_count" "$forwarding_errors" "$parser_errors"; do
    [[ "$count" =~ ^[0-9]+$ ]] || block DOCKER_API_OBSERVER_STATE_INVALID
  done
  [[ "$observer_classification" == "NO_DOCKER_API_REQUEST_OBSERVED" \
    && "$request_count" == "0" \
    && "$response_count" == "0" \
    && "$write_count" == "0" \
    && "$forwarding_errors" == "0" \
    && "$parser_errors" == "0" ]] || block UNEXPECTED_DOCKER_OR_PROVIDER_BOUNDARY docker-api-observed

  packet_object_counts post_cli || block ROOT_INIT_DOCKER_OBJECT_DRIFT
  capture_listener_snapshot post_cli "$DB_PORT" \
    || block "${LISTENER_FAILURE_CODE:-LISTENER_UNEXPECTED_INTERRUPTION}" "${LISTENER_LAST_PHASE:-POST_CLI_PORT_56422_UNKNOWN}"
  [[ "$LISTENER_SNAPSHOT_COUNT" == "0" ]] || block ROOT_INIT_LISTENER_DRIFT
  native_listener_contract post_cli \
    || block "${LISTENER_FAILURE_CODE:-NATIVE_LISTENER_DRIFT}" "${LISTENER_LAST_PHASE:-POST_CLI_LISTENER_UNKNOWN}"

  case "$loader_classification" in
    CONFIG_LOAD_PASS_UNDER_CLEAN_ENV|CONFIG_ENV_TRAVERSAL_FAILED|CONFIG_FILE_READ_FAILED|CONFIG_FILE_MERGE_FAILED|CONFIG_DECODE_FAILED|CONFIG_VALIDATION_PROJECT_FAILED|CONFIG_VALIDATION_DB_FAILED|CONFIG_VALIDATION_AUTH_FAILED|CONFIG_KEY_GENERATION_FAILED|CONFIG_UNKNOWN_SANITIZED)
      block "$loader_classification" loader-only-diagnostic-terminal
      ;;
    *) block CONFIG_UNKNOWN_SANITIZED classifier-schema-rejected ;;
  esac
}

if [[ "$MODE" == "cleanup-only" ]]; then
  cleanup_only
fi

mkdir -p -- "$RAW" "$RUNTIME_HOME" "$PROJECT_DIR/supabase" "$ROOT/artifacts"
: >"$STATE_FILE"
: >"$AUDIT_FILE"
: >"$VIOLATION_FILE"
trap finalize EXIT
write_cleanup_mode_contract "$MODE" || block CLEANUP_MODE_CONTRACT_PUBLICATION_FAILED

record started_at str "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
record status str BLOCKED
record failure.code str HARNESS_INTERRUPTED
record failure.detail str preterminal-state
if [[ "$MODE" == "direct-port" ]]; then
  record result.profile str direct-docker-port-v1
elif [[ "$MODE" == "firewall-rehearsal" ]]; then
  record result.profile str containment-smoke-v1
  record packet str "$FIREWALL_PACKET"
  record diagnostic.profile str firewall-publication-rehearsal-v1
  record source_contract.command str firewall-publication-rehearsal
  record source_contract.root_persistent_prerun bool false
  record source_contract.load_config bool false
  record source_contract.docker_access_expected bool true
  record source_contract.provider_access_enabled bool false
  record source_contract.telemetry_endpoint_enabled bool false
  record source_contract.database_only bool false
  record source_contract.application_migrations_enabled bool false
  record source_contract.seed_enabled bool false
  record source_contract.gotrue_enabled bool false
else
  record result.profile str containment-smoke-v1
  record diagnostic.profile str db-start-policy-v1
  record source_contract.command str supabase-db-start
  record source_contract.root_persistent_prerun bool true
  record source_contract.load_config bool true
  record source_contract.docker_access_expected bool true
  record source_contract.provider_access_enabled bool false
  record source_contract.telemetry_endpoint_enabled bool false
  record source_contract.database_only bool true
  record source_contract.application_migrations_enabled bool false
  record source_contract.seed_enabled bool false
  record source_contract.gotrue_enabled bool true
fi

python3 -B -m unittest discover -s "$ROOT/tests" -v >"$RAW/unit-tests.log" 2>&1 || block CONTRACT_TEST_FAILED

os_id="$(awk -F= '$1=="ID"{gsub(/"/,"",$2); print $2}' /etc/os-release)"
os_version="$(awk -F= '$1=="VERSION_ID"{gsub(/"/,"",$2); print $2}' /etc/os-release)"
arch="$(uname -m)"
kernel="$(uname -r)"
record runner.image_capture str github-actions-set-up-job-log
record runner.os_id str "$os_id"
record runner.os_version str "$os_version"
record runner.architecture str "$arch"
record runner.kernel str "$kernel"
record runner.os_release_sha256 str "$(sha256sum /etc/os-release | awk '{print $1}')"
[[ "$os_id" == "ubuntu" && "$os_version" == "24.04" ]] || block RUNNER_IMAGE_MISMATCH
[[ "$arch" == "x86_64" ]] || block RUNNER_ARCHITECTURE_MISMATCH

docker_client="$(docker version --format '{{.Client.Version}}' 2>"$RAW/docker-version-client.log")" || block DOCKER_CLIENT_UNAVAILABLE
docker_server="$(docker version --format '{{.Server.Version}}' 2>"$RAW/docker-version-server.log")" || block DOCKER_SERVER_UNAVAILABLE
docker_api_version="$(docker version --format '{{.Server.APIVersion}}' 2>"$RAW/docker-api-version.log")" || block DOCKER_SERVER_UNAVAILABLE
docker_arch="$(docker info --format '{{.Architecture}}' 2>"$RAW/docker-info.log")" || block DOCKER_SERVER_UNAVAILABLE
record docker.client_version str "$docker_client"
record docker.server_version str "$docker_server"
record docker.server_api_version str "$docker_api_version"
record docker.architecture str "$docker_arch"
version_at_least "$docker_client" 28.0.0 || block DOCKER_CLIENT_VERSION_TOO_OLD
version_at_least "$docker_server" 28.0.0 || block DOCKER_SERVER_VERSION_TOO_OLD
[[ "$docker_arch" == "x86_64" || "$docker_arch" == "amd64" ]] || block DOCKER_SERVER_ARCHITECTURE_MISMATCH

ram_bytes="$(( $(awk '/^MemTotal:/{print $2}' /proc/meminfo) * 1024 ))"
disk_bytes="$(( $(df -Pk "$ROOT" | awk 'NR==2{print $4}') * 1024 ))"
record runner.ram_bytes int "$ram_bytes"
record runner.free_disk_bytes int "$disk_bytes"
(( ram_bytes >= 8589934592 )) || block RUNNER_RAM_BELOW_8_GIB
(( disk_bytes >= 10737418240 )) || block RUNNER_DISK_BELOW_10_GIB

if [[ "$MODE" == "run" ]]; then
  [[ ! -v SUPABASE_GO_BINARY ]] || block CLI_SIDECAR_OVERRIDE_FORBIDDEN
  curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
    --output "$RUNTIME/$CLI_ASSET" "$CLI_URL" >"$RAW/cli-download.log" 2>&1 || block CLI_DOWNLOAD_FAILED
  actual_cli_sha="$(sha256sum "$RUNTIME/$CLI_ASSET" | awk '{print $1}')"
  record supabase_cli.version str "$CLI_VERSION"
  record supabase_cli.source_commit str "$CLI_COMMIT"
  record supabase_cli.asset_sha256 str "$actual_cli_sha"
  [[ "$actual_cli_sha" == "$CLI_SHA" ]] || block CLI_ASSET_DIGEST_MISMATCH
  mkdir -p "$RUNTIME/bin"
  CLI_ARCHIVE_STATE_FILE="$RUNTIME/cli-archive-contract.tsv"
  validate_extract_cli_archive "$RUNTIME/$CLI_ASSET" "$RUNTIME/bin" \
    >"$CLI_ARCHIVE_STATE_FILE" 2>"$RAW/cli-extract.log" || block CLI_ARCHIVE_CONTRACT_MISMATCH
  [[ "$(wc -l <"$CLI_ARCHIVE_STATE_FILE" | tr -d ' ')" == "7" ]] || block CLI_ARCHIVE_RECEIPT_INVALID
  archive_member_count="$(awk -F '\t' '$1=="archive_member_count" && $2=="int" {print $3; exit}' "$CLI_ARCHIVE_STATE_FILE")"
  member_manifest_sha="$(awk -F '\t' '$1=="member_manifest_sha256" && $2=="str" {print $3; exit}' "$CLI_ARCHIVE_STATE_FILE")"
  adjacency_sha="$(awk -F '\t' '$1=="adjacency_sha256" && $2=="str" {print $3; exit}' "$CLI_ARCHIVE_STATE_FILE")"
  receipt_binary_size="$(awk -F '\t' '$1=="binary_size" && $2=="int" {print $3; exit}' "$CLI_ARCHIVE_STATE_FILE")"
  receipt_binary_sha="$(awk -F '\t' '$1=="binary_sha256" && $2=="str" {print $3; exit}' "$CLI_ARCHIVE_STATE_FILE")"
  receipt_sidecar_size="$(awk -F '\t' '$1=="sidecar_size" && $2=="int" {print $3; exit}' "$CLI_ARCHIVE_STATE_FILE")"
  receipt_sidecar_sha="$(awk -F '\t' '$1=="sidecar_sha256" && $2=="str" {print $3; exit}' "$CLI_ARCHIVE_STATE_FILE")"
  [[ "$archive_member_count" == "2" ]] || block CLI_ARCHIVE_RECEIPT_INVALID
  [[ "$member_manifest_sha" == "$CLI_MEMBER_MANIFEST_SHA" ]] || block CLI_ARCHIVE_RECEIPT_INVALID
  [[ "$adjacency_sha" == "$CLI_ADJACENCY_SHA" ]] || block CLI_ARCHIVE_RECEIPT_INVALID
  [[ "$receipt_binary_size" == "$CLI_BINARY_SIZE" && "$receipt_binary_sha" == "$CLI_BINARY_SHA" ]] || block CLI_ARCHIVE_RECEIPT_INVALID
  [[ "$receipt_sidecar_size" == "$CLI_SIDECAR_SIZE" && "$receipt_sidecar_sha" == "$CLI_SIDECAR_SHA" ]] || block CLI_ARCHIVE_RECEIPT_INVALID
  [[ -f "$RUNTIME/bin/supabase" && ! -L "$RUNTIME/bin/supabase" ]] || block CLI_BINARY_IDENTITY_MISMATCH
  [[ -f "$RUNTIME/bin/supabase-go" && ! -L "$RUNTIME/bin/supabase-go" ]] || block CLI_SIDECAR_IDENTITY_MISMATCH
  [[ "$(stat -c '%a' "$RUNTIME/bin/supabase")" == "555" ]] || block CLI_BINARY_MODE_MISMATCH
  [[ "$(stat -c '%a' "$RUNTIME/bin/supabase-go")" == "555" ]] || block CLI_SIDECAR_MODE_MISMATCH
  [[ "$(find "$RUNTIME/bin" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')" == "2" ]] || block CLI_ARCHIVE_DENOMINATOR_MISMATCH
  actual_cli_binary_sha="$(sha256sum "$RUNTIME/bin/supabase" | awk '{print $1}')"
  actual_cli_binary_size="$(wc -c <"$RUNTIME/bin/supabase" | tr -d ' ')"
  actual_cli_sidecar_sha="$(sha256sum "$RUNTIME/bin/supabase-go" | awk '{print $1}')"
  actual_cli_sidecar_size="$(wc -c <"$RUNTIME/bin/supabase-go" | tr -d ' ')"
  record supabase_cli.binary_sha256 str "$actual_cli_binary_sha"
  record supabase_cli.binary_size int "$actual_cli_binary_size"
  record supabase_cli.sidecar_sha256 str "$actual_cli_sidecar_sha"
  record supabase_cli.sidecar_size int "$actual_cli_sidecar_size"
  record supabase_cli.archive_member_count int "$archive_member_count"
  record supabase_cli.member_manifest_sha256 str "$member_manifest_sha"
  record supabase_cli.adjacency_sha256 str "$adjacency_sha"
  record supabase_cli.sidecar_adjacent bool true
  record supabase_cli.sidecar_override_env_present bool false
  [[ "$actual_cli_binary_sha" == "$CLI_BINARY_SHA" && "$actual_cli_binary_size" == "$CLI_BINARY_SIZE" ]] || block CLI_BINARY_DIGEST_MISMATCH
  [[ "$actual_cli_sidecar_sha" == "$CLI_SIDECAR_SHA" && "$actual_cli_sidecar_size" == "$CLI_SIDECAR_SIZE" ]] || block CLI_SIDECAR_DIGEST_MISMATCH
fi

docker pull --platform linux/amd64 "$POSTGRES_PULL" >"$RAW/postgres-pull.log" 2>&1 || block POSTGRES_PULL_FAILED
postgres_platform="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$POSTGRES_PULL")" || block POSTGRES_INSPECT_FAILED
[[ "$postgres_platform" == "linux/amd64" ]] || block IMAGE_PLATFORM_MISMATCH
docker image inspect --format '{{json .RepoDigests}}' "$POSTGRES_PULL" | grep -Fq "${POSTGRES_TAG%:*}@${POSTGRES_DIGEST}" || block POSTGRES_REPODIGEST_MISMATCH
POSTGRES_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$POSTGRES_PULL")"
record images.postgres.digest str "$POSTGRES_DIGEST"
if [[ "$MODE" == "firewall-rehearsal" ]]; then
  record images.postgres.image_id_sha256 str "$(hash_identifier "$POSTGRES_IMAGE_ID")"
else
  record images.postgres.image_id str "$POSTGRES_IMAGE_ID"
fi
record images.postgres.platform str "$postgres_platform"
if [[ "$MODE" == "run" ]]; then
  docker pull --platform linux/amd64 "$GOTRUE_PULL" >"$RAW/gotrue-pull.log" 2>&1 || block GOTRUE_PULL_FAILED
  gotrue_platform="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$GOTRUE_PULL")" || block GOTRUE_INSPECT_FAILED
  [[ "$gotrue_platform" == "linux/amd64" ]] || block IMAGE_PLATFORM_MISMATCH
  docker image inspect --format '{{json .RepoDigests}}' "$GOTRUE_PULL" | grep -Fq "${GOTRUE_TAG%:*}@${GOTRUE_DIGEST}" || block GOTRUE_REPODIGEST_MISMATCH
  GOTRUE_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$GOTRUE_PULL")"
  docker tag "$POSTGRES_PULL" "$POSTGRES_EXPECTED" || block POSTGRES_RETAG_FAILED
  docker tag "$GOTRUE_PULL" "$GOTRUE_EXPECTED" || block GOTRUE_RETAG_FAILED
  [[ "$(docker image inspect --format '{{.Id}}' "$POSTGRES_EXPECTED")" == "$POSTGRES_IMAGE_ID" ]] || block POSTGRES_RETAG_ID_MISMATCH
  [[ "$(docker image inspect --format '{{.Id}}' "$GOTRUE_EXPECTED")" == "$GOTRUE_IMAGE_ID" ]] || block GOTRUE_RETAG_ID_MISMATCH
  record images.gotrue.digest str "$GOTRUE_DIGEST"
  record images.gotrue.image_id str "$GOTRUE_IMAGE_ID"
  record images.gotrue.platform str "$gotrue_platform"
  record images.pull_count int 2
else
  record images.pull_count int 1
fi

mapfile -t existing_prefixes < <(
  {
    ip -o -4 route show scope link 2>/dev/null | awk '$1 ~ /\// {print $1}'
    for id in $(docker network ls -q); do
      docker network inspect --format '{{range .IPAM.Config}}{{println .Subnet}}{{end}}' "$id" 2>/dev/null
    done
  } | awk 'NF' | sort -u
)
python3 "$ROOT/scripts/check_subnet.py" "$SUBNET" "${existing_prefixes[@]:-}" || block FIXED_SUBNET_COLLISION

network_args=(
  --driver bridge
  --ipv6=false
  --subnet "$SUBNET"
  --label "io.fawxzzy.packet=${PACKET}"
  --label "io.fawxzzy.role=${NETWORK_ROLE}"
  --label "com.supabase.cli.project=${PROJECT}"
  --label "com.docker.compose.project=${PROJECT}"
  --opt "com.docker.network.bridge.host_binding_ipv4=127.0.0.1"
)
if [[ "$MODE" == "firewall-rehearsal" ]]; then
  gateway_contract request "$SUBNET" "$SUBNET_GATEWAY" \
    || block PACKET_GATEWAY_REQUEST_INVALID
  ip link show dev "$FIREWALL_BRIDGE_NAME" >"$RAW/bridge-collision.log" 2>&1 \
    && block FIREWALL_BRIDGE_COLLISION
  network_args+=(
    --gateway "$SUBNET_GATEWAY"
    --opt "com.docker.network.bridge.gateway_mode_ipv4=nat"
    --opt "com.docker.network.bridge.name=${FIREWALL_BRIDGE_NAME}"
  )
else
  network_args+=(
    --internal
    --opt "com.docker.network.bridge.gateway_mode_ipv4=isolated"
  )
fi
if [[ "$MODE" == "firewall-rehearsal" ]]; then
  firewall_prepare_state="$RUNTIME/firewall-prepare.tsv"
  python3 -B "$ROOT/scripts/firewall_boundary.py" prepare \
    --ledger "$FIREWALL_LEDGER" \
    --interface "$FIREWALL_BRIDGE_NAME" \
    --subnet "$SUBNET" >"$firewall_prepare_state" 2>"$RAW/firewall-prepare.log" \
    || {
      failure_code="$(awk -F '\t' '$1=="firewall.failure_code"{print $3; exit}' "$firewall_prepare_state" 2>/dev/null || true)"
      [[ "$failure_code" =~ ^FIREWALL_[A-Z0-9_]+$ ]] || failure_code=FIREWALL_PREPARE_FAILED
      block "$failure_code"
    }
  cat "$firewall_prepare_state" >>"$STATE_FILE"
fi
NETWORK_ID="$(docker network create "${network_args[@]}" "$NETWORK_NAME" 2>"$RAW/network-create.log")" \
  || block NETWORK_CREATE_FAILED
[[ -n "$NETWORK_ID" ]] || block NETWORK_ID_EMPTY
record network.id_sha256 str "$(hash_identifier "$NETWORK_ID")"
record network.name str "$NETWORK_NAME"
record network.subnet str "$SUBNET"
if [[ "$MODE" == "firewall-rehearsal" ]]; then
  record network.internal bool false
else
  record network.internal bool true
fi
record network.ipv6 bool false
record network.host_binding_ipv4 str 127.0.0.1
if [[ "$MODE" == "firewall-rehearsal" ]]; then
  record network.gateway_mode_ipv4 str nat
  record network.bridge_name str "$FIREWALL_BRIDGE_NAME"
else
  record network.gateway_mode_ipv4 str isolated
fi
if [[ "$MODE" == "firewall-rehearsal" ]]; then
  validate_network_ipam_contract "$NETWORK_ID" after-create \
    || block NETWORK_IPAM_CONTRACT_MISMATCH
  ipam_gateway="$SUBNET_GATEWAY"
else
  ipam_gateway="$(docker network inspect --format '{{(index .IPAM.Config 0).Gateway}}' "$NETWORK_ID")"
fi
record network.ipam_gateway str "${ipam_gateway:-none}"

[[ "$(docker network inspect --format '{{.Id}}' "$NETWORK_ID")" == "$NETWORK_ID" ]] || block NETWORK_ID_MISMATCH
[[ "$(docker network inspect --format '{{.Driver}}' "$NETWORK_ID")" == "bridge" ]] || block NETWORK_DRIVER_MISMATCH
if [[ "$MODE" == "firewall-rehearsal" ]]; then
  [[ "$(docker network inspect --format '{{.Internal}}' "$NETWORK_ID")" == "false" ]] || block NETWORK_UNEXPECTEDLY_INTERNAL
else
  [[ "$(docker network inspect --format '{{.Internal}}' "$NETWORK_ID")" == "true" ]] || block NETWORK_NOT_INTERNAL
fi
[[ "$(docker network inspect --format '{{.EnableIPv6}}' "$NETWORK_ID")" == "false" ]] || block NETWORK_IPV6_ENABLED
[[ "$(docker network inspect --format '{{(index .IPAM.Config 0).Subnet}}' "$NETWORK_ID")" == "$SUBNET" ]] || block NETWORK_SUBNET_MISMATCH
[[ "$(docker network inspect --format '{{index .Options "com.docker.network.bridge.host_binding_ipv4"}}' "$NETWORK_ID")" == "127.0.0.1" ]] || block NETWORK_HOST_BINDING_MISMATCH
if [[ "$MODE" == "firewall-rehearsal" ]]; then
  [[ "$(docker network inspect --format '{{index .Options "com.docker.network.bridge.gateway_mode_ipv4"}}' "$NETWORK_ID")" == "nat" ]] || block NETWORK_GATEWAY_MODE_MISMATCH
  [[ "$(docker network inspect --format '{{index .Options "com.docker.network.bridge.name"}}' "$NETWORK_ID")" == "$FIREWALL_BRIDGE_NAME" ]] || block NETWORK_BRIDGE_NAME_MISMATCH
else
  [[ "$(docker network inspect --format '{{index .Options "com.docker.network.bridge.gateway_mode_ipv4"}}' "$NETWORK_ID")" == "isolated" ]] || block NETWORK_GATEWAY_MODE_MISMATCH
fi
[[ "$(docker network ls -q --filter "label=io.fawxzzy.packet=${PACKET}" | awk 'NF' | wc -l)" == "1" ]] || block PACKET_NETWORK_COUNT_MISMATCH
assert_frozen_network after_create empty
bridge_name="br-${NETWORK_ID:0:12}"
[[ "$MODE" != "firewall-rehearsal" ]] || bridge_name="$FIREWALL_BRIDGE_NAME"
ip link show dev "$bridge_name" >"$RAW/bridge-link.log" 2>&1 || block PACKET_BRIDGE_MISSING
if [[ "$MODE" == "firewall-rehearsal" ]]; then
  ip -4 -o addr show dev "$bridge_name" | grep -Fq " ${SUBNET_GATEWAY}/" || block PACKET_GATEWAY_ADDRESS_MISMATCH
else
  if ip -4 -o addr show dev "$bridge_name" | grep -q ' inet '; then
    block ISOLATED_BRIDGE_HAS_HOST_ADDRESS
  fi
fi

if [[ "$MODE" == "firewall-rehearsal" ]]; then
  run_firewall_publication_rehearsal
  exit 0
fi

host_ips="$(hostname -I 2>/dev/null | xargs)"
canary_image="$POSTGRES_EXPECTED"
[[ "$MODE" != "direct-port" ]] || canary_image="$POSTGRES_PULL"
set +e
docker run --rm --pull=never \
  --name "${PROJECT}-canary" \
  --label "io.fawxzzy.packet=${PACKET}" \
  --label "io.fawxzzy.role=prestart-canary" \
  --network "$NETWORK_ID" \
  --add-host host.docker.internal:host-gateway \
  "$canary_image" bash -ceu '
    command -v ip >/dev/null
    command -v getent >/dev/null
    command -v ping >/dev/null
    command -v timeout >/dev/null
    test -z "$(ip -4 route show default)" || exit 11
    test -z "$(ip -6 route show default)" || exit 12
    ! timeout 5 getent ahostsv4 example.com >/dev/null 2>&1 || exit 13
    ! timeout 3 bash -c "</dev/tcp/1.1.1.1/443" >/dev/null 2>&1 || exit 14
    ! timeout 3 bash -c "</dev/tcp/169.254.169.254/80" >/dev/null 2>&1 || exit 15
    if test -n "$1"; then
      ! ping -c 1 -W 1 "$1" >/dev/null 2>&1 || exit 16
    fi
    for address in $2; do
      ! ping -c 1 -W 1 "$address" >/dev/null 2>&1 || exit 17
    done
  ' -- "$ipam_gateway" "$host_ips" >"$RAW/prestart-canary.log" 2>&1
canary_rc="$?"
set -e
case "$canary_rc" in
  0) ;;
  11) block DEFAULT_ROUTE_PRESENT ;;
  12) block IPV6_DEFAULT_ROUTE_PRESENT ;;
  13) block EXTERNAL_DNS_SUCCEEDED ;;
  14) block LITERAL_IP_EGRESS_SUCCEEDED ;;
  15) block METADATA_EGRESS_SUCCEEDED ;;
  16) block PACKET_GATEWAY_REACHABLE ;;
  17) block HOST_ADDRESS_REACHABLE ;;
  *) block PRESTART_EGRESS_CANARY_FAILED "canary-exit-${canary_rc}" ;;
esac
record canaries.prestart.no_default_route bool true
record canaries.prestart.external_dns_failed bool true
record canaries.prestart.literal_ip_failed bool true
record canaries.prestart.metadata_failed bool true
record canaries.prestart.host_gateway_failed bool true
assert_frozen_network pre_cli empty

if [[ "$MODE" == "direct-port" ]]; then
  run_direct_port_probe
  exit 0
fi

prepare_root_init_scratch
CLI_PROJECT_DIR="$ROOT_INIT_WORKDIR"
[[ ! -e "$CLI_PROJECT_DIR/supabase/migrations" ]] || block APPLICATION_MIGRATIONS_PRESENT
[[ ! -e "$CLI_PROJECT_DIR/supabase/seed.sql" ]] || block SEED_FILE_PRESENT

python3 "$ROOT/scripts/container_watch.py" \
  --network-id "$NETWORK_ID" \
  --network-name "$NETWORK_NAME" \
  --network-subnet "$SUBNET" \
  --packet "$PACKET" \
  --postgres-image-id "$POSTGRES_IMAGE_ID" \
  --gotrue-image-id "$GOTRUE_IMAGE_ID" \
  --audit-file "$AUDIT_FILE" \
  --violation-file "$VIOLATION_FILE" \
  --ready-file "$WATCH_READY" \
  >"$RAW/container-watcher.log" 2>&1 &
WATCH_PID="$!"
for _ in $(seq 1 50); do
  [[ -f "$WATCH_READY" ]] && break
  kill -0 "$WATCH_PID" 2>/dev/null || break
  sleep 0.1
done
if [[ ! -f "$WATCH_READY" ]]; then
  if [[ -s "$VIOLATION_FILE" ]]; then
    block "$(first_observer_violation)"
  fi
  block CONTAINER_WATCHER_NOT_READY
fi
assert_frozen_network pre_cli_start empty
freeze_precli_objects_and_listeners
EVENT_SINCE="$(date -u +%s)"
record docker_event_history.boundary_frozen bool true

[[ ! -e "$DOCKER_API_SOCKET" && ! -e "$DOCKER_API_READY" && ! -e "$DOCKER_API_BOUNDARY_STATE_FILE" ]] \
  || block DOCKER_API_OBSERVER_PREEXISTING_STATE
[[ "$docker_api_version" =~ ^[0-9]+\.[0-9]+$ ]] || block DOCKER_API_VERSION_INVALID
python3 -B - \
  "$DOCKER_API_POLICY_FILE" "$docker_api_version" "$PROJECT" \
  "$NETWORK_NAME" "$NETWORK_ID" "$DB_NAME" "$DB_VOLUME" "$DB_PORT" \
  "$POSTGRES_EXPECTED" "$POSTGRES_IMAGE_ID" "$POSTGRES_DIGEST" \
  "$GOTRUE_EXPECTED" "$GOTRUE_IMAGE_ID" "$GOTRUE_DIGEST" <<'PY'
import json
import os
import sys

path, api_version, project, network_name, network_id, db_name, db_volume, db_port, postgres_ref, postgres_id, postgres_digest, gotrue_ref, gotrue_id, gotrue_digest = sys.argv[1:]
value = {
    "schema": "fawxzzy.hosted-replay-harness.db-start-policy.v1",
    "matrix_sha256": "9669ebd4ae75cfdc3950c9db8b2786270023ce0e26dde993806b3f7b6b2c5492",
    "generation": 0,
    "nonce": os.urandom(32).hex(),
    "api_version": api_version,
    "project": project,
    "network_name": network_name,
    "network_id": network_id,
    "db_name": db_name,
    "db_volume": db_volume,
    "db_port": db_port,
    "postgres_image_ref": postgres_ref,
    "postgres_image_id": postgres_id,
    "postgres_digest": postgres_digest,
    "gotrue_image_ref": gotrue_ref,
    "gotrue_image_id": gotrue_id,
    "gotrue_digest": gotrue_digest,
}
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
    json.dump(value, stream, sort_keys=True, separators=(",", ":"))
PY
[[ "$(stat -c '%a' "$DOCKER_API_POLICY_FILE")" == "600" ]] || block POLICY_DESCRIPTOR_PERMISSIONS
exec 3<"$DOCKER_API_POLICY_FILE"
rm -f -- "$DOCKER_API_POLICY_FILE" || block POLICY_DESCRIPTOR_UNLINK_FAILED
[[ ! -e "$DOCKER_API_POLICY_FILE" ]] || block POLICY_DESCRIPTOR_UNLINK_FAILED
python3 -B "$ROOT/scripts/docker_api_boundary.py" \
  --listen "$DOCKER_API_SOCKET" \
  --upstream /var/run/docker.sock \
  --state "$DOCKER_API_BOUNDARY_STATE_FILE" \
  --ready "$DOCKER_API_READY" \
  --policy-fd 3 \
  3<&3 >"$RAW/docker-api-observer.log" 2>&1 &
DOCKER_API_OBSERVER_PID="$!"
exec 3<&-
for _ in $(seq 1 50); do
  [[ -S "$DOCKER_API_SOCKET" && -f "$DOCKER_API_READY" ]] && break
  kill -0 "$DOCKER_API_OBSERVER_PID" 2>/dev/null || break
  sleep 0.1
done
if [[ ! -S "$DOCKER_API_SOCKET" || ! -f "$DOCKER_API_READY" ]]; then
  docker_api_observer_rc=0
  stop_docker_api_observer || docker_api_observer_rc="$?"
  if [[ -f "$DOCKER_API_BOUNDARY_STATE_FILE" ]]; then
    cat "$DOCKER_API_BOUNDARY_STATE_FILE" >>"$STATE_FILE"
    policy_start_failure="$(awk -F '\t' '$1=="docker_api_boundary.policy_failure_code"{print $3; exit}' "$DOCKER_API_BOUNDARY_STATE_FILE")"
    if [[ "$policy_start_failure" =~ ^POLICY_[A-Z0-9_]+$ ]]; then
      block "$policy_start_failure" observer-startup
    fi
  fi
  block DOCKER_API_OBSERVER_NOT_READY "observer-exit-${docker_api_observer_rc}"
fi
[[ "$(stat -c '%a' "$DOCKER_API_SOCKET")" == "600" ]] || block DOCKER_API_OBSERVER_SOCKET_PERMISSIONS
[[ "$(stat -c '%a' "$DOCKER_API_READY")" == "600" ]] || block DOCKER_API_OBSERVER_READY_PERMISSIONS

set +e
(
  cd -- "$CLI_PROJECT_DIR"
  env -i \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME="$ROOT_INIT_HOME" \
    XDG_CONFIG_HOME="$ROOT_INIT_XDG_CONFIG" \
    XDG_CACHE_HOME="$ROOT_INIT_XDG_CACHE" \
    XDG_DATA_HOME="$ROOT_INIT_XDG_DATA" \
    XDG_STATE_HOME="$ROOT_INIT_XDG_STATE" \
    TMPDIR="$ROOT_INIT_TMP" \
    DO_NOT_TRACK=1 \
    DOCKER_HOST="unix://$DOCKER_API_SOCKET" \
    timeout --signal=TERM --kill-after=10s 300s "$RUNTIME/bin/supabase" \
    --workdir "$CLI_PROJECT_DIR" \
    --network-id "$NETWORK_NAME" \
    --yes \
    db start
) >"$RAW/supabase-db-start.log" 2>&1
cli_rc="$?"
set -e
sleep 1
docker_api_observer_rc=0
stop_docker_api_observer || docker_api_observer_rc="$?"
watcher_alive=0
kill -0 "$WATCH_PID" 2>/dev/null && watcher_alive=1
stop_watcher
if ! python3 -B "$ROOT/scripts/classify_db_start_log.py" \
  --input "$RAW/supabase-db-start.log" \
  --exit-code "$cli_rc" >"$DB_START_DIAGNOSTIC_FILE" 2>"$RAW/db-start-sanitizer.log"; then
  rm -f -- "$RAW/supabase-db-start.log"
  block DB_START_LOG_SANITIZER_FAILED
fi
cat "$DB_START_DIAGNOSTIC_FILE" >>"$STATE_FILE"
db_start_category="$(awk -F '\t' '$1=="supabase_cli.db_start_diagnostic.category"{print $3; exit}' "$DB_START_DIAGNOSTIC_FILE")"
if ! rm -f -- "$RAW/supabase-db-start.log"; then
  block DB_START_RAW_LOG_DELETE_FAILED
fi
[[ ! -e "$RAW/supabase-db-start.log" ]] || block DB_START_RAW_LOG_DELETE_FAILED
record supabase_cli.db_start_diagnostic.raw_deleted bool true
[[ "$db_start_category" =~ ^[A-Z0-9_]+$ ]] || block DB_START_LOG_SANITIZER_FAILED

docker_api_boundary_state_present=true
if [[ ! -f "$DOCKER_API_BOUNDARY_STATE_FILE" ]]; then
  docker_api_boundary_state_present=false
  docker_api_classification=OBSERVER_STATE_MISSING
else
  cat "$DOCKER_API_BOUNDARY_STATE_FILE" >>"$STATE_FILE"
  docker_api_classification="$(awk -F '\t' '$1=="docker_api_boundary.classification"{print $3; exit}' "$DOCKER_API_BOUNDARY_STATE_FILE")"
fi
record docker_api_boundary.observer_exit_code int "$docker_api_observer_rc"
record docker_api_boundary.state_present bool "$docker_api_boundary_state_present"
[[ "$docker_api_boundary_state_present" == "true" ]] || block DOCKER_API_OBSERVER_STATE_MISSING
[[ "$docker_api_classification" =~ ^[A-Z0-9_]+$ ]] || block DOCKER_API_OBSERVER_STATE_INVALID
[[ "$docker_api_observer_rc" == "0" || "$docker_api_observer_rc" == "2" || "$docker_api_observer_rc" == "3" ]] \
  || block DOCKER_API_OBSERVER_FAILED "observer-exit-${docker_api_observer_rc}"
[[ "$cli_rc" != "124" ]] || block SUPABASE_DB_START_TIMEOUT
if [[ "$watcher_alive" != "1" ]]; then
  if [[ -s "$VIOLATION_FILE" ]]; then
    block "$(first_observer_violation)"
  fi
  block CONTAINER_WATCHER_EXITED
fi
if [[ -s "$VIOLATION_FILE" ]]; then
  block "$(first_observer_violation)"
fi

case "$ROOT_INIT_DIR" in
  "$RUNTIME"/root-init) rm -rf -- "$ROOT_INIT_DIR" || block ROOT_INIT_SCRATCH_DELETE_FAILED ;;
  *) block ROOT_INIT_SCRATCH_DELETE_FAILED invalid-root-init-path ;;
esac
[[ ! -e "$ROOT_INIT_DIR" ]] || block ROOT_INIT_SCRATCH_DELETE_FAILED
record db_start.clean_environment bool true
record db_start.scratch_deleted bool true
record docker_api_boundary.policy_descriptor_unlinked bool true

assert_frozen_network post_cli active
record network.correlated_count_after_cli int 1
native_listener_contract post_cli \
  || block "${LISTENER_FAILURE_CODE:-NATIVE_LISTENER_DRIFT}" "${LISTENER_LAST_PHASE:-POST_CLI_LISTENER_UNKNOWN}"

EVENT_UNTIL="$(( $(date -u +%s) + 1 ))"
timeout --signal=TERM --kill-after=5s 20s docker events \
  --since "$EVENT_SINCE" --until "$EVENT_UNTIL" \
  --filter type=container \
  --filter event=create --filter event=start --filter event=die --filter event=destroy \
  --filter "label=com.supabase.cli.project=${PROJECT}" \
  --format '{{json .}}' >"$CONTAINER_EVENTS_FILE" 2>"$RAW/docker-container-events.log" \
  || block DOCKER_EVENT_HISTORY_QUERY_FAILED
timeout --signal=TERM --kill-after=5s 20s docker events \
  --since "$EVENT_SINCE" --until "$EVENT_UNTIL" \
  --filter type=volume \
  --filter event=create \
  --filter "label=com.supabase.cli.project=${PROJECT}" \
  --format '{{json .}}' >"$VOLUME_EVENTS_FILE" 2>"$RAW/docker-volume-events.log" \
  || block DOCKER_EVENT_HISTORY_QUERY_FAILED
timeout --signal=TERM --kill-after=5s 20s docker events \
  --since "$EVENT_SINCE" --until "$EVENT_UNTIL" \
  --filter type=network \
  --filter event=connect \
  --filter "network=${NETWORK_NAME}" \
  --format '{{json .}}' >"$NETWORK_EVENTS_FILE" 2>"$RAW/docker-network-events.log" \
  || block DOCKER_EVENT_HISTORY_QUERY_FAILED

if ! python3 -B "$ROOT/scripts/classify_docker_events.py" \
  --container-events "$CONTAINER_EVENTS_FILE" \
  --volume-events "$VOLUME_EVENTS_FILE" \
  --network-events "$NETWORK_EVENTS_FILE" \
  --live-audit "$AUDIT_FILE" \
  --project "$PROJECT" \
  --network-name "$NETWORK_NAME" \
  --network-id "$NETWORK_ID" \
  --db-volume "$DB_VOLUME" \
  --postgres-image "$POSTGRES_EXPECTED" \
  --postgres-image-id "$POSTGRES_IMAGE_ID" \
  --gotrue-image "$GOTRUE_EXPECTED" \
  --gotrue-image-id "$GOTRUE_IMAGE_ID" \
  >"$EVENT_HISTORY_STATE_FILE" 2>"$RAW/docker-event-history-sanitizer.log"; then
  block DOCKER_EVENT_HISTORY_SANITIZER_FAILED
fi
cat "$EVENT_HISTORY_STATE_FILE" >>"$STATE_FILE"
event_classification="$(awk -F '\t' '$1=="docker_event_history.classification"{print $3; exit}' "$EVENT_HISTORY_STATE_FILE")"
event_image_correlated="$(awk -F '\t' '$1=="docker_event_history.pinned_image_identity_correlated"{print $3; exit}' "$EVENT_HISTORY_STATE_FILE")"
event_network_correlated="$(awk -F '\t' '$1=="docker_event_history.frozen_network_id_correlated"{print $3; exit}' "$EVENT_HISTORY_STATE_FILE")"
[[ "$event_classification" =~ ^[A-Z0-9_]+$ ]] || block DOCKER_EVENT_HISTORY_SANITIZER_FAILED
[[ "$event_image_correlated" == "true" ]] || block EVENT_HISTORY_IMAGE_IDENTITY_FAILED
[[ "$event_network_correlated" == "true" ]] || block EVENT_HISTORY_NETWORK_CORRELATION_FAILED

database_create_observations="$(python3 -c 'import json,sys; print(sum(json.loads(x).get("role")=="database" and json.loads(x).get("phase")=="create" for x in open(sys.argv[1]) if x.strip()))' "$AUDIT_FILE")"
database_start_observations="$(python3 -c 'import json,sys; print(sum(json.loads(x).get("role")=="database" and json.loads(x).get("phase")=="start" for x in open(sys.argv[1]) if x.strip()))' "$AUDIT_FILE")"
gotrue_create_observations="$(python3 -c 'import json,sys; print(sum(json.loads(x).get("role")=="gotrue_migration" and json.loads(x).get("phase")=="create" for x in open(sys.argv[1]) if x.strip()))' "$AUDIT_FILE")"
gotrue_start_observations="$(python3 -c 'import json,sys; print(sum(json.loads(x).get("role")=="gotrue_migration" and json.loads(x).get("phase")=="start" for x in open(sys.argv[1]) if x.strip()))' "$AUDIT_FILE")"
record container_lifecycle.database.create_count int "$database_create_observations"
record container_lifecycle.database.start_count int "$database_start_observations"
record container_lifecycle.gotrue_migration.create_count int "$gotrue_create_observations"
record container_lifecycle.gotrue_migration.start_count int "$gotrue_start_observations"
record container_lifecycle.network_id_correlated bool true
docker_api_request_count="$(awk -F '\t' '$1=="docker_api_boundary.request_count"{print $3; exit}' "$DOCKER_API_BOUNDARY_STATE_FILE")"
docker_api_response_count="$(awk -F '\t' '$1=="docker_api_boundary.response_count"{print $3; exit}' "$DOCKER_API_BOUNDARY_STATE_FILE")"
docker_api_write_attempt_count="$(awk -F '\t' '$1=="docker_api_boundary.write_attempt_count"{print $3; exit}' "$DOCKER_API_BOUNDARY_STATE_FILE")"
docker_api_unknown_phase_count="$(awk -F '\t' '$1=="docker_api_boundary.phase_counts.UNKNOWN_API_PHASE"{print $3; exit}' "$DOCKER_API_BOUNDARY_STATE_FILE")"
docker_api_image_pull_count="$(awk -F '\t' '$1=="docker_api_boundary.phase_counts.IMAGE_PULL"{print $3; exit}' "$DOCKER_API_BOUNDARY_STATE_FILE")"
docker_api_container_list_count="$(awk -F '\t' '$1=="docker_api_boundary.phase_counts.CONTAINER_LIST"{print $3; exit}' "$DOCKER_API_BOUNDARY_STATE_FILE")"
docker_api_cleanup_count="$(awk -F '\t' '$1=="docker_api_boundary.phase_counts.CLEANUP_API_PHASE"{print $3; exit}' "$DOCKER_API_BOUNDARY_STATE_FILE")"
docker_api_forwarding_errors="$(awk -F '\t' '$1=="docker_api_boundary.forwarding_error_count"{print $3; exit}' "$DOCKER_API_BOUNDARY_STATE_FILE")"
docker_api_parser_errors="$(awk -F '\t' '$1=="docker_api_boundary.parser_error_count"{print $3; exit}' "$DOCKER_API_BOUNDARY_STATE_FILE")"
docker_api_policy_mode="$(awk -F '\t' '$1=="docker_api_boundary.policy_mode"{print $3; exit}' "$DOCKER_API_BOUNDARY_STATE_FILE")"
docker_api_policy_matrix="$(awk -F '\t' '$1=="docker_api_boundary.policy_matrix_sha256"{print $3; exit}' "$DOCKER_API_BOUNDARY_STATE_FILE")"
docker_api_policy_digest="$(awk -F '\t' '$1=="docker_api_boundary.policy_digest"{print $3; exit}' "$DOCKER_API_BOUNDARY_STATE_FILE")"
docker_api_policy_consumed="$(awk -F '\t' '$1=="docker_api_boundary.policy_descriptor_consumed"{print $3; exit}' "$DOCKER_API_BOUNDARY_STATE_FILE")"
docker_api_policy_complete="$(awk -F '\t' '$1=="docker_api_boundary.policy_complete"{print $3; exit}' "$DOCKER_API_BOUNDARY_STATE_FILE")"
docker_api_policy_violations="$(awk -F '\t' '$1=="docker_api_boundary.policy_violation_count"{print $3; exit}' "$DOCKER_API_BOUNDARY_STATE_FILE")"
docker_api_policy_failure="$(awk -F '\t' '$1=="docker_api_boundary.policy_failure_code"{print $3; exit}' "$DOCKER_API_BOUNDARY_STATE_FILE")"
for count in \
  "$docker_api_request_count" \
  "$docker_api_response_count" \
  "$docker_api_write_attempt_count" \
  "$docker_api_unknown_phase_count" \
  "$docker_api_image_pull_count" \
  "$docker_api_container_list_count" \
  "$docker_api_cleanup_count" \
  "$docker_api_forwarding_errors" \
  "$docker_api_parser_errors" \
  "$docker_api_policy_consumed" \
  "$docker_api_policy_complete" \
  "$docker_api_policy_violations"; do
  [[ "$count" =~ ^[0-9]+$ ]] || block DOCKER_API_OBSERVER_STATE_INVALID
done
case "$event_classification" in
  OBSERVER_COVERAGE_GAP|CONTAINER_CREATE_FAILED|DATABASE_HEALTH_FAILED|GOTRUE_MIGRATION_FAILED)
    block "$event_classification" "cli-exit-${cli_rc}"
    ;;
  CONTAINER_CREATED_NOT_STARTED)
    case "$db_start_category" in
      CONTAINER_START_FAILED|PORT_BIND_FAILED|GOTRUE_MIGRATION_FAILED)
        block "$db_start_category" "cli-exit-${cli_rc}"
        ;;
      *) block CONTAINER_CREATED_NOT_STARTED "cli-exit-${cli_rc}" ;;
    esac
    ;;
  EVENT_HISTORY_CONSISTENT|NO_DOCKER_MUTATION_OBSERVED) ;;
  *) block DOCKER_EVENT_HISTORY_SANITIZER_FAILED ;;
esac
case "$docker_api_classification" in
  DB_START_POLICY_COMPLETE|DB_START_POLICY_INCOMPLETE|DB_START_POLICY_VIOLATION) ;;
  OBSERVER_FORWARDING_FAILED) block DOCKER_API_OBSERVER_FAILED ;;
  *) block DOCKER_API_OBSERVER_STATE_INVALID ;;
esac
[[ "$docker_api_policy_mode" == "DB_START_V1" ]] || block POLICY_DESCRIPTOR_INVALID
[[ "$docker_api_policy_matrix" == "$POLICY_MATRIX_SHA256" ]] || block POLICY_DESCRIPTOR_INVALID
[[ "$docker_api_policy_digest" =~ ^[0-9a-f]{64}$ ]] || block DOCKER_API_OBSERVER_STATE_INVALID
[[ "$docker_api_policy_consumed" == "1" ]] || block POLICY_DESCRIPTOR_INVALID
[[ "$docker_api_unknown_phase_count" == "0" ]] || block POLICY_OPERATION_REJECTED
[[ "$docker_api_image_pull_count" == "0" ]] || block POLICY_OPERATION_REJECTED
[[ "$docker_api_container_list_count" == "0" ]] || block POLICY_OPERATION_REJECTED
[[ "$docker_api_cleanup_count" == "0" ]] || block POLICY_OPERATION_REJECTED
[[ "$docker_api_forwarding_errors" == "0" && "$docker_api_parser_errors" == "0" ]] \
  || block DOCKER_API_OBSERVER_FAILED
if [[ "$docker_api_policy_violations" != "0" || "$docker_api_observer_rc" == "2" ]]; then
  [[ "$docker_api_policy_failure" =~ ^POLICY_[A-Z0-9_]+$ ]] || block DB_START_POLICY_VIOLATION
  block "$docker_api_policy_failure" "cli-exit-${cli_rc}"
fi
if [[ "$docker_api_policy_complete" != "1" || "$docker_api_classification" != "DB_START_POLICY_COMPLETE" || "$docker_api_observer_rc" != "0" ]]; then
  if [[ "$db_start_category" != "UNKNOWN_SANITIZED" ]]; then
    block "$db_start_category" "cli-exit-${cli_rc}"
  fi
  block DB_START_POLICY_INCOMPLETE "cli-exit-${cli_rc}"
fi

if [[ "$cli_rc" != "0" ]]; then
  if [[ "$db_start_category" != "UNKNOWN_SANITIZED" ]]; then
    block "$db_start_category" "cli-exit-${cli_rc}"
  fi
  if [[ "$event_classification" == "NO_DOCKER_MUTATION_OBSERVED" ]]; then
    case "$docker_api_classification" in
      NO_DOCKER_API_REQUEST_OBSERVED) block NO_DOCKER_API_REQUEST_OBSERVED "cli-exit-${cli_rc}" ;;
      DOCKER_API_ERROR_RESPONSE_OBSERVED) block DOCKER_API_ERROR_RESPONSE_OBSERVED "cli-exit-${cli_rc}" ;;
      DOCKER_API_REQUESTS_OBSERVED) block DOCKER_API_BOUNDARY_OBSERVED "cli-exit-${cli_rc}" ;;
    esac
    block OTHER_PRECONTAINER_FAILURE "cli-exit-${cli_rc}"
  fi
  block SUPABASE_DB_START_FAILED "cli-exit-${cli_rc}"
fi

record database.audit_observations int "$database_start_observations"
record gotrue.audit_observations int "$gotrue_start_observations"
[[ "$database_create_observations" == "1" && "$database_start_observations" == "1" ]] || block DATABASE_CONTAINER_NOT_EXACTLY_ONCE
[[ "$gotrue_create_observations" == "1" && "$gotrue_start_observations" == "1" ]] || block GOTRUE_MIGRATION_NOT_EXACTLY_ONCE

db_id="$(docker ps -q --filter "name=^/${DB_NAME}$" --filter "label=com.supabase.cli.project=${PROJECT}")"
[[ -n "$db_id" ]] || block DATABASE_CONTAINER_MISSING
published="$(docker port "$db_id" 5432/tcp 2>"$RAW/docker-port.log" | sed '/^$/d')"
[[ "$published" == "127.0.0.1:${DB_PORT}" ]] || block DATABASE_PORT_NOT_LOOPBACK_ONLY
[[ "$(printf '%s\n' "$published" | wc -l)" == "1" ]] || block DATABASE_PORT_BINDING_COUNT_MISMATCH
timeout 3 bash -c "</dev/tcp/127.0.0.1/${DB_PORT}" >/dev/null 2>&1 || block DATABASE_LOOPBACK_CONNECT_FAILED
record database.published_binding str "$published"
record database.loopback_connect bool true

psql_scalar() {
  local sql="$1"
  docker exec "$db_id" psql -X -qAt -v ON_ERROR_STOP=1 -U postgres -d postgres -c "$sql" 2>"$RAW/psql-error.log"
}

available_count="$(psql_scalar "select count(*) from pg_available_extensions where name in ('pg_cron','pg_net');")" || block EXTENSION_AVAILABILITY_QUERY_FAILED
[[ "$available_count" == "2" ]] || block REQUIRED_EXTENSION_NOT_AVAILABLE
psql_scalar "create extension if not exists pg_cron; create extension if not exists pg_net with schema extensions;" >/dev/null || block EXTENSION_ENABLE_FAILED
installed_count="$(psql_scalar "select count(*) from pg_extension where extname in ('pg_cron','pg_net');")" || block EXTENSION_INSTALL_QUERY_FAILED
[[ "$installed_count" == "2" ]] || block REQUIRED_EXTENSION_NOT_INSTALLED
auth_table_count="$(psql_scalar "select count(*) from information_schema.tables where table_schema='auth';")" || block AUTH_SCHEMA_QUERY_FAILED
(( auth_table_count > 0 )) || block GOTRUE_MIGRATION_SCHEMA_EMPTY
record database.pg_cron_available bool true
record database.pg_net_available bool true
record database.auth_table_count int "$auth_table_count"
record gotrue.migration_succeeded bool true

psql_scalar "
  create schema fp_smoke;
  create table fp_smoke.requests(kind text primary key, request_id bigint not null);
  insert into fp_smoke.requests values
    ('dns', net.http_get(url := 'https://example.com/', timeout_milliseconds := 2000)),
    ('literal', net.http_get(url := 'https://1.1.1.1/', timeout_milliseconds := 2000));
" >/dev/null || block PG_NET_CANARY_QUEUE_FAILED
sleep 5
direct_success_count="$(psql_scalar "select count(*) from fp_smoke.requests r join net._http_response h on h.id=r.request_id where h.status_code is not null;")" || block PG_NET_CANARY_RESULT_FAILED
direct_response_count="$(psql_scalar "select count(*) from fp_smoke.requests r join net._http_response h on h.id=r.request_id;")" || block PG_NET_CANARY_RESULT_FAILED
[[ "$direct_response_count" == "2" ]] || block PG_NET_CANARY_NOT_TERMINAL
[[ "$direct_success_count" == "0" ]] || block PG_NET_EXTERNAL_REQUEST_SUCCEEDED
record canaries.pg_net.request_count int 2
record canaries.pg_net.terminal_response_count int "$direct_response_count"
record canaries.pg_net.external_success_count int "$direct_success_count"

psql_scalar "
  create table fp_smoke.cron_guard(singleton boolean primary key default true, request_id bigint, invoked_at timestamptz default clock_timestamp());
  create function fp_smoke.cron_once() returns void language plpgsql as \$body\$
  declare queued_id bigint;
  begin
    insert into fp_smoke.cron_guard(singleton) values (true) on conflict do nothing;
    if found then
      queued_id := net.http_get(url := 'https://1.1.1.1/', timeout_milliseconds := 2000);
      update fp_smoke.cron_guard set request_id=queued_id where singleton=true;
    end if;
  end
  \$body\$;
" >/dev/null || block PG_CRON_CANARY_SETUP_FAILED
cron_job_id="$(psql_scalar "select cron.schedule('fp_hosted_replay_ro_001','1 second','select fp_smoke.cron_once()');")" || block PG_CRON_SCHEDULE_FAILED
[[ "$cron_job_id" =~ ^[0-9]+$ ]] || block PG_CRON_JOB_ID_INVALID
cron_invocation_count=0
for _ in $(seq 1 15); do
  cron_invocation_count="$(psql_scalar "select count(*) from fp_smoke.cron_guard where request_id is not null;")" || block PG_CRON_GUARD_QUERY_FAILED
  [[ "$cron_invocation_count" == "1" ]] && break
  sleep 1
done
psql_scalar "select cron.unschedule('fp_hosted_replay_ro_001');" >/dev/null || block PG_CRON_UNSCHEDULE_FAILED
[[ "$cron_invocation_count" == "1" ]] || block PG_CRON_ONE_SHOT_NOT_INVOKED
sleep 5
cron_external_success_count="$(psql_scalar "select count(*) from fp_smoke.cron_guard g join net._http_response h on h.id=g.request_id where h.status_code is not null;")" || block PG_CRON_CANARY_RESULT_FAILED
cron_response_count="$(psql_scalar "select count(*) from fp_smoke.cron_guard g join net._http_response h on h.id=g.request_id;")" || block PG_CRON_CANARY_RESULT_FAILED
cron_run_success_count="$(psql_scalar "select count(*) from cron.job_run_details where jobid=${cron_job_id} and status='succeeded';")" || block PG_CRON_RUN_QUERY_FAILED
(( cron_run_success_count >= 1 )) || block PG_CRON_EXECUTION_FAILED
[[ "$cron_response_count" == "1" ]] || block PG_CRON_CANARY_NOT_TERMINAL
[[ "$cron_external_success_count" == "0" ]] || block PG_CRON_EXTERNAL_REQUEST_SUCCEEDED
record canaries.pg_cron.external_request_count int 1
record canaries.pg_cron.cron_success_count int "$cron_run_success_count"
record canaries.pg_cron.terminal_response_count int "$cron_response_count"
record canaries.pg_cron.external_success_count int "$cron_external_success_count"

psql_scalar "drop schema fp_smoke cascade;" >/dev/null || block SMOKE_SCHEMA_CLEANUP_FAILED
record completed_at str "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SMOKE_PASSED=1
exit 0
