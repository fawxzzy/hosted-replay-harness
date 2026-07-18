#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
MODE="${1:-run}"
RESULT_PROFILE="${RESULT_PROFILE:-}"
[[ "$#" -le 1 ]] || exit 2
case "$MODE" in
  run|direct-port|cleanup-only) ;;
  *) exit 2 ;;
esac
case "$RESULT_PROFILE" in
  ""|direct-docker-port-v1) ;;
  *) exit 2 ;;
esac
CONTAINMENT_PACKET="FP-HOSTED-REPLAY-CONTAINMENT-SMOKE-001"
DIRECT_PACKET="FP-HOSTED-REPLAY-DIRECT-PORT-DIAG-001"
PACKET="$CONTAINMENT_PACKET"
[[ "$MODE" != "direct-port" ]] || PACKET="$DIRECT_PACKET"
PROJECT="fp-hosted-replay-ro-001"
NETWORK_NAME="fp-hosted-replay-ro-001-net"
SUBNET="172.31.253.0/24"
SUBNET_GATEWAY="172.31.253.1"
DB_NAME="supabase_db_${PROJECT}"
DB_VOLUME="$DB_NAME"
DIRECT_DB_NAME="${PROJECT}-direct-postgres"
DB_PORT="56422"
RUNTIME="$ROOT/.smoke-runtime"
RUNTIME_HOME="$RUNTIME/home"
RAW="$RUNTIME/raw"
PROJECT_DIR="$RUNTIME/project"
AUDIT_FILE="$RUNTIME/container-audit.jsonl"
VIOLATION_FILE="$RUNTIME/container-violations.jsonl"
WATCH_READY="$RUNTIME/watcher.ready"
DB_START_DIAGNOSTIC_FILE="$RUNTIME/db-start-diagnostic.tsv"
EVENT_HISTORY_STATE_FILE="$RUNTIME/docker-event-history.tsv"
CONTAINER_EVENTS_FILE="$RAW/docker-container-events.jsonl"
VOLUME_EVENTS_FILE="$RAW/docker-volume-events.jsonl"
NETWORK_EVENTS_FILE="$RAW/docker-network-events.jsonl"
STATE_FILE="$ROOT/artifacts/.state.tsv"
RESULT_FILE="$ROOT/artifacts/containment-smoke.json"
WATCH_PID=""
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

CLI_VERSION="2.109.1"
CLI_COMMIT="6d4c19870ed213ba7f682f117d0345c8a40bfa94"
CLI_SHA="36d87b7fe6b4bcfe89ac47a4354e526cff22480224de426d7b370f6934556976"
CLI_ASSET="supabase_2.109.1_linux_amd64.tar.gz"
CLI_URL="https://github.com/supabase/cli/releases/download/v2.109.1/${CLI_ASSET}"
POSTGRES_TAG="supabase/postgres:17.6.1.143"
POSTGRES_DIGEST="sha256:b021e96054128399f84f24e39d29c21ee7c7169515e5d9e4e99ff15d5043d1d8"
POSTGRES_PULL="supabase/postgres@${POSTGRES_DIGEST}"
POSTGRES_EXPECTED="public.ecr.aws/supabase/postgres:17.6.1.143"
GOTRUE_TAG="supabase/gotrue:v2.192.0"
GOTRUE_DIGEST="sha256:288d880ebc80a1cb5ad52dc7d12328f76e9c90127003306864a270118bba00a8"
GOTRUE_PULL="supabase/gotrue@${GOTRUE_DIGEST}"
GOTRUE_EXPECTED="public.ecr.aws/supabase/gotrue:v2.192.0"

record() {
  local key="$1" kind="$2" value="$3"
  value="${value//$'\t'/ }"
  value="${value//$'\r'/ }"
  value="${value//$'\n'/ }"
  printf '%s\t%s\t%s\n' "$key" "$kind" "$value" >>"$STATE_FILE"
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

hash_identifier() {
  printf 'sha256:%s' "$(printf '%s' "$1" | sha256sum | awk '{print $1}')"
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
  [[ "$(docker network inspect --format '{{.Internal}}' "$NETWORK_NAME" 2>>"$RAW/network-contract.log")" == "true" ]] \
    || { printf 'NETWORK_NOT_INTERNAL\n'; return 1; }
  [[ "$(docker network inspect --format '{{.EnableIPv6}}' "$NETWORK_NAME" 2>>"$RAW/network-contract.log")" == "false" ]] \
    || { printf 'NETWORK_IPV6_ENABLED\n'; return 1; }
  [[ "$(docker network inspect --format '{{(index .IPAM.Config 0).Subnet}}' "$NETWORK_NAME" 2>>"$RAW/network-contract.log")" == "$SUBNET" ]] \
    || { printf 'NETWORK_SUBNET_MISMATCH\n'; return 1; }
  [[ "$(docker network inspect --format '{{index .Options "com.docker.network.bridge.host_binding_ipv4"}}' "$NETWORK_NAME" 2>>"$RAW/network-contract.log")" == "127.0.0.1" ]] \
    || { printf 'NETWORK_HOST_BINDING_MISMATCH\n'; return 1; }
  [[ "$(docker network inspect --format '{{index .Options "com.docker.network.bridge.gateway_mode_ipv4"}}' "$NETWORK_NAME" 2>>"$RAW/network-contract.log")" == "isolated" ]] \
    || { printf 'NETWORK_GATEWAY_MODE_MISMATCH\n'; return 1; }
  [[ "$(docker network inspect --format '{{index .Labels "io.fawxzzy.packet"}}' "$NETWORK_NAME" 2>>"$RAW/network-contract.log")" == "$PACKET" ]] \
    || { printf 'NETWORK_LABEL_MISMATCH\n'; return 1; }
  [[ "$(docker network inspect --format '{{index .Labels "io.fawxzzy.role"}}' "$NETWORK_NAME" 2>>"$RAW/network-contract.log")" == "containment-network" ]] \
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

cleanup_exact() {
  local id label project_label count listener_count container_count volume_count
  stop_watcher

  mapfile -t container_ids < <(
    {
      docker ps -aq --filter "label=io.fawxzzy.packet=${CONTAINMENT_PACKET}" 2>/dev/null || true
      docker ps -aq --filter "label=io.fawxzzy.packet=${DIRECT_PACKET}" 2>/dev/null || true
      docker ps -aq --filter "label=com.supabase.cli.project=${PROJECT}" 2>/dev/null || true
    } | awk 'NF' | sort -u
  )
  for id in "${container_ids[@]:-}"; do
    [[ -n "$id" ]] || continue
    label="$(docker inspect --format '{{index .Config.Labels "io.fawxzzy.packet"}}' "$id" 2>/dev/null || true)"
    project_label="$(docker inspect --format '{{index .Config.Labels "com.supabase.cli.project"}}' "$id" 2>/dev/null || true)"
    if [[ "$label" == "$CONTAINMENT_PACKET" || "$label" == "$DIRECT_PACKET" || "$project_label" == "$PROJECT" ]]; then
      timeout --signal=TERM --kill-after=5s 20s docker rm -f "$id" >"$RAW/cleanup-container-${id:0:12}.log" 2>&1 || true
    fi
  done

  mapfile -t volume_names < <(
    {
      docker volume ls -q --filter "label=io.fawxzzy.packet=${CONTAINMENT_PACKET}" 2>/dev/null || true
      docker volume ls -q --filter "label=io.fawxzzy.packet=${DIRECT_PACKET}" 2>/dev/null || true
      docker volume ls -q --filter "label=com.supabase.cli.project=${PROJECT}" 2>/dev/null || true
    } | awk 'NF' | sort -u
  )
  for id in "${volume_names[@]:-}"; do
    [[ -n "$id" ]] || continue
    label="$(docker volume inspect --format '{{index .Labels "io.fawxzzy.packet"}}' "$id" 2>/dev/null || true)"
    project_label="$(docker volume inspect --format '{{index .Labels "com.supabase.cli.project"}}' "$id" 2>/dev/null || true)"
    if [[ "$label" == "$CONTAINMENT_PACKET" || "$label" == "$DIRECT_PACKET" || "$project_label" == "$PROJECT" ]]; then
      timeout --signal=TERM --kill-after=5s 20s docker volume rm "$id" >"$RAW/cleanup-volume.log" 2>&1 || true
    fi
  done

  mapfile -t network_ids < <(
    {
      docker network ls -q --filter "label=io.fawxzzy.packet=${CONTAINMENT_PACKET}" 2>/dev/null || true
      docker network ls -q --filter "label=io.fawxzzy.packet=${DIRECT_PACKET}" 2>/dev/null || true
      docker network ls -q --filter "label=com.supabase.cli.project=${PROJECT}" 2>/dev/null || true
    } | awk 'NF' | sort -u
  )
  for id in "${network_ids[@]:-}"; do
    [[ -n "$id" ]] || continue
    label="$(docker network inspect --format '{{index .Labels "io.fawxzzy.packet"}}' "$id" 2>/dev/null || true)"
    project_label="$(docker network inspect --format '{{index .Labels "com.supabase.cli.project"}}' "$id" 2>/dev/null || true)"
    if [[ "$label" == "$CONTAINMENT_PACKET" || "$label" == "$DIRECT_PACKET" || "$project_label" == "$PROJECT" ]]; then
      timeout --signal=TERM --kill-after=5s 20s docker network rm "$id" >"$RAW/cleanup-network-${id:0:12}.log" 2>&1 || true
    fi
  done

  count="$({ docker ps -aq --filter "label=io.fawxzzy.packet=${CONTAINMENT_PACKET}" 2>/dev/null; docker ps -aq --filter "label=io.fawxzzy.packet=${DIRECT_PACKET}" 2>/dev/null; docker ps -aq --filter "label=com.supabase.cli.project=${PROJECT}" 2>/dev/null; } | awk 'NF' | sort -u | wc -l)"
  record cleanup.containers_remaining int "$count"
  container_count="$count"
  count="$({ docker volume ls -q --filter "label=io.fawxzzy.packet=${CONTAINMENT_PACKET}" 2>/dev/null; docker volume ls -q --filter "label=io.fawxzzy.packet=${DIRECT_PACKET}" 2>/dev/null; docker volume ls -q --filter "label=com.supabase.cli.project=${PROJECT}" 2>/dev/null; } | awk 'NF' | sort -u | wc -l)"
  record cleanup.volumes_remaining int "$count"
  volume_count="$count"
  count="$({ docker network ls -q --filter "label=io.fawxzzy.packet=${CONTAINMENT_PACKET}" 2>/dev/null; docker network ls -q --filter "label=io.fawxzzy.packet=${DIRECT_PACKET}" 2>/dev/null; docker network ls -q --filter "label=com.supabase.cli.project=${PROJECT}" 2>/dev/null; } | awk 'NF' | sort -u | wc -l)"
  record cleanup.networks_remaining int "$count"
  if capture_listener_snapshot cleanup "$DB_PORT"; then
    listener_count="$LISTENER_SNAPSHOT_COUNT"
  else
    listener_count=-1
    record cleanup.listener_failure_code str "${LISTENER_FAILURE_CODE:-LISTENER_UNEXPECTED_INTERRUPTION}" || true
    record cleanup.listener_failure_phase str "${LISTENER_LAST_PHASE:-CLEANUP_PORT_56422_UNKNOWN}" || true
  fi
  record cleanup.listeners_remaining int "$listener_count"

  [[ "$container_count" == "0" ]] || return 1
  [[ "$volume_count" == "0" ]] || return 1
  [[ "$count" == "0" ]] || return 1
  [[ "$listener_count" == "0" ]] || return 1
  timeout 2 bash -c "</dev/tcp/127.0.0.1/${DB_PORT}" >/dev/null 2>&1 && return 1
  native_listener_contract cleanup || return 1
  return 0
}

finalize() {
  local original_rc="$?" final_rc=1 final_status=BLOCKED network_code=PASS network_contract_ok=1 primary_failure listener_phase
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

  if [[ "$MODE" == "run" && -n "$NETWORK_ID" ]]; then
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
    record cleanup.failure_code str CLEANUP_RESIDUE
    primary_failure="$(current_failure_code)"
    if [[ -z "$primary_failure" || "$primary_failure" == "HARNESS_INTERRUPTED" ]]; then
      record status str BLOCKED
      record failure.code str CLEANUP_RESIDUE
      record failure.detail str exact-packet-resource-remains
    fi
  elif [[ "$SMOKE_PASSED" == "1" && "$original_rc" == "0" && "$network_contract_ok" == "1" ]]; then
    if [[ "$MODE" == "direct-port" ]]; then
      record status str DIRECT_DOCKER_PORT_PATH_PASS
      final_status=DIRECT_DOCKER_PORT_PATH_PASS
    else
      record status str CONTAINMENT_SMOKE_PASS
      final_status=CONTAINMENT_SMOKE_PASS
    fi
    final_rc=0
  else
    if ! grep -q $'^status\tstr\tBLOCKED$' "$STATE_FILE" 2>/dev/null; then
      record status str BLOCKED
      record failure.code str HARNESS_INTERRUPTED
      record failure.detail str unexpected-nonzero-exit
    fi
  fi

  python3 "$ROOT/scripts/write_result.py" \
    --root "$ROOT" --state "$STATE_FILE" --audit "$AUDIT_FILE" --output "$RESULT_FILE" \
    >"$RAW/result-writer.log" 2>&1

  if [[ "$final_status" == "BLOCKED" ]]; then
    failure_code="$(python3 -c 'import json,sys; print((json.load(open(sys.argv[1])).get("failure") or {}).get("code","UNKNOWN"))' "$RESULT_FILE" 2>/dev/null || printf UNKNOWN)"
    printf 'BLOCKED: %s\n' "$failure_code"
  else
    printf '%s\n' "$final_status"
  fi

  rm -f -- "$STATE_FILE"
  case "$RUNTIME" in
    "$ROOT"/.smoke-runtime) rm -rf -- "$RUNTIME" ;;
  esac
  trap - EXIT
  exit "$final_rc"
}

cleanup_only() {
  local cleanup_rc=0
  mkdir -p -- "$RAW" "$RUNTIME_HOME" "$PROJECT_DIR/supabase" "$ROOT/artifacts"
  STATE_FILE="$ROOT/artifacts/.cleanup-state.tsv"
  : >"$STATE_FILE"
  [[ -e "$AUDIT_FILE" ]] || : >"$AUDIT_FILE"

  if ! cleanup_exact; then
    record status str BLOCKED
    record failure.code str CLEANUP_RESIDUE
    record failure.detail str exact-packet-resource-remains
    cleanup_rc=1
  elif [[ ! -f "$RESULT_FILE" ]]; then
    if [[ "$RESULT_PROFILE" == "direct-docker-port-v1" ]]; then
      record result.profile str direct-docker-port-v1
    fi
    record status str BLOCKED
    record failure.code str HARNESS_INTERRUPTED
    record failure.detail str cleanup-step-recovered-interrupted-run
  fi

  python3 "$ROOT/scripts/write_result.py" \
    --root "$ROOT" --state "$STATE_FILE" --audit "$AUDIT_FILE" --output "$RESULT_FILE" \
    --merge-existing >"$RAW/cleanup-result-writer.log" 2>&1 || cleanup_rc=1

  rm -f -- "$STATE_FILE"
  case "$RUNTIME" in
    "$ROOT"/.smoke-runtime) rm -rf -- "$RUNTIME" ;;
  esac
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

if [[ "$MODE" == "cleanup-only" ]]; then
  cleanup_only
fi

mkdir -p -- "$RAW" "$RUNTIME_HOME" "$PROJECT_DIR/supabase" "$ROOT/artifacts"
: >"$STATE_FILE"
: >"$AUDIT_FILE"
: >"$VIOLATION_FILE"
trap finalize EXIT

record started_at str "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
record status str BLOCKED
record failure.code str HARNESS_INTERRUPTED
record failure.detail str preterminal-state
if [[ "$MODE" == "direct-port" ]]; then
  record result.profile str direct-docker-port-v1
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
docker_arch="$(docker info --format '{{.Architecture}}' 2>"$RAW/docker-info.log")" || block DOCKER_SERVER_UNAVAILABLE
record docker.client_version str "$docker_client"
record docker.server_version str "$docker_server"
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
  curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
    --output "$RUNTIME/$CLI_ASSET" "$CLI_URL" >"$RAW/cli-download.log" 2>&1 || block CLI_DOWNLOAD_FAILED
  actual_cli_sha="$(sha256sum "$RUNTIME/$CLI_ASSET" | awk '{print $1}')"
  record supabase_cli.version str "$CLI_VERSION"
  record supabase_cli.source_commit str "$CLI_COMMIT"
  record supabase_cli.asset_sha256 str "$actual_cli_sha"
  [[ "$actual_cli_sha" == "$CLI_SHA" ]] || block CLI_ASSET_DIGEST_MISMATCH
  mkdir -p "$RUNTIME/bin"
  tar -xzf "$RUNTIME/$CLI_ASSET" -C "$RUNTIME/bin" supabase >"$RAW/cli-extract.log" 2>&1 || block CLI_EXTRACTION_FAILED
  chmod 0555 "$RUNTIME/bin/supabase"
  reported_cli_version="$($RUNTIME/bin/supabase --version 2>"$RAW/cli-version.log")" || block CLI_VERSION_FAILED
  [[ "$reported_cli_version" == "$CLI_VERSION" ]] || block CLI_VERSION_MISMATCH
fi

docker pull --platform linux/amd64 "$POSTGRES_PULL" >"$RAW/postgres-pull.log" 2>&1 || block POSTGRES_PULL_FAILED
postgres_platform="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$POSTGRES_PULL")" || block POSTGRES_INSPECT_FAILED
[[ "$postgres_platform" == "linux/amd64" ]] || block IMAGE_PLATFORM_MISMATCH
docker image inspect --format '{{json .RepoDigests}}' "$POSTGRES_PULL" | grep -Fq "${POSTGRES_TAG%:*}@${POSTGRES_DIGEST}" || block POSTGRES_REPODIGEST_MISMATCH
POSTGRES_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$POSTGRES_PULL")"
record images.postgres.digest str "$POSTGRES_DIGEST"
record images.postgres.image_id str "$POSTGRES_IMAGE_ID"
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

NETWORK_ID="$(docker network create \
  --driver bridge \
  --internal \
  --ipv6=false \
  --subnet "$SUBNET" \
  --label "io.fawxzzy.packet=${PACKET}" \
  --label "io.fawxzzy.role=containment-network" \
  --label "com.supabase.cli.project=${PROJECT}" \
  --label "com.docker.compose.project=${PROJECT}" \
  --opt "com.docker.network.bridge.host_binding_ipv4=127.0.0.1" \
  --opt "com.docker.network.bridge.gateway_mode_ipv4=isolated" \
  "$NETWORK_NAME" 2>"$RAW/network-create.log")" || block NETWORK_CREATE_FAILED
[[ -n "$NETWORK_ID" ]] || block NETWORK_ID_EMPTY
record network.id_sha256 str "$(hash_identifier "$NETWORK_ID")"
record network.name str "$NETWORK_NAME"
record network.subnet str "$SUBNET"
record network.internal bool true
record network.ipv6 bool false
record network.host_binding_ipv4 str 127.0.0.1
record network.gateway_mode_ipv4 str isolated
ipam_gateway="$(docker network inspect --format '{{(index .IPAM.Config 0).Gateway}}' "$NETWORK_ID")"
record network.ipam_gateway str "${ipam_gateway:-none}"

[[ "$(docker network inspect --format '{{.Id}}' "$NETWORK_ID")" == "$NETWORK_ID" ]] || block NETWORK_ID_MISMATCH
[[ "$(docker network inspect --format '{{.Driver}}' "$NETWORK_ID")" == "bridge" ]] || block NETWORK_DRIVER_MISMATCH
[[ "$(docker network inspect --format '{{.Internal}}' "$NETWORK_ID")" == "true" ]] || block NETWORK_NOT_INTERNAL
[[ "$(docker network inspect --format '{{.EnableIPv6}}' "$NETWORK_ID")" == "false" ]] || block NETWORK_IPV6_ENABLED
[[ "$(docker network inspect --format '{{(index .IPAM.Config 0).Subnet}}' "$NETWORK_ID")" == "$SUBNET" ]] || block NETWORK_SUBNET_MISMATCH
[[ "$(docker network inspect --format '{{index .Options "com.docker.network.bridge.host_binding_ipv4"}}' "$NETWORK_ID")" == "127.0.0.1" ]] || block NETWORK_HOST_BINDING_MISMATCH
[[ "$(docker network inspect --format '{{index .Options "com.docker.network.bridge.gateway_mode_ipv4"}}' "$NETWORK_ID")" == "isolated" ]] || block NETWORK_GATEWAY_MODE_MISMATCH
[[ "$(docker network ls -q --filter "label=io.fawxzzy.packet=${PACKET}" | awk 'NF' | wc -l)" == "1" ]] || block PACKET_NETWORK_COUNT_MISMATCH
assert_frozen_network after_create empty
bridge_name="br-${NETWORK_ID:0:12}"
ip link show dev "$bridge_name" >"$RAW/bridge-link.log" 2>&1 || block PACKET_BRIDGE_MISSING
if ip -4 -o addr show dev "$bridge_name" | grep -q ' inet '; then
  block ISOLATED_BRIDGE_HAS_HOST_ADDRESS
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

cp "$ROOT/supabase/config.toml" "$PROJECT_DIR/supabase/config.toml"
[[ ! -e "$PROJECT_DIR/supabase/migrations" ]] || block APPLICATION_MIGRATIONS_PRESENT
[[ ! -e "$PROJECT_DIR/supabase/seed.sql" ]] || block SEED_FILE_PRESENT

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

set +e
timeout --signal=TERM --kill-after=10s 300s "$RUNTIME/bin/supabase" \
  --debug \
  --workdir "$PROJECT_DIR" \
  --network-id "$NETWORK_NAME" \
  --yes \
  db start >"$RAW/supabase-db-start.log" 2>&1
cli_rc="$?"
set -e
sleep 1
watcher_alive=0
kill -0 "$WATCH_PID" 2>/dev/null && watcher_alive=1
stop_watcher
if ! python3 -B "$ROOT/scripts/classify_db_start_log.py" \
  --input "$RAW/supabase-db-start.log" \
  --exit-code "$cli_rc" \
  --debug-enabled >"$DB_START_DIAGNOSTIC_FILE" 2>"$RAW/db-start-sanitizer.log"; then
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
if [[ "$cli_rc" != "0" ]]; then
  if [[ "$db_start_category" != "UNKNOWN_SANITIZED" ]]; then
    block "$db_start_category" "cli-exit-${cli_rc}"
  fi
  if [[ "$event_classification" == "NO_DOCKER_MUTATION_OBSERVED" ]]; then
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
