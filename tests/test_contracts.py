from __future__ import annotations

import asyncio
import importlib.util
import json
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections import deque
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def bash_executable() -> str:
    git = shutil.which("git")
    if git:
        bundled = Path(git).resolve().parent.parent / "bin" / (
            "bash.exe" if sys.platform == "win32" else "bash"
        )
        if bundled.is_file():
            return str(bundled)
    bash = shutil.which("bash")
    assert bash, "bash is required for listener contract tests"
    return bash


BASH = bash_executable()


def load_module(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


watch = load_module("container_watch", "scripts/container_watch.py")
subnets = load_module("check_subnet", "scripts/check_subnet.py")
db_start_log = load_module("classify_db_start_log", "scripts/classify_db_start_log.py")
docker_events = load_module("classify_docker_events", "scripts/classify_docker_events.py")
direct_port = load_module("direct_port_probe", "scripts/direct_port_probe.py")
docker_api_boundary = load_module(
    "docker_api_boundary", "scripts/docker_api_boundary.py"
)


class PinContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pins = json.loads((ROOT / "pins.json").read_text(encoding="utf-8"))

    def test_exact_supabase_pin(self) -> None:
        cli = self.pins["supabase_cli"]
        self.assertEqual(cli["version"], "2.109.1")
        self.assertEqual(cli["source_commit"], "6d4c19870ed213ba7f682f117d0345c8a40bfa94")
        self.assertEqual(cli["sha256"], "36d87b7fe6b4bcfe89ac47a4354e526cff22480224de426d7b370f6934556976")

    def test_exact_image_pins(self) -> None:
        images = self.pins["images"]
        self.assertEqual(images["postgres"]["tag"], "supabase/postgres:17.6.1.143")
        self.assertEqual(images["postgres"]["digest"], "sha256:b021e96054128399f84f24e39d29c21ee7c7169515e5d9e4e99ff15d5043d1d8")
        self.assertEqual(images["gotrue"]["tag"], "supabase/gotrue:v2.192.0")
        self.assertEqual(images["gotrue"]["digest"], "sha256:288d880ebc80a1cb5ad52dc7d12328f76e9c90127003306864a270118bba00a8")
        self.assertEqual(images["postgres"]["platform"], "linux/amd64")
        self.assertEqual(images["gotrue"]["platform"], "linux/amd64")


class WorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = (ROOT / ".github/workflows/containment-smoke.yml").read_text(encoding="utf-8")

    def test_manual_only_and_read_only(self) -> None:
        self.assertIn("workflow_dispatch:", self.workflow)
        self.assertNotRegex(self.workflow, r"(?m)^\s{2}(push|pull_request|schedule):")
        self.assertRegex(self.workflow, r"(?ms)^permissions:\s*\n\s{2}contents: read\s*$")
        self.assertNotIn("id-token:", self.workflow)
        self.assertNotIn("packages:", self.workflow)
        self.assertNotIn("secrets:", self.workflow)

    def test_runner_concurrency_timeout_and_retention(self) -> None:
        self.assertIn("group: fp-hosted-replay-ro-001", self.workflow)
        self.assertIn("cancel-in-progress: false", self.workflow)
        self.assertIn("runs-on: ubuntu-24.04", self.workflow)
        self.assertIn("timeout-minutes: 30", self.workflow)
        self.assertIn("retention-days: 7", self.workflow)

    def test_actions_are_exactly_pinned(self) -> None:
        self.assertIn("actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8", self.workflow)
        self.assertIn("actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02", self.workflow)
        self.assertIn("persist-credentials: false", self.workflow)
        uses = re.findall(r"(?m)^\s*uses:\s*(\S+)", self.workflow)
        self.assertEqual(len(uses), 2)

    def test_harness_gets_no_inherited_environment(self) -> None:
        self.assertEqual(self.workflow.count("env -i"), 2)
        self.assertNotRegex(self.workflow, r"(?m)^\s*env:\s*$")

    def test_cleanup_is_an_explicit_always_step(self) -> None:
        self.assertRegex(
            self.workflow,
            r"(?ms)- name: Cleanup exact packet resources\s+if: always\(\).*"
            r"run-containment-smoke\.sh cleanup-only\s+- name: Upload sanitized receipt",
        )

    def test_only_sanitized_result_is_uploaded(self) -> None:
        upload_paths = re.findall(r"(?m)^\s+path:\s*(\S+)$", self.workflow)
        self.assertEqual(upload_paths, ["artifacts/containment-smoke.json"])
        self.assertNotIn("supabase-db-start.log", self.workflow)

    def test_manual_workflow_selects_only_fixed_cli_containment_mode(self) -> None:
        self.assertIn("Hosted replay containment smoke", self.workflow)
        self.assertEqual(self.workflow.count("./scripts/run-containment-smoke.sh\n"), 1)
        self.assertNotIn("run-containment-smoke.sh direct-port", self.workflow)
        self.assertEqual(self.workflow.count("run-containment-smoke.sh cleanup-only"), 1)
        self.assertNotIn("RESULT_PROFILE=", self.workflow)


class SupabaseProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = (ROOT / "supabase/config.toml").read_text(encoding="utf-8")

    def test_database_only_profile(self) -> None:
        self.assertIn('project_id = "fp-hosted-replay-ro-001"', self.config)
        self.assertIn("port = 56422", self.config)
        self.assertIn("major_version = 17", self.config)
        for section in ("api", "realtime", "studio", "local_smtp", "storage", "edge_runtime", "analytics"):
            self.assertRegex(self.config, rf"(?ms)^\[{re.escape(section)}\]\s*\nenabled = false")
        self.assertRegex(self.config, r"(?ms)^\[db\.pooler\]\s*\nenabled = false")
        self.assertRegex(self.config, r"(?ms)^\[db\.migrations\]\s*\nenabled = false")
        self.assertRegex(self.config, r"(?ms)^\[db\.seed\]\s*\nenabled = false")
        self.assertRegex(self.config, r"(?ms)^\[auth\]\s*\nenabled = true")

    def test_no_secret_or_environment_references(self) -> None:
        self.assertNotIn("env(", self.config)
        self.assertNotRegex(self.config.lower(), r"(password|secret|token|api_key)\s*=")


class RunnerStaticContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = (ROOT / "scripts/run-containment-smoke.sh").read_text(encoding="utf-8")

    def test_legacy_direct_path_keeps_exact_pulls_but_loader_split_acquires_no_image(self) -> None:
        pulls = re.findall(r"(?m)^\s*docker pull --platform linux/amd64 ", self.runner)
        self.assertEqual(len(pulls), 2)
        self.assertNotRegex(self.runner, r"(?m)^\s*docker (build|compose pull|image pull)\b")
        root_init = self.runner.index("run_loadconfig_services_split\n  exit 1")
        first_pull = self.runner.index('docker pull --platform linux/amd64 "$POSTGRES_PULL"')
        self.assertLess(root_init, first_pull)

    def test_direct_mode_isolated_from_cli_and_uses_one_exact_target(self) -> None:
        self.assertIn('run|direct-port|cleanup-only', self.runner)
        self.assertRegex(self.runner, r'(?s)if \[\[ "\$MODE" == "direct-port" \]\]; then\s+run_direct_port_probe\s+exit 0\s+fi')
        direct_function = self.runner[
            self.runner.index("run_direct_port_probe() {") : self.runner.index(
                "packet_object_counts() {"
            )
        ]
        self.assertEqual(direct_function.count("docker run -d"), 1)
        self.assertIn("--pull=never", direct_function)
        self.assertIn("--platform linux/amd64", direct_function)
        self.assertIn('--network "$NETWORK_ID"', direct_function)
        self.assertIn('--publish "${DB_PORT}:5432"', direct_function)
        self.assertNotIn("0.0.0.0:", direct_function)
        self.assertNotIn(":::", direct_function)
        self.assertNotIn("$RUNTIME/bin/supabase", direct_function)
        self.assertNotIn("db start", direct_function)

    def test_direct_credential_is_masked_before_env_only_use(self) -> None:
        mask = "printf '::add-mask::%s\\n' \"$db_password\""
        export = 'export POSTGRES_PASSWORD="$db_password"'
        env_only = "--env POSTGRES_PASSWORD"
        self.assertIn(mask, self.runner)
        self.assertIn(export, self.runner)
        self.assertIn(env_only, self.runner)
        self.assertLess(self.runner.index(mask), self.runner.index(export))
        self.assertLess(self.runner.index(export), self.runner.index(env_only))
        self.assertNotRegex(self.runner, r"record\s+\S+\s+\S+\s+\"?\$db_password")

    def test_contract_tests_do_not_leave_bytecode(self) -> None:
        self.assertIn('python3 -B -m unittest discover', self.runner)

    def test_legacy_network_contract_is_preserved_but_not_reached_by_loader_split(self) -> None:
        for fragment in (
            "--internal",
            "--ipv6=false",
            'com.docker.network.bridge.host_binding_ipv4=127.0.0.1',
            'com.docker.network.bridge.gateway_mode_ipv4=isolated',
            '--network-id "$NETWORK_NAME"',
        ):
            self.assertIn(fragment, self.runner)
        self.assertEqual(self.runner.count('--network-id "$NETWORK_NAME"'), 2)
        self.assertIn("record network.ipam_gateway", self.runner)
        self.assertIn("16) block PACKET_GATEWAY_REACHABLE", self.runner)
        self.assertIn("assert_frozen_network after_create empty", self.runner)
        self.assertIn("assert_frozen_network pre_cli empty", self.runner)
        self.assertIn("assert_frozen_network pre_cli_start empty", self.runner)
        self.assertIn("assert_frozen_network post_cli active", self.runner)
        self.assertIn("record network.pre_cleanup_exact_id bool true", self.runner)
        self.assertIn("SECOND_PACKET_NETWORK_DETECTED", self.runner)
        self.assertLess(
            self.runner.index('run_loadconfig_services_split\n  exit 1'),
            self.runner.index('docker pull --platform linux/amd64 "$POSTGRES_PULL"'),
        )

    def test_root_init_split_requires_zero_packet_objects_and_listener_drift(self) -> None:
        for fragment in (
            'packet_object_counts pre_cli',
            'packet_object_counts post_cli',
            'block ROOT_INIT_PREEXISTING_OBJECT',
            'block ROOT_INIT_DOCKER_OBJECT_DRIFT',
            'block ROOT_INIT_LISTENER_DRIFT',
            'native_listener_contract post_cli',
            'native_listener_contract cleanup',
        ):
            self.assertIn(fragment, self.runner)

    def test_loader_split_has_exact_closed_terminal_classes(self) -> None:
        classes = (
            "CONFIG_LOAD_PASS_UNDER_CLEAN_ENV",
            "CONFIG_ENV_TRAVERSAL_FAILED",
            "CONFIG_FILE_READ_FAILED",
            "CONFIG_FILE_MERGE_FAILED",
            "CONFIG_DECODE_FAILED",
            "CONFIG_VALIDATION_PROJECT_FAILED",
            "CONFIG_VALIDATION_DB_FAILED",
            "CONFIG_VALIDATION_AUTH_FAILED",
            "CONFIG_KEY_GENERATION_FAILED",
            "CONFIG_UNKNOWN_SANITIZED",
            "UNEXPECTED_DOCKER_OR_PROVIDER_BOUNDARY",
        )
        for value in classes:
            self.assertIn(value, self.runner)
        self.assertIn('record diagnostic.classification str "$loader_classification"', self.runner)
    def test_pre_cleanup_network_failure_cannot_be_overwritten_by_pass(self) -> None:
        self.assertIn("network_contract_ok=1", self.runner)
        self.assertIn("network_contract_ok=0", self.runner)
        self.assertIn('"$network_contract_ok" == "1"', self.runner)

    def test_finalize_preserves_the_first_explicit_failure_code(self) -> None:
        self.assertIn("current_failure_code()", self.runner)
        self.assertIn('record network.pre_cleanup_failure_code str "$network_code"', self.runner)
        self.assertIn("record cleanup.failure_code str CLEANUP_RESIDUE", self.runner)
        self.assertGreaterEqual(
            self.runner.count(
                '[[ -z "$primary_failure" || "$primary_failure" == "HARNESS_INTERRUPTED" ]]'
            ),
            2,
        )

    def test_loader_output_is_sanitized_classified_and_deleted(self) -> None:
        self.assertIn("umask 077", self.runner)
        command = 'services\n  ) >"$RAW/supabase-services.stdout" 2>"$RAW/supabase-services.stderr"'
        self.assertEqual(self.runner.count(command), 1)
        raw_delete = 'rm -f -- "$RAW/supabase-services.stdout" "$RAW/supabase-services.stderr"'
        self.assertIn(raw_delete, self.runner)
        self.assertIn("supabase_cli.loadconfig.raw_deleted", self.runner)
        self.assertIn("supabase_cli.loadconfig.stdout_raw_byte_count", self.runner)
        self.assertIn("supabase_cli.loadconfig.stdout_raw_line_count", self.runner)
        self.assertIn("supabase_cli.loadconfig.stdout_raw_sha256", self.runner)
        self.assertIn("supabase_cli.loadconfig.stderr_raw_byte_count", self.runner)
        self.assertIn("supabase_cli.loadconfig.stderr_raw_line_count", self.runner)
        self.assertIn("supabase_cli.loadconfig.stderr_raw_sha256", self.runner)
        self.assertLess(self.runner.index(command), self.runner.index(raw_delete))
        self.assertNotIn('cat "$RAW/supabase-services.stdout"', self.runner)
        self.assertNotIn('cat "$RAW/supabase-services.stderr"', self.runner)

    def test_docker_api_observer_is_scoped_to_the_cli_child(self) -> None:
        child_env = 'DOCKER_HOST="unix://$DOCKER_API_SOCKET" \\'
        self.assertGreaterEqual(self.runner.count(child_env), 1)
        self.assertNotIn("export DOCKER_HOST", self.runner)
        root_init = self.runner.index("run_loadconfig_services_split() {")
        root_init_end = self.runner.index("\n}\n\nif [[ \"$MODE\" == \"cleanup-only\" ]]", root_init)
        root_init_source = self.runner[root_init:root_init_end]
        observer_start = root_init_source.index(
            'python3 -B "$ROOT/scripts/docker_api_boundary.py"'
        )
        cli_start = root_init_source.index(
            'services\n  ) >"$RAW/supabase-services.stdout"'
        )
        observer_stop = root_init_source.index("stop_docker_api_observer", cli_start)
        self.assertLess(observer_start, cli_start)
        self.assertLess(cli_start, observer_stop)
        self.assertIn(
            '[[ "$(stat -c \'%a\' "$DOCKER_API_SOCKET")" == "600" ]]',
            self.runner,
        )
        self.assertIn(
            '[[ "$(stat -c \'%a\' "$DOCKER_API_READY")" == "600" ]]',
            self.runner,
        )

    def test_docker_api_observer_state_is_sanitized_and_transient(self) -> None:
        self.assertIn("DOCKER_API_OBSERVER_STATE_MISSING", self.runner)
        self.assertIn("DOCKER_API_OBSERVER_FAILED", self.runner)
        self.assertIn("DOCKER_API_RESPONSE_INCOMPLETE", self.runner)
        self.assertIn("DOCKER_API_WRITE_ATTEMPT_OBSERVED", self.runner)
        self.assertIn("OBSERVER_FORWARDING_FAILED", self.runner)
        self.assertNotIn('cat "$RAW/docker-api-observer.log"', self.runner)
        self.assertIn('cat "$DOCKER_API_BOUNDARY_STATE_FILE" >>"$STATE_FILE"', self.runner)
        self.assertIn('rm -rf -- "$RUNTIME"', self.runner)

    def test_precli_object_listener_and_event_history_boundaries(self) -> None:
        freeze = "freeze_precli_objects_and_listeners"
        boundary = 'EVENT_SINCE="$(date -u +%s)"'
        cli_start = 'services\n  ) >"$RAW/supabase-services.stdout"'
        self.assertIn(freeze, self.runner)
        self.assertIn('"$LISTENER_QUERY_BIN" -H -ltn "sport = :${port}"', self.runner)
        self.assertIn("pre_cli.packet_db_container_count", self.runner)
        self.assertIn("pre_cli.packet_db_volume_count", self.runner)
        self.assertIn("pre_cli.db_listener_count", self.runner)
        self.assertIn("native_listener_contract post_cli", self.runner)
        self.assertIn("native_listener_contract cleanup", self.runner)
        self.assertLess(self.runner.index(freeze), self.runner.index(boundary))
        self.assertLess(self.runner.index(boundary), self.runner.index(cli_start))

    def test_listener_capture_is_sequential_and_fail_closed(self) -> None:
        ordered = (
            "COMMAND_PRECHECK_BEGIN",
            "COMMAND_PRECHECK_COMPLETE",
            "QUERY_BEGIN",
            "QUERY_COMPLETE",
            "NORMALIZATION_BEGIN",
            "NORMALIZATION_COMPLETE",
            "COUNT_BEGIN",
            "COUNT_COMPLETE",
            "HASH_BEGIN",
            "HASH_COMPLETE",
            "RECEIPT_BEGIN",
            "RECEIPT_COMPLETE",
        )
        positions = [self.runner.index(value) for value in ordered]
        self.assertEqual(positions, sorted(positions))
        for code in (
            "LISTENER_COMMAND_UNAVAILABLE",
            "LISTENER_QUERY_NONZERO",
            "LISTENER_NORMALIZATION_FAILED",
            "LISTENER_COUNT_FAILED",
            "LISTENER_HASH_FAILED",
            "LISTENER_RECEIPT_WRITE_FAILED",
            "LISTENER_UNEXPECTED_INTERRUPTION",
        ):
            self.assertIn(code, self.runner)
        self.assertIn("listener_phase_is_unexpected", self.runner)
        self.assertIn("listener_diagnostic.unexpected_interruption_phase", self.runner)
        self.assertNotRegex(
            self.runner,
            r'local stage="\$1" port="\$2" snapshot=',
        )

    def test_loader_scratch_is_fully_redirected_allowlisted_and_deleted(self) -> None:
        for variable in (
            "HOME",
            "XDG_CONFIG_HOME",
            "XDG_CACHE_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "TMPDIR",
        ):
            self.assertRegex(self.runner, rf'(?m)^\s+{variable}="\$ROOT_INIT_[A-Z_]+" \\$')
        self.assertIn("DO_NOT_TRACK=1", self.runner)
        loader_start = self.runner.index("run_loadconfig_services_split() {")
        loader_end = self.runner.index('\n}\n\nif [[ "$MODE" == "cleanup-only" ]]', loader_start)
        loader = self.runner[loader_start:loader_end]
        self.assertNotIn("SUPABASE_HOME=", loader)
        self.assertNotIn("SUPABASE_TELEMETRY_DISABLED=", loader)
        self.assertNotIn("CI=", loader)
        self.assertIn("CLI_UPDATE_CACHE", self.runner)
        self.assertIn("TELEMETRY_STATE", self.runner)
        self.assertIn("PROJECT_CONFIG", self.runner)
        self.assertIn('*) block ROOT_INIT_STATE_ESCAPE "unexpected-scratch-class"', self.runner)
        self.assertIn("loader.scratch.class_digest_sha256", self.runner)
        self.assertIn("loader.scratch.deleted bool true", self.runner)
        self.assertRegex(
            self.runner,
            r'(?s)case "\$ROOT_INIT_DIR" in\s+"\$RUNTIME"/root-init\) rm -rf -- "\$ROOT_INIT_DIR"',
        )

    def test_event_classification_routes_fail_closed(self) -> None:
        for code in (
            "OBSERVER_COVERAGE_GAP",
            "CONTAINER_CREATE_FAILED",
            "CONTAINER_CREATED_NOT_STARTED",
            "DATABASE_HEALTH_FAILED",
            "GOTRUE_MIGRATION_FAILED",
            "EVENT_HISTORY_IMAGE_IDENTITY_FAILED",
            "EVENT_HISTORY_NETWORK_CORRELATION_FAILED",
        ):
            self.assertIn(code, self.runner)

    def test_exact_loader_source_contract_and_binary_hash(self) -> None:
        self.assertIn('CLI_COMMIT="6d4c19870ed213ba7f682f117d0345c8a40bfa94"', self.runner)
        self.assertIn(
            'CLI_BINARY_SHA="e9c1c33233b4341a0475f9acb2ecac35c41f6c9aa6cfdcd4f54b3761cc789c20"',
            self.runner,
        )
        self.assertIn('[[ "$actual_cli_binary_sha" == "$CLI_BINARY_SHA" ]]', self.runner)
        self.assertIn("record source_contract.command str supabase-services", self.runner)
        self.assertIn("record source_contract.root_persistent_prerun bool true", self.runner)
        self.assertIn("record source_contract.load_config bool true", self.runner)
        self.assertIn("record source_contract.docker_access_expected bool false", self.runner)
        self.assertIn("record source_contract.provider_access_enabled bool false", self.runner)
        self.assertEqual(
            self.runner.count('services\n  ) >"$RAW/supabase-services.stdout"'), 1
        )

    def test_loader_execution_path_is_exact_and_prohibits_mutating_or_remote_commands(self) -> None:
        start = self.runner.index("run_loadconfig_services_split() {")
        end = self.runner.index("\n}\n\nif [[ \"$MODE\" == \"cleanup-only\" ]]", start)
        root_init = self.runner[start:end]
        exact = (
            '"$RUNTIME/bin/supabase" \\\n'
            '      --workdir "$ROOT_INIT_WORKDIR" \\\n'
            '      --network-id "$NETWORK_NAME" \\\n'
            '      --output json \\\n'
            '      services'
        )
        self.assertIn(exact, root_init)
        self.assertEqual(root_init.count("\n      services\n"), 1)
        prohibited = (
            r"\bstatus\s+--ignore-health-check\b",
            r"\b(login|link|pull|push|dump)\b",
            r"\bdb\s+(start|reset)\b",
            r"--linked\b",
            r"--db-url\b",
            r"docker\s+(pull|run|create|start|stop|rm|tag)\b",
            r"docker\s+(system|container|volume|network|image)\s+prune",
        )
        for pattern in prohibited:
            self.assertNotRegex(root_init, pattern)
        workflow_entry = self.runner[
            self.runner.index('if [[ "$MODE" == "run" ]]') : self.runner.index(
                'docker pull --platform linux/amd64 "$POSTGRES_PULL"'
            )
        ]
        self.assertIn("run_loadconfig_services_split", workflow_entry)
        self.assertIn("exit 1", workflow_entry)

    def test_loader_preflight_proves_config_and_provider_state_absence(self) -> None:
        self.assertIn(
            'CONFIG_SHA="1b955c23161259dd41f3849f261bab41525b5ffeca83ab3074e44c5cc18ac0c6"',
            self.runner,
        )
        for fragment in (
            "loader.config.public_sha256",
            "loader.config.readable",
            "loader.config.lf_only",
            "loader.config.env_file_count",
            "loader.provider.linked_state_absent",
            "loader.provider.access_token_absent",
            "loader.provider.inherited_supabase_environment",
            "loader.application.migrations_absent",
            "loader.application.seed_absent",
        ):
            self.assertIn(fragment, self.runner)
        self.assertIn("env -i", self.runner)

    def test_cleanup_is_exactly_correlated(self) -> None:
        self.assertIn('label=com.supabase.cli.project=${PROJECT}', self.runner)
        self.assertIn('label=io.fawxzzy.packet=${PACKET}', self.runner)
        self.assertNotIn("docker rm -f $(docker ps", self.runner)
        self.assertNotIn("supabase stop", self.runner)
        self.assertIn('if [[ "$MODE" == "cleanup-only" ]]', self.runner)
        self.assertIn('20s docker rm -f "$id"', self.runner)
        self.assertIn('20s docker volume rm "$id"', self.runner)
        self.assertIn('20s docker network rm "$id"', self.runner)
        self.assertGreaterEqual(self.runner.count('label=io.fawxzzy.packet=${DIRECT_PACKET}'), 4)
        self.assertIn('[[ "$listener_count" == "0" ]] || return 1', self.runner)
        self.assertRegex(
            self.runner,
            r'(?s)elif \[\[ ! -f "\$RESULT_FILE" \]\]; then\s+if \[\[ "\$RESULT_PROFILE" == "direct-docker-port-v1" \]\]; then\s+record result.profile str direct-docker-port-v1',
        )


class LoadConfigClassifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        runner = (ROOT / "scripts/run-containment-smoke.sh").read_text(encoding="utf-8")
        start = runner.index("# BEGIN LOADCONFIG_CLASSIFIER_FUNCTION")
        end = runner.index("# END LOADCONFIG_CLASSIFIER_FUNCTION")
        cls.function = runner[start:end].split("\n", 1)[1]

    def classify(
        self,
        stderr: str,
        *,
        exit_code: int = 1,
        schema_valid: bool = False,
        secret_shape: bool = False,
    ) -> str:
        script = f"""
set -Eeuo pipefail
{self.function}
classify_loadconfig_result "$1" "$2" "$3" "$4"
"""
        with tempfile.TemporaryDirectory() as directory:
            error_file = Path(directory) / "stderr"
            error_file.write_text(stderr, encoding="utf-8")
            result = subprocess.run(
                [
                    BASH,
                    "-c",
                    script,
                    "bash",
                    str(exit_code),
                    str(error_file),
                    str(schema_valid).lower(),
                    str(secret_shape).lower(),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            return result.stdout.strip()

    def test_every_source_class_has_a_narrow_fixture(self) -> None:
        fixtures = (
            ("failed to get repo directory", "CONFIG_ENV_TRAVERSAL_FAILED"),
            ("failed to read file config", "CONFIG_FILE_READ_FAILED"),
            ("failed to merge file config", "CONFIG_FILE_MERGE_FAILED"),
            ("failed to parse config", "CONFIG_DECODE_FAILED"),
            ("Missing required field in config: project_id", "CONFIG_VALIDATION_PROJECT_FAILED"),
            ("Missing required field in config: db.port", "CONFIG_VALIDATION_DB_FAILED"),
            ("Missing required field in config: auth.site_url", "CONFIG_VALIDATION_AUTH_FAILED"),
            ("failed to generate JWT", "CONFIG_KEY_GENERATION_FAILED"),
        )
        for stderr, expected in fixtures:
            with self.subTest(expected=expected):
                self.assertEqual(self.classify(stderr), expected)

    def test_pass_unknown_and_secret_shape_are_closed(self) -> None:
        self.assertEqual(
            self.classify("", exit_code=0, schema_valid=True),
            "CONFIG_LOAD_PASS_UNDER_CLEAN_ENV",
        )
        self.assertEqual(self.classify("opaque failure"), "CONFIG_UNKNOWN_SANITIZED")
        self.assertEqual(
            self.classify("failed to read file config", secret_shape=True),
            "CONFIG_UNKNOWN_SANITIZED",
        )

    def test_classifier_never_emits_raw_input(self) -> None:
        marker = "opaque synthetic marker"
        observed = self.classify(marker)
        self.assertNotIn(marker, observed)
        self.assertRegex(observed, r"^[A-Z0-9_]+$")


class ListenerDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        runner = (ROOT / "scripts/run-containment-smoke.sh").read_text(encoding="utf-8")
        start = runner.index("# BEGIN LISTENER_DIAGNOSTIC_FUNCTIONS")
        end = runner.index("# END LISTENER_DIAGNOSTIC_FUNCTIONS")
        cls.functions = runner[start:end].split("\n", 1)[1]

    def run_capture(
        self,
        query_body: str = "exit 0\n",
        *,
        overrides: dict[str, str] | None = None,
        record_fail_key: str = "",
    ) -> tuple[dict[str, str], str]:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            raw = temp / "raw"
            raw.mkdir()
            state = temp / "state.tsv"
            query = temp / "listener-query"
            query.write_text("#!/usr/bin/env bash\n" + query_body, encoding="utf-8", newline="\n")
            query.chmod(0o755)
            commands = {
                "LISTENER_QUERY_BIN": query.as_posix(),
                "LISTENER_NORMALIZE_BIN": "awk",
                "LISTENER_SORT_BIN": "sort",
                "LISTENER_COUNT_BIN": "awk",
                "LISTENER_HASH_BIN": "sha256sum",
            }
            commands.update(overrides or {})
            assignments = "\n".join(
                f"{key}={shlex.quote(value)}" for key, value in commands.items()
            )
            script = f"""
set -u
RAW={shlex.quote(raw.as_posix())}
STATE_FILE={shlex.quote(state.as_posix())}
RECORD_FAIL_KEY={shlex.quote(record_fail_key)}
LISTENER_FAILURE_CODE=
LISTENER_LAST_PHASE=
LISTENER_SNAPSHOT_COUNT=
LISTENER_SNAPSHOT_SHA256=
{assignments}
record() {{
  local key kind value
  key="$1"
  kind="$2"
  value="$3"
  if [[ -n "$RECORD_FAIL_KEY" && "$key" == "$RECORD_FAIL_KEY" ]]; then
    return 97
  fi
  printf '%s\\t%s\\t%s\\n' "$key" "$kind" "$value" >>"$STATE_FILE"
}}
{self.functions}
capture_listener_snapshot pre_cli 56422
capture_rc="$?"
printf 'capture_rc=%s\\n' "$capture_rc"
printf 'failure_code=%s\\n' "$LISTENER_FAILURE_CODE"
printf 'last_phase=%s\\n' "$LISTENER_LAST_PHASE"
printf 'count=%s\\n' "$LISTENER_SNAPSHOT_COUNT"
printf 'sha256=%s\\n' "$LISTENER_SNAPSHOT_SHA256"
"""
            completed = subprocess.run(
                [BASH, "-c", script],
                check=True,
                capture_output=True,
                text=True,
            )
            observed = dict(line.split("=", 1) for line in completed.stdout.splitlines())
            return observed, state.read_text(encoding="utf-8") if state.exists() else ""

    def test_empty_and_nonempty_snapshots_emit_only_count_and_digest(self) -> None:
        empty, empty_state = self.run_capture()
        self.assertEqual(empty["capture_rc"], "0")
        self.assertEqual(empty["count"], "0")
        self.assertRegex(empty["sha256"], r"^[0-9a-f]{64}$")
        self.assertIn("PRE_CLI_PORT_56422_RECEIPT_COMPLETE", empty_state)

        nonempty, state = self.run_capture(
            "printf '%s\\n' "
            "'LISTEN 0 4096 fixture-a:5432 peer-a:*' "
            "'LISTEN 0 4096 fixture-a:5432 peer-a:*' "
            "'LISTEN 0 4096 fixture-b:5432 peer-b:*'\n"
        )
        self.assertEqual(nonempty["capture_rc"], "0")
        self.assertEqual(nonempty["count"], "2")
        self.assertRegex(nonempty["sha256"], r"^[0-9a-f]{64}$")
        for raw_tuple in ("fixture-a", "fixture-b", "peer-a", "peer-b"):
            self.assertNotIn(raw_tuple, state)

    def test_each_operation_failure_has_a_stable_code_and_phase(self) -> None:
        cases = (
            (
                "command",
                {"LISTENER_QUERY_BIN": "listener-command-does-not-exist"},
                "",
                "LISTENER_COMMAND_UNAVAILABLE",
                "COMMAND_UNAVAILABLE",
            ),
            (
                "query",
                None,
                "exit 7\n",
                "LISTENER_QUERY_NONZERO",
                "QUERY_FAILED",
            ),
            (
                "normalization",
                {"LISTENER_NORMALIZE_BIN": "false"},
                "",
                "LISTENER_NORMALIZATION_FAILED",
                "NORMALIZATION_FAILED",
            ),
            (
                "count",
                {"LISTENER_COUNT_BIN": "false"},
                "",
                "LISTENER_COUNT_FAILED",
                "COUNT_FAILED",
            ),
            (
                "hash",
                {"LISTENER_HASH_BIN": "false"},
                "",
                "LISTENER_HASH_FAILED",
                "HASH_FAILED",
            ),
        )
        for name, overrides, query_body, failure_code, phase_suffix in cases:
            with self.subTest(name=name):
                observed, state = self.run_capture(query_body, overrides=overrides)
                self.assertEqual(observed["capture_rc"], "1")
                self.assertEqual(observed["failure_code"], failure_code)
                self.assertTrue(observed["last_phase"].endswith(phase_suffix))
                self.assertNotRegex(state, r"fixture-[ab]|peer-[ab]")

    def test_receipt_failure_is_distinct(self) -> None:
        observed, _ = self.run_capture(
            record_fail_key="listener_diagnostic.pre_cli.port_56422.normalized_count"
        )
        self.assertEqual(observed["capture_rc"], "1")
        self.assertEqual(observed["failure_code"], "LISTENER_RECEIPT_WRITE_FAILED")
        self.assertEqual(observed["last_phase"], "PRE_CLI_PORT_56422_RECEIPT_BEGIN")

    def test_unexpected_interruption_phase_predicate_is_bounded(self) -> None:
        script = f"""
set -u
record() {{ :; }}
LISTENER_FAILURE_CODE=
LISTENER_LAST_PHASE=
{self.functions}
for phase in PRE_CLI_BOUNDARY_BEGIN PRE_CLI_PORT_56422_QUERY_BEGIN PRE_CLI_PORT_5433_HASH_COMPLETE PRE_CLI_PREFLIGHT_COMPLETE POST_CLI_PORT_5432_QUERY_BEGIN; do
  if listener_phase_is_unexpected "$phase"; then
    printf '%s=true\\n' "$phase"
  else
    printf '%s=false\\n' "$phase"
  fi
done
"""
        completed = subprocess.run(
            [BASH, "-c", script], check=True, capture_output=True, text=True
        )
        observed = dict(line.split("=", 1) for line in completed.stdout.splitlines())
        self.assertEqual(observed["PRE_CLI_BOUNDARY_BEGIN"], "true")
        self.assertEqual(observed["PRE_CLI_PORT_56422_QUERY_BEGIN"], "true")
        self.assertEqual(observed["PRE_CLI_PORT_5433_HASH_COMPLETE"], "true")
        self.assertEqual(observed["PRE_CLI_PREFLIGHT_COMPLETE"], "false")
        self.assertEqual(observed["POST_CLI_PORT_5432_QUERY_BEGIN"], "false")


class ResultWriterTests(unittest.TestCase):
    def test_cli_result_preserves_lifecycle_counts_and_only_hashed_object_ids(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            state = temp / "state.tsv"
            audit = temp / "audit.jsonl"
            output = temp / "result.json"
            state.write_text(
                "status\tstr\tBLOCKED\n"
                "failure.code\tstr\tCONTAINER_CREATED_NOT_STARTED\n"
                "failure.detail\tstr\tgate-rejected\n"
                "container_lifecycle.database.create_count\tint\t1\n"
                "container_lifecycle.database.start_count\tint\t0\n"
                "container_lifecycle.network_id_correlated\tbool\ttrue\n",
                encoding="utf-8",
            )
            audit.write_text(
                json.dumps(
                    {
                        "phase": "create",
                        "role": "database",
                        "container_id": "sha256:" + "a" * 64,
                        "image_id": "sha256:" + "b" * 64,
                        "command": [],
                        "network_ids": ["sha256:" + "c" * 64],
                        "published_db_binding": None,
                        "compliant": True,
                        "violations": [],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "scripts/write_result.py"),
                    "--root",
                    str(ROOT),
                    "--state",
                    str(state),
                    "--audit",
                    str(audit),
                    "--output",
                    str(output),
                ],
                check=True,
            )
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result["container_lifecycle"]["database"]["create_count"], 1)
            self.assertEqual(result["container_lifecycle"]["database"]["start_count"], 0)
            observed = result["container_audit"]["containers"][0]
            self.assertRegex(observed["container_id"], r"^sha256:[0-9a-f]{64}$")
            self.assertRegex(observed["network_ids"][0], r"^sha256:[0-9a-f]{64}$")
            self.assertNotIn("phase", observed)
            self.assertEqual(observed["command"], [])

    def test_direct_result_is_strictly_allowlisted_and_cleanup_merge_preserves_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            state = temp / "state.tsv"
            audit = temp / "audit.jsonl"
            output = temp / "result.json"
            state.write_text(
                "result.profile\tstr\tdirect-docker-port-v1\n"
                "status\tstr\tDIRECT_DOCKER_PORT_PATH_PASS\n"
                "failure.code\tstr\tSHOULD_BE_REMOVED\n"
                "diagnostic.binding.class\tstr\tloopback-ipv4-only\n"
                "runner.kernel\tstr\tMUST_NOT_LEAK\n"
                "images.postgres.image_id\tstr\tMUST_NOT_LEAK\n",
                encoding="utf-8",
            )
            audit.write_text('{"container_id":"MUST_NOT_LEAK"}\n', encoding="utf-8")
            subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "scripts/write_result.py"),
                    "--root",
                    str(ROOT),
                    "--state",
                    str(state),
                    "--audit",
                    str(audit),
                    "--output",
                    str(output),
                ],
                check=True,
            )
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                set(result), {"schema", "packet", "status", "failure", "diagnostic", "cleanup"}
            )
            self.assertEqual(result["status"], "DIRECT_DOCKER_PORT_PATH_PASS")
            self.assertIsNone(result["failure"])
            self.assertEqual(result["diagnostic"]["binding"]["class"], "loopback-ipv4-only")
            self.assertNotIn("MUST_NOT_LEAK", output.read_text(encoding="utf-8"))

            state.write_text("cleanup.containers_remaining\tint\t0\n", encoding="utf-8")
            subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "scripts/write_result.py"),
                    "--root",
                    str(ROOT),
                    "--state",
                    str(state),
                    "--audit",
                    str(audit),
                    "--output",
                    str(output),
                    "--merge-existing",
                ],
                check=True,
            )
            merged = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(merged["status"], "DIRECT_DOCKER_PORT_PATH_PASS")
            self.assertEqual(merged["cleanup"]["containers_remaining"], 0)
            self.assertNotIn("container_audit", merged)

    def test_cleanup_merge_preserves_existing_sanitized_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            state = temp / "state.tsv"
            audit = temp / "audit.jsonl"
            output = temp / "result.json"
            state.write_text("cleanup.containers_remaining\tint\t0\n", encoding="utf-8")
            audit.write_text("", encoding="utf-8")
            output.write_text(
                json.dumps({"status": "BLOCKED", "failure": {"code": "ORIGINAL"}}),
                encoding="utf-8",
            )
            subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "scripts/write_result.py"),
                    "--root",
                    str(ROOT),
                    "--state",
                    str(state),
                    "--audit",
                    str(audit),
                    "--output",
                    str(output),
                    "--merge-existing",
                ],
                check=True,
            )
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result["failure"]["code"], "ORIGINAL")
            self.assertEqual(result["cleanup"]["containers_remaining"], 0)

    def test_diagnostic_state_is_nested_without_raw_text(self) -> None:
        raw = b"opaque diagnostic fixture\n"
        diagnostic = db_start_log.classify(raw, 1)
        state_text = db_start_log.format_state_lines(diagnostic)
        self.assertNotIn("opaque diagnostic fixture", state_text)
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            state = temp / "state.tsv"
            audit = temp / "audit.jsonl"
            output = temp / "result.json"
            state.write_text(
                "status\tstr\tBLOCKED\n"
                "failure.code\tstr\tSUPABASE_DB_START_FAILED\n"
                "failure.detail\tstr\tcli-exit-1\n"
                + state_text,
                encoding="utf-8",
            )
            audit.write_text("", encoding="utf-8")
            subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "scripts/write_result.py"),
                    "--root",
                    str(ROOT),
                    "--state",
                    str(state),
                    "--audit",
                    str(audit),
                    "--output",
                    str(output),
                ],
                check=True,
            )
            result = json.loads(output.read_text(encoding="utf-8"))
            observed = result["supabase_cli"]["db_start_diagnostic"]
            self.assertEqual(observed, diagnostic)
            self.assertNotIn("opaque diagnostic fixture", output.read_text(encoding="utf-8"))

    def test_loader_profile_replaces_root_init_source_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            state = temp / "state.tsv"
            audit = temp / "audit.jsonl"
            output = temp / "result.json"
            state.write_text(
                "result.profile\tstr\tloadconfig-services-v1\n"
                "diagnostic.profile\tstr\tloadconfig-services-v1\n"
                "source_contract.command\tstr\tsupabase-services\n"
                "source_contract.root_persistent_prerun\tbool\ttrue\n"
                "source_contract.load_config\tbool\ttrue\n"
                "source_contract.docker_access_expected\tbool\tfalse\n"
                "source_contract.provider_access_enabled\tbool\tfalse\n"
                "source_contract.telemetry_endpoint_enabled\tbool\tfalse\n"
                "source_contract.database_only\tbool\tfalse\n"
                "source_contract.application_migrations_enabled\tbool\tfalse\n"
                "source_contract.seed_enabled\tbool\tfalse\n"
                "source_contract.gotrue_enabled\tbool\tfalse\n",
                encoding="utf-8",
            )
            audit.write_text("", encoding="utf-8")
            subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "scripts/write_result.py"),
                    "--root",
                    str(ROOT),
                    "--state",
                    str(state),
                    "--audit",
                    str(audit),
                    "--output",
                    str(output),
                ],
                check=True,
            )
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertNotIn("result", result)
            self.assertEqual(
                result["diagnostic"]["profile"], "loadconfig-services-v1"
            )
            self.assertEqual(
                result["source_contract"]["command"],
                "supabase-services",
            )
            self.assertTrue(result["source_contract"]["root_persistent_prerun"])
            self.assertTrue(result["source_contract"]["load_config"])
            self.assertFalse(result["source_contract"]["gotrue_enabled"])
            self.assertNotEqual(
                result["source_contract"]["command"], "supabase db start"
            )


class DockerApiBoundaryTests(unittest.TestCase):
    class FakeReader:
        def __init__(self, chunks: list[bytes]) -> None:
            self.chunks = deque(chunks)

        async def read(self, _size: int) -> bytes:
            await asyncio.sleep(0)
            return self.chunks.popleft() if self.chunks else b""

    class FakeWriter:
        def __init__(self) -> None:
            self.data = bytearray()
            self.eof = False
            self.closed = False

        def write(self, data: bytes) -> None:
            self.data.extend(data)

        async def drain(self) -> None:
            await asyncio.sleep(0)

        def write_eof(self) -> None:
            self.eof = True

        def close(self) -> None:
            self.closed = True

        async def wait_closed(self) -> None:
            await asyncio.sleep(0)

    def test_zero_requests_has_stable_closed_receipt(self) -> None:
        first = docker_api_boundary.Receipt().sanitized()
        second = docker_api_boundary.Receipt().sanitized()
        self.assertEqual(first, second)
        self.assertEqual(first["classification"], "NO_DOCKER_API_REQUEST_OBSERVED")
        self.assertRegex(first["canonical_sha256"], r"^[0-9a-f]{64}$")
        rendered = docker_api_boundary.format_state_lines(first)
        self.assertNotIn("/var/run", rendered)
        self.assertNotIn("DOCKER_HOST", rendered)

    def test_fixed_path_templates_and_version_normalization(self) -> None:
        cases = {
            (b"GET", b"/v1.47/_ping"): "API_NEGOTIATION",
            (b"GET", b"/version"): "API_NEGOTIATION",
            (b"GET", b"/v1.47/images/pinned@sha256:opaque/json"): "IMAGE_INSPECT",
            (b"GET", b"/networks/opaque?verbose=true"): "NETWORK_INSPECT_REUSE",
            (b"GET", b"/v1.47/volumes/opaque"): "VOLUME_INSPECT",
            (b"POST", b"/v1.47/volumes/create"): "VOLUME_CREATE",
            (b"POST", b"/containers/create?name=opaque"): "CONTAINER_CREATE",
            (b"GET", b"/v1.47/not-allowlisted/opaque?token=secret"): "UNKNOWN_API_PHASE",
        }
        for (method, target), expected in cases.items():
            with self.subTest(target=target):
                self.assertEqual(
                    docker_api_boundary.classify_path(method, target), expected
                )
        self.assertEqual(
            docker_api_boundary.normalize_path(b"/v1.47/_ping?opaque=value"),
            b"/_ping",
        )

    def test_partial_chunked_and_keepalive_framing(self) -> None:
        receipt = docker_api_boundary.Receipt()
        pending: deque[tuple[str, bytes]] = deque()
        requests = docker_api_boundary.RequestParser(receipt, pending)
        responses = docker_api_boundary.ResponseParser(receipt, pending)
        request_bytes = (
            b"GET /v1.47/containers/json HTTP/1.1\r\n\r\n"
            b"HEAD /v1.47/_ping HTTP/1.1\r\n\r\n"
        )
        response_bytes = (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"2\r\n[]\r\n0\r\n\r\n"
            b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n"
        )
        for offset in range(0, len(request_bytes), 3):
            requests.feed(request_bytes[offset : offset + 3])
        for offset in range(0, len(response_bytes), 5):
            responses.feed(response_bytes[offset : offset + 5])
        result = receipt.sanitized()
        self.assertEqual(result["request_count"], 2)
        self.assertEqual(result["response_count"], 2)
        self.assertEqual(result["phase_counts"]["CONTAINER_LIST"], 1)
        self.assertEqual(result["phase_counts"]["API_NEGOTIATION"], 1)
        self.assertEqual(result["status_code_counts"]["CODE_200"], 2)
        self.assertEqual(result["write_attempt_count"], 0)
        self.assertEqual(result["classification"], "DOCKER_API_REQUESTS_OBSERVED")

    def test_read_error_response_records_only_allowlisted_status(self) -> None:
        receipt = docker_api_boundary.Receipt()
        receipt.request("CONTAINER_LIST", "READ")
        receipt.response("CONTAINER_LIST", 500)
        result = receipt.sanitized()
        self.assertEqual(result["classification"], "DOCKER_API_ERROR_RESPONSE_OBSERVED")
        self.assertEqual(result["first_error_phase"], "CONTAINER_LIST")
        self.assertEqual(result["first_error_status_code"], 500)
        self.assertEqual(result["status_code_counts"]["CODE_500"], 1)

    def test_sensitive_input_is_never_retained(self) -> None:
        receipt = docker_api_boundary.Receipt()
        pending: deque[tuple[str, bytes]] = deque()
        parser = docker_api_boundary.RequestParser(receipt, pending)
        sensitive = (
            b"GET /v1.47/containers/json?token=do-not-retain HTTP/1.1\r\n"
            b"Authorization: Bearer fake.jwt.value\r\n"
            b"Content-Length: 32\r\n\r\n"
            b'{"password":"do-not-retain-now"}'
        )
        parser.feed(sensitive)
        rendered = docker_api_boundary.format_state_lines(receipt.sanitized())
        for forbidden in (
            "do-not-retain",
            "Authorization",
            "Bearer",
            "password",
            "containers/create",
            "token=",
            "fake.jwt.value",
        ):
            self.assertNotIn(forbidden, rendered)

    def test_every_non_read_method_is_rejected(self) -> None:
        cases = {
            b"POST": "WRITE",
            b"PUT": "WRITE",
            b"PATCH": "WRITE",
            b"DELETE": "DELETE",
            b"OPTIONS": "OTHER",
        }
        for method, method_kind in cases.items():
            with self.subTest(method=method):
                receipt = docker_api_boundary.Receipt()
                parser = docker_api_boundary.RequestParser(receipt, deque())
                with self.assertRaises(docker_api_boundary.WriteAttemptError):
                    parser.feed(
                        method + b" /v1.47/containers/json HTTP/1.1\r\n\r\n"
                    )
                result = receipt.sanitized()
                self.assertEqual(
                    result["classification"],
                    "DOCKER_API_WRITE_ATTEMPT_OBSERVED",
                )
                self.assertEqual(result["write_attempt_count"], 1)
                self.assertEqual(result["method_class_counts"][method_kind], 1)

    def test_write_attempt_is_not_forwarded(self) -> None:
        async def exercise() -> tuple[bytes, object]:
            receipt = docker_api_boundary.Receipt()
            server = docker_api_boundary.BoundaryServer(
                Path("packet.sock"), Path("docker.sock"), receipt
            )
            writer = self.FakeWriter()
            parser = docker_api_boundary.RequestParser(receipt, deque())
            await server.relay(
                self.FakeReader(
                    [b"POST /v1.47/containers/create HTTP/1.1\r\n\r\n"]
                ),
                writer,
                parser,
            )
            return bytes(writer.data), receipt.sanitized()

        forwarded, result = asyncio.run(exercise())
        self.assertEqual(forwarded, b"")
        self.assertEqual(result["write_attempt_count"], 1)
        self.assertEqual(
            result["classification"], "DOCKER_API_WRITE_ATTEMPT_OBSERVED"
        )

    def test_schema_rejects_unknown_keys_types_and_values(self) -> None:
        valid = docker_api_boundary.Receipt().sanitized()
        unknown = dict(valid)
        unknown["raw_path"] = "/containers/secret"
        with self.assertRaises(ValueError):
            docker_api_boundary.validate_result(unknown)
        bad_type = dict(valid)
        bad_type["request_count"] = "0"
        with self.assertRaises(ValueError):
            docker_api_boundary.validate_result(bad_type)
        bad_phase = dict(valid)
        bad_phase["first_phase"] = "RAW_PATH"
        with self.assertRaises(ValueError):
            docker_api_boundary.validate_result(bad_phase)
        bad_digest = dict(valid)
        bad_digest["canonical_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            docker_api_boundary.validate_result(bad_digest)

    def test_relay_is_byte_exact_for_concurrent_connections(self) -> None:
        async def exercise() -> tuple[bytes, bytes, object]:
            receipt = docker_api_boundary.Receipt()
            server = docker_api_boundary.BoundaryServer(
                Path("packet.sock"), Path("docker.sock"), receipt
            )
            payload_a = b"GET /_ping HTTP/1.1\r\n\r\n"
            payload_b = b"GET /v1.47/networks/opaque HTTP/1.1\r\n\r\n"
            writer_a = self.FakeWriter()
            writer_b = self.FakeWriter()
            pending_a: deque[tuple[str, bytes]] = deque()
            pending_b: deque[tuple[str, bytes]] = deque()
            receipt.connect()
            receipt.connect()
            await asyncio.gather(
                server.relay(
                    self.FakeReader([payload_a[:7], payload_a[7:]]),
                    writer_a,
                    docker_api_boundary.RequestParser(receipt, pending_a),
                ),
                server.relay(
                    self.FakeReader([payload_b[:11], payload_b[11:]]),
                    writer_b,
                    docker_api_boundary.RequestParser(receipt, pending_b),
                ),
            )
            return bytes(writer_a.data), bytes(writer_b.data), receipt.sanitized()

        forwarded_a, forwarded_b, result = asyncio.run(exercise())
        self.assertEqual(forwarded_a, b"GET /_ping HTTP/1.1\r\n\r\n")
        self.assertEqual(
            forwarded_b, b"GET /v1.47/networks/opaque HTTP/1.1\r\n\r\n"
        )
        self.assertEqual(result["connection_count"], 2)
        self.assertEqual(result["request_count"], 2)

    def test_upstream_failure_is_fail_closed(self) -> None:
        async def exercise() -> object:
            receipt = docker_api_boundary.Receipt()
            server = docker_api_boundary.BoundaryServer(
                Path("packet.sock"), Path("missing.sock"), receipt
            )
            client_writer = self.FakeWriter()
            with mock.patch.object(
                docker_api_boundary.asyncio,
                "open_unix_connection",
                side_effect=OSError("unavailable"),
                create=True,
            ):
                await server.handle(self.FakeReader([]), client_writer)
            self.assertTrue(client_writer.closed)
            return receipt.sanitized()

        result = asyncio.run(exercise())
        self.assertEqual(result["classification"], "OBSERVER_FORWARDING_FAILED")
        self.assertEqual(result["forwarding_error_count"], 1)

    def test_incomplete_response_is_fail_closed(self) -> None:
        receipt = docker_api_boundary.Receipt()
        receipt.request("VOLUME_INSPECT", "READ")
        self.assertEqual(
            receipt.sanitized()["classification"],
            "DOCKER_API_RESPONSE_INCOMPLETE",
        )


class DbStartLogClassifierTests(unittest.TestCase):
    def test_every_admitted_category_has_a_synthetic_fixture(self) -> None:
        fixtures = {
            "CONFIG_VALIDATION_FAILED": b"failed to validate config\n",
            "CLI_USAGE_ERROR": b"unknown flag: --not-real\n",
            "DOCKER_CLIENT_API_NEGOTIATION_FAILED": b"failed to initialize Docker client\n",
            "IMAGE_RESOLUTION_FAILED": b"manifest unknown\n",
            "NETWORK_REUSE_ATTACHMENT_REJECTED": b"failed to create docker network\n",
            "NETWORK_CONFIGURATION_REJECTED": b"network pool is invalid\n",
            "VOLUME_CREATE_REJECTED": b"failed to create volume\n",
            "VOLUME_PREPARATION_FAILED": b"failed to parse docker volume\n",
            "CONTAINER_CREATE_REJECTED": b"failed to create docker container\n",
            "CONTAINER_CREATE_FAILED": b"failed to create the container\n",
            "CONTAINER_START_FAILED": b"failed to start docker container\n",
            "PORT_BIND_FAILED": b"port is already allocated\n",
            "DATABASE_HEALTH_FAILED": b"database is not healthy\n",
            "GOTRUE_MIGRATION_FAILED": b"gotrue migrate failed\n",
            "DOCKER_DAEMON_ERROR": b"cannot connect to the Docker daemon\n",
            "UNKNOWN_SANITIZED": b"unrecognized opaque failure\n",
        }
        self.assertEqual(set(fixtures), set(db_start_log.ALLOWED_CATEGORIES))
        for expected, raw in fixtures.items():
            with self.subTest(category=expected):
                result = db_start_log.classify(raw, 1)
                self.assertEqual(result["category"], expected)
                self.assertEqual(result["exit_code"], 1)
                self.assertEqual(result["raw_byte_count"], len(raw))
                self.assertEqual(result["raw_line_count"], 1)
                self.assertRegex(result["raw_sha256"], r"^[0-9a-f]{64}$")
                expected_keys = {
                    "category",
                    "exit_code",
                    "match_count",
                    "raw_byte_count",
                    "raw_line_count",
                    "raw_sha256",
                    "debug_enabled",
                    "sensitive_shape_detected",
                    "sensitive_shape_count",
                }
                if expected != "UNKNOWN_SANITIZED":
                    expected_keys.add("first_match_line")
                    self.assertEqual(result["first_match_line"], 1)
                    self.assertEqual(result["match_count"], 1)
                else:
                    self.assertEqual(result["match_count"], 0)
                self.assertFalse(result["debug_enabled"])
                self.assertFalse(result["sensitive_shape_detected"])
                self.assertEqual(result["sensitive_shape_count"], 0)
                self.assertEqual(set(result), expected_keys)

    def test_specific_network_rule_precedes_generic_daemon_rule(self) -> None:
        raw = b"Error response from daemon: failed to create docker network\n"
        self.assertEqual(
            db_start_log.classify(raw, 1)["category"],
            "NETWORK_REUSE_ATTACHMENT_REJECTED",
        )

    def test_empty_log_defaults_without_leaking_input(self) -> None:
        result = db_start_log.classify(b"", 7)
        self.assertEqual(result["category"], "UNKNOWN_SANITIZED")
        self.assertEqual(result["match_count"], 0)
        self.assertEqual(result["raw_byte_count"], 0)
        self.assertEqual(result["raw_line_count"], 0)
        rendered = db_start_log.format_state_lines(result)
        self.assertEqual(len(rendered.splitlines()), 9)

    def test_exact_cli_source_wrappers_and_match_location(self) -> None:
        fixtures = {
            b"failed to create Docker CLI: fixture\n": "DOCKER_CLIENT_API_NEGOTIATION_FAILED",
            b"failed to initialize Docker CLI: fixture\n": "DOCKER_CLIENT_API_NEGOTIATION_FAILED",
            b"failed to inspect docker image: fixture\n": "IMAGE_RESOLUTION_FAILED",
            b"failed to pull docker image from all registries: fixture\n": "IMAGE_RESOLUTION_FAILED",
            b"failed to create docker network: fixture\n": "NETWORK_REUSE_ATTACHMENT_REJECTED",
            b"failed to parse docker volume: fixture\n": "VOLUME_PREPARATION_FAILED",
            b"failed to create volume: fixture\n": "VOLUME_CREATE_REJECTED",
            b"failed to create docker container: fixture\n": "CONTAINER_CREATE_REJECTED",
            b"failed to start docker container fixture: fixture\n": "CONTAINER_START_FAILED",
        }
        for raw, expected in fixtures.items():
            with self.subTest(expected=expected):
                result = db_start_log.classify(b"prefix\n" + raw + raw, 1)
                self.assertEqual(result["category"], expected)
                self.assertEqual(result["match_count"], 2)
                self.assertEqual(result["first_match_line"], 2)

    def test_mixed_input_uses_narrow_deterministic_priority(self) -> None:
        raw = (
            b"failed to create docker container: lower-priority\n"
            b"failed to create volume: higher-priority\n"
            b"failed to inspect docker image: highest-priority\n"
        )
        result = db_start_log.classify(raw, 1, debug_enabled=True)
        self.assertEqual(result["category"], "IMAGE_RESOLUTION_FAILED")
        self.assertEqual(result["match_count"], 1)
        self.assertEqual(result["first_match_line"], 3)
        self.assertTrue(result["debug_enabled"])

    def test_secret_shaped_input_is_counted_but_never_emitted(self) -> None:
        secrets = (
            "postgresql://worker:opaque-password@database.invalid/postgres\n"
            "Authorization: Bearer opaque-token-value\n"
            "JWT_SECRET=opaque-secret-value\n"
            "-----BEGIN PRIVATE KEY-----\n"
        ).encode()
        result = db_start_log.classify(secrets, 1, debug_enabled=True)
        rendered = db_start_log.format_state_lines(result)
        self.assertTrue(result["sensitive_shape_detected"])
        self.assertEqual(result["sensitive_shape_count"], 4)
        for forbidden in (
            "opaque-password",
            "opaque-token-value",
            "opaque-secret-value",
            "database.invalid",
            "PRIVATE KEY",
        ):
            self.assertNotIn(forbidden, rendered)
        with self.assertRaises(ValueError):
            db_start_log.validate_state_lines(
                rendered + "unclassified.raw\tstr\topaque\n",
                has_first_match=False,
            )

    def test_prior_unknown_fingerprint_schema_remains_compatible(self) -> None:
        prior = {
            "category": "UNKNOWN_SANITIZED",
            "exit_code": 1,
            "match_count": 0,
            "raw_byte_count": 1078,
            "raw_line_count": 23,
            "raw_sha256": "d3a19bac055dc3fad0bca48c92d3cbe3d1d59ec9ac43d90829b5dd0c41545d31",
            "debug_enabled": False,
            "sensitive_shape_detected": False,
            "sensitive_shape_count": 0,
        }
        rendered = db_start_log.format_state_lines(prior)
        self.assertIn(prior["raw_sha256"], rendered)
        self.assertIn("UNKNOWN_SANITIZED", rendered)
        self.assertNotIn("OTHER_PRECONTAINER_FAILURE", rendered)

    def test_executable_path_emits_only_sanitized_state(self) -> None:
        raw = b"failed to create docker network opaque-fixture-text\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "db-start.log"
            path.write_bytes(raw)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "scripts/classify_db_start_log.py"),
                    "--input",
                    str(path),
                    "--exit-code",
                    "1",
                    "--debug-enabled",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        self.assertEqual(len(completed.stdout.splitlines()), 10)
        self.assertIn("NETWORK_REUSE_ATTACHMENT_REJECTED", completed.stdout)
        self.assertIn("debug_enabled\tbool\ttrue", completed.stdout)
        self.assertNotIn("opaque-fixture-text", completed.stdout)
        self.assertEqual(completed.stderr, "")


def docker_event_line(event_type: str, action: str, object_id: str, **attributes: str) -> bytes:
    return (
        json.dumps(
            {
                "Type": event_type,
                "Action": action,
                "Actor": {"ID": object_id, "Attributes": attributes},
            },
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


class DockerEventHistoryClassifierTests(unittest.TestCase):
    project = "fp-hosted-replay-ro-001"
    network_name = "fp-hosted-replay-ro-001-net"
    network_id = "a" * 64
    volume = "supabase_db_fp-hosted-replay-ro-001"
    postgres_image = "public.ecr.aws/supabase/postgres:17.6.1.143"
    postgres_image_id = "sha256:postgres"
    gotrue_image = "public.ecr.aws/supabase/gotrue:v2.192.0"
    gotrue_image_id = "sha256:gotrue"
    database_id = "b" * 64
    gotrue_id = "c" * 64

    def container(self, action: str, object_id: str, image: str, **attributes: str) -> bytes:
        return docker_event_line(
            "container",
            action,
            object_id,
            **{
                "com.supabase.cli.project": self.project,
                "image": image,
                **attributes,
            },
        )

    def volume_event(self, action: str = "create") -> bytes:
        return docker_event_line(
            "volume",
            action,
            self.volume,
            **{"com.supabase.cli.project": self.project},
        )

    def network(self, action: str, container_id: str, network_id: str | None = None) -> bytes:
        return docker_event_line(
            "network",
            action,
            network_id or self.network_id,
            name=self.network_name,
            container=container_id,
        )

    def live(self, *observations: tuple[str, str]) -> bytes:
        return b"".join(
            json.dumps(
                {
                    "phase": phase,
                    "container_id": docker_events.identity_digest(container_id),
                },
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
            for phase, container_id in observations
        )

    def analyze(
        self,
        container_raw: bytes = b"",
        volume_raw: bytes = b"",
        network_raw: bytes = b"",
        live_raw: bytes = b"",
    ) -> dict:
        return docker_events.analyze(
            container_raw,
            volume_raw,
            network_raw,
            live_raw,
            project=self.project,
            network_name=self.network_name,
            network_id=self.network_id,
            db_volume=self.volume,
            postgres_image=self.postgres_image,
            postgres_image_id=self.postgres_image_id,
            gotrue_image=self.gotrue_image,
            gotrue_image_id=self.gotrue_image_id,
        )

    def database_create_start(self) -> tuple[bytes, bytes, bytes]:
        containers = self.container("create", self.database_id, self.postgres_image)
        containers += self.container("start", self.database_id, self.postgres_image)
        network = self.network("connect", self.database_id)
        live = self.live(("create", self.database_id), ("start", self.database_id))
        return containers, network, live

    def test_every_event_classification_has_a_deterministic_fixture(self) -> None:
        containers, network, live = self.database_create_start()
        fixtures = {
            "NO_DOCKER_MUTATION_OBSERVED": self.analyze(),
            "EVENT_HISTORY_CONSISTENT": self.analyze(
                containers, self.volume_event(), network, live
            ),
            "OBSERVER_COVERAGE_GAP": self.analyze(
                containers, self.volume_event(), network, b""
            ),
            "CONTAINER_CREATE_FAILED": self.analyze(
                b"", self.volume_event(), b"", b""
            ),
            "CONTAINER_CREATED_NOT_STARTED": self.analyze(
                self.container("create", self.database_id, self.postgres_image),
                self.volume_event(),
                self.network("connect", self.database_id),
                self.live(("create", self.database_id)),
            ),
            "DATABASE_HEALTH_FAILED": self.analyze(
                containers
                + self.container(
                    "die", self.database_id, self.postgres_image, exitCode="1"
                ),
                self.volume_event(),
                network,
                live,
            ),
            "GOTRUE_MIGRATION_FAILED": self.analyze(
                containers
                + self.container("create", self.gotrue_id, self.gotrue_image)
                + self.container("start", self.gotrue_id, self.gotrue_image)
                + self.container("die", self.gotrue_id, self.gotrue_image, exitCode="1"),
                self.volume_event(),
                network + self.network("connect", self.gotrue_id),
                live
                + self.live(("create", self.gotrue_id), ("start", self.gotrue_id)),
            ),
        }
        self.assertEqual(set(fixtures), docker_events.ALLOWED_CLASSIFICATIONS)
        for expected, result in fixtures.items():
            with self.subTest(expected=expected):
                self.assertEqual(result["classification"], expected)

    def test_action_counts_and_correlations_are_sanitized(self) -> None:
        containers, network, live = self.database_create_start()
        result = self.analyze(containers, self.volume_event(), network, live)
        self.assertEqual(result["container_create_count"], 1)
        self.assertEqual(result["container_start_count"], 1)
        self.assertEqual(result["volume_create_count"], 1)
        self.assertEqual(result["network_connect_count"], 1)
        self.assertTrue(result["pinned_image_identity_correlated"])
        self.assertTrue(result["frozen_network_id_correlated"])
        self.assertTrue(result["live_observer_correlated"])
        rendered = docker_events.format_state_lines(result)
        for raw_value in (
            self.database_id,
            self.volume,
            self.project,
            self.network_name,
            self.postgres_image,
        ):
            self.assertNotIn(raw_value, rendered)
        self.assertRegex(result["container_id_set_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(result["raw_sha256"], r"^[0-9a-f]{64}$")

    def test_identity_or_network_drift_is_not_accepted(self) -> None:
        unknown_image = self.container("create", self.database_id, "foreign:image")
        image_result = self.analyze(
            unknown_image,
            self.volume_event(),
            self.network("connect", self.database_id),
            self.live(("create", self.database_id)),
        )
        self.assertFalse(image_result["pinned_image_identity_correlated"])

        containers, _, live = self.database_create_start()
        network_result = self.analyze(
            containers,
            self.volume_event(),
            self.network("connect", self.database_id, network_id="d" * 64),
            live,
        )
        self.assertFalse(network_result["frozen_network_id_correlated"])

    def test_wrong_project_label_or_raw_event_is_rejected(self) -> None:
        wrong_label = docker_event_line(
            "container",
            "create",
            self.database_id,
            **{"com.supabase.cli.project": "foreign", "image": self.postgres_image},
        )
        with self.assertRaises(docker_events.EventHistoryError):
            self.analyze(wrong_label)
        with self.assertRaises(docker_events.EventHistoryError):
            self.analyze(b"raw opaque event\n")


def base_inspection() -> dict:
    network_id = "a" * 64
    return {
        "id": "b" * 64,
        "name": "/supabase_db_fp-hosted-replay-ro-001",
        "image_id": "sha256:postgres",
        "config_image": "public.ecr.aws/supabase/postgres:17.6.1.143",
        "cmd": [],
        "labels": {
            "com.supabase.cli.project": "fp-hosted-replay-ro-001",
            "com.docker.compose.project": "fp-hosted-replay-ro-001",
        },
        "network_mode": "fp-hosted-replay-ro-001-net",
        "privileged": False,
        "pid_mode": "",
        "ipc_mode": "private",
        "binds": ["supabase_db_fp-hosted-replay-ro-001:/var/lib/postgresql/data"],
        "devices": [],
        "device_requests": [],
        "cap_add": [],
        "security_opt": [],
        "extra_hosts": ["host.docker.internal:host-gateway"],
        "port_bindings": {"5432/tcp": [{"HostIp": "", "HostPort": "56422"}]},
        "restart_policy": {"Name": "unless-stopped"},
        "mounts": [
            {
                "Type": "volume",
                "Name": "supabase_db_fp-hosted-replay-ro-001",
                "Source": "/var/lib/docker/volumes/bounded/_data",
                "Destination": "/var/lib/postgresql/data",
                "RW": True,
            }
        ],
        "networks": {"packet": {"NetworkID": network_id}},
        "published_ports": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "56422"}]},
    }


class ContainerAuditTests(unittest.TestCase):
    def test_accepts_exact_database(self) -> None:
        data = base_inspection()
        role, violations = watch.classify_and_validate(
            data,
            "start",
            "fp-hosted-replay-ro-001-net",
            "a" * 64,
            "sha256:postgres",
            "sha256:gotrue",
        )
        self.assertEqual(role, "database")
        self.assertEqual(violations, [])

    def test_create_phase_does_not_require_runtime_port_publication(self) -> None:
        data = base_inspection()
        data["published_ports"] = {}
        role, violations = watch.classify_and_validate(
            data,
            "create",
            "fp-hosted-replay-ro-001-net",
            "a" * 64,
            "sha256:postgres",
            "sha256:gotrue",
        )
        self.assertEqual(role, "database")
        self.assertEqual(violations, [])

    def test_accepts_exact_one_shot_gotrue(self) -> None:
        data = base_inspection()
        data.update(
            name="/random-job",
            image_id="sha256:gotrue",
            cmd=["gotrue", "migrate"],
            binds=[],
            mounts=[],
            port_bindings={},
            published_ports={},
            restart_policy={"Name": "no"},
        )
        role, violations = watch.classify_and_validate(
            data,
            "start",
            "fp-hosted-replay-ro-001-net",
            "a" * 64,
            "sha256:postgres",
            "sha256:gotrue",
        )
        self.assertEqual(role, "gotrue_migration")
        self.assertEqual(violations, [])

    def test_rejects_privilege_network_capability_and_socket(self) -> None:
        data = base_inspection()
        data["privileged"] = True
        data["network_mode"] = "bridge"
        data["cap_add"] = ["NET_ADMIN"]
        data["binds"] = ["/var/run/docker.sock:/var/run/docker.sock"]
        _, violations = watch.classify_and_validate(
            data,
            "start",
            "fp-hosted-replay-ro-001-net",
            "a" * 64,
            "sha256:postgres",
            "sha256:gotrue",
        )
        self.assertIn("PRIVILEGED_MODE_REJECTED", violations)
        self.assertIn("NETWORK_ATTACHMENT_MISMATCH", violations)
        self.assertIn("ADDED_CAPABILITY_REJECTED", violations)
        self.assertIn("DOCKER_SOCKET_REJECTED", violations)

    def test_rejects_second_network_even_when_expected_network_is_present(self) -> None:
        data = base_inspection()
        data["networks"]["foreign"] = {"NetworkID": "c" * 64}
        _, violations = watch.classify_and_validate(
            data,
            "start",
            "fp-hosted-replay-ro-001-net",
            "a" * 64,
            "sha256:postgres",
            "sha256:gotrue",
        )
        self.assertIn("NETWORK_ATTACHMENT_MISMATCH", violations)

    def test_observer_hashes_object_ids_and_never_inspects_environment(self) -> None:
        self.assertRegex(watch.identity_digest("opaque"), r"^sha256:[0-9a-f]{64}$")
        self.assertNotIn("Config.Env", watch.INSPECT_TEMPLATE)
        source = (ROOT / "scripts/container_watch.py").read_text(encoding="utf-8")
        self.assertIn('"event=create"', source)
        self.assertIn('"event=start"', source)
        self.assertNotIn('str(data.get("id", ""))[:12]', source)


def network_inspection() -> dict:
    return {
        "id": "a" * 64,
        "name": "fp-hosted-replay-ro-001-net",
        "driver": "bridge",
        "scope": "local",
        "internal": True,
        "enable_ipv6": False,
        "subnet": "172.31.253.0/24",
        "options": {
            "com.docker.network.bridge.host_binding_ipv4": "127.0.0.1",
            "com.docker.network.bridge.gateway_mode_ipv4": "isolated",
        },
        "labels": {
            "io.fawxzzy.packet": "FP-HOSTED-REPLAY-CONTAINMENT-SMOKE-001",
            "io.fawxzzy.role": "containment-network",
            "com.supabase.cli.project": "fp-hosted-replay-ro-001",
            "com.docker.compose.project": "fp-hosted-replay-ro-001",
        },
    }


class NetworkIdentityContractTests(unittest.TestCase):
    def validate(
        self,
        data: dict,
        resolved_ids: list[str] | None = None,
        correlated_ids: list[str] | None = None,
    ) -> list[str]:
        return watch.validate_network_contract(
            data,
            resolved_ids if resolved_ids is not None else ["a" * 64],
            correlated_ids if correlated_ids is not None else ["a" * 64],
            "fp-hosted-replay-ro-001-net",
            "a" * 64,
            "172.31.253.0/24",
            "FP-HOSTED-REPLAY-CONTAINMENT-SMOKE-001",
        )

    def test_unique_name_resolves_to_frozen_engine_id(self) -> None:
        self.assertEqual(self.validate(network_inspection()), [])

    def test_rejects_name_to_id_drift(self) -> None:
        violations = self.validate(network_inspection(), resolved_ids=["c" * 64])
        self.assertIn("NETWORK_NAME_ID_MAPPING_FAILED", violations)
        data = network_inspection()
        data["id"] = "c" * 64
        self.assertIn("NETWORK_NAME_ID_MAPPING_FAILED", self.validate(data))

    def test_rejects_second_packet_or_project_network(self) -> None:
        violations = self.validate(
            network_inspection(), correlated_ids=["a" * 64, "c" * 64]
        )
        self.assertIn("SECOND_PACKET_NETWORK_DETECTED", violations)

    def test_rejects_any_network_contract_option_or_label_drift(self) -> None:
        mutations = (
            ("internal", False, "NETWORK_NOT_INTERNAL"),
            ("enable_ipv6", True, "NETWORK_IPV6_ENABLED"),
            ("subnet", "172.31.252.0/24", "NETWORK_SUBNET_MISMATCH"),
        )
        for key, value, expected in mutations:
            with self.subTest(key=key):
                data = network_inspection()
                data[key] = value
                self.assertIn(expected, self.validate(data))
        data = network_inspection()
        data["options"]["com.docker.network.bridge.gateway_mode_ipv4"] = "nat"
        self.assertIn("NETWORK_GATEWAY_MODE_MISMATCH", self.validate(data))
        data = network_inspection()
        data["labels"]["io.fawxzzy.packet"] = "foreign"
        self.assertIn("NETWORK_LABEL_MISMATCH", self.validate(data))


def direct_inspection() -> dict:
    network_id = "a" * 64
    return {
        "schema_version": 1,
        "id": "b" * 64,
        "name": "/fp-hosted-replay-ro-001-direct-postgres",
        "image_id": "sha256:postgres",
        "config_image": "supabase/postgres@sha256:pinned",
        "labels": {
            "io.fawxzzy.packet": "FP-HOSTED-REPLAY-DIRECT-PORT-DIAG-001",
            "io.fawxzzy.role": "direct-postgres",
            "com.supabase.cli.project": "fp-hosted-replay-ro-001",
            "com.docker.compose.project": "fp-hosted-replay-ro-001",
        },
        "network_mode": network_id,
        "privileged": False,
        "pid_mode": "",
        "ipc_mode": "private",
        "binds": [],
        "tmpfs": {
            "/var/lib/postgresql/data": "rw,nosuid,nodev,noexec,size=1073741824"
        },
        "devices": [],
        "device_requests": [],
        "cap_add": [],
        "security_opt": [],
        "extra_hosts": [],
        "port_bindings": {"5432/tcp": [{"HostIp": "", "HostPort": "56422"}]},
        "restart_policy": {"Name": "no", "MaximumRetryCount": 0},
        "mounts": [
            {
                "Type": "tmpfs",
                "Source": "",
                "Destination": "/var/lib/postgresql/data",
                "RW": True,
            }
        ],
        "networks": {"packet": {"NetworkID": network_id}},
        "published_ports": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "56422"}]},
        "restart_count": 0,
        "state": {
            "Status": "running",
            "Running": True,
            "Restarting": False,
            "OOMKilled": False,
        },
        "health": {"Status": "healthy", "FailingStreak": 0},
    }


class DirectPortProbeTests(unittest.TestCase):
    def validate(self, data: dict) -> list[str]:
        return direct_port.validate_inspection(
            data,
            "a" * 64,
            "sha256:postgres",
            "supabase/postgres@sha256:pinned",
        )

    def test_accepts_only_exact_loopback_direct_container(self) -> None:
        self.assertEqual(self.validate(direct_inspection()), [])
        self.assertRegex(direct_port.identity_digest("opaque"), r"^sha256:[0-9a-f]{64}$")
        self.assertNotIn("Config.Env", direct_port.INSPECT_TEMPLATE)
        self.assertNotIn("__ENV__", direct_port.INSPECT_TEMPLATE)

    def test_unknown_or_corrupt_inspection_schema_fails_closed(self) -> None:
        self.assertEqual(self.validate({}), ["DIRECT_INSPECTION_SCHEMA_INVALID"])
        data = direct_inspection()
        data["schema_version"] = 2
        self.assertEqual(self.validate(data), ["DIRECT_INSPECTION_SCHEMA_INVALID"])
        data = direct_inspection()
        data["mounts"] = ["corrupt"]
        data["restart_policy"] = "corrupt"
        violations = self.validate(data)
        self.assertIn("DIRECT_MOUNT_CONTRACT_MISMATCH", violations)
        self.assertIn("DIRECT_RESTART_POLICY_MISMATCH", violations)

    def test_rejects_privilege_namespaces_devices_capabilities_and_socket(self) -> None:
        data = direct_inspection()
        data.update(privileged=True, pid_mode="host", ipc_mode="host")
        data["devices"] = [{"PathOnHost": "/dev/kvm"}]
        data["cap_add"] = ["NET_ADMIN"]
        data["binds"] = ["/var/run/docker.sock:/var/run/docker.sock"]
        violations = self.validate(data)
        self.assertIn("DIRECT_PRIVILEGED_MODE_REJECTED", violations)
        self.assertIn("DIRECT_PID_MODE_REJECTED", violations)
        self.assertIn("DIRECT_IPC_MODE_REJECTED", violations)
        self.assertIn("DIRECT_DEVICE_ACCESS_REJECTED", violations)
        self.assertIn("DIRECT_ADDED_CAPABILITY_REJECTED", violations)
        self.assertIn("DIRECT_BIND_MOUNT_REJECTED", violations)

    def test_rejects_extra_network_or_any_nonloopback_or_second_binding(self) -> None:
        for binding in (
            [{"HostIp": "0.0.0.0", "HostPort": "56422"}],
            [{"HostIp": "::", "HostPort": "56422"}],
            [
                {"HostIp": "127.0.0.1", "HostPort": "56422"},
                {"HostIp": "0.0.0.0", "HostPort": "56422"},
            ],
        ):
            with self.subTest(binding=binding):
                data = direct_inspection()
                data["published_ports"]["5432/tcp"] = binding
                self.assertIn("DIRECT_PORT_BINDING_MISMATCH", self.validate(data))
        data = direct_inspection()
        data["networks"]["extra"] = {"NetworkID": "c" * 64}
        self.assertIn("DIRECT_NETWORK_ATTACHMENT_MISMATCH", self.validate(data))

    def test_rejects_explicit_host_ip_request_health_restart_oom_and_extra_mount(self) -> None:
        data = direct_inspection()
        data["port_bindings"]["5432/tcp"][0]["HostIp"] = "127.0.0.1"
        data["health"] = {"Status": "unhealthy", "FailingStreak": 3}
        data["restart_count"] = 1
        data["state"]["OOMKilled"] = True
        data["mounts"].append(
            {"Type": "bind", "Source": "/tmp", "Destination": "/extra", "RW": True}
        )
        violations = self.validate(data)
        self.assertIn("DIRECT_PORT_REQUEST_MISMATCH", violations)
        self.assertIn("DIRECT_CONTAINER_NOT_HEALTHY", violations)
        self.assertIn("DIRECT_RESTART_COUNT_NONZERO", violations)
        self.assertIn("DIRECT_CONTAINER_OOM_KILLED", violations)
        self.assertIn("DIRECT_MOUNT_CONTRACT_MISMATCH", violations)


class SubnetTests(unittest.TestCase):
    def test_detects_overlap(self) -> None:
        self.assertEqual(subnets.overlaps("172.31.253.0/24", ["172.31.0.0/16"]), ["172.31.0.0/16"])

    def test_accepts_collision_free_prefix(self) -> None:
        self.assertEqual(subnets.overlaps("172.31.253.0/24", ["172.17.0.0/16", "10.0.0.0/8"]), [])


if __name__ == "__main__":
    unittest.main()
