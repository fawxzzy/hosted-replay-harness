from __future__ import annotations

import asyncio
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import struct
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


def gateway_contract_source() -> str:
    runner = (ROOT / "scripts/run-containment-smoke.sh").read_text(encoding="utf-8")
    match = re.search(
        r"# BEGIN GATEWAY_CONTRACT_PYTHON\n(?P<source>.*?)\n# END GATEWAY_CONTRACT_PYTHON",
        runner,
        re.DOTALL,
    )
    assert match
    return match.group("source")


def run_gateway_contract(
    mode: str,
    subnet: str,
    gateway: str,
    payload: object | None = None,
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as directory:
        command = [sys.executable, "-B", "-", mode, subnet, gateway]
        if payload is not None:
            path = Path(directory) / "ipam.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            command.append(str(path))
        return subprocess.run(
            command,
            input=gateway_contract_source(),
            capture_output=True,
            text=True,
            check=False,
        )


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
firewall_boundary = load_module("firewall_boundary", "scripts/firewall_boundary.py")


class PinContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pins = json.loads((ROOT / "pins.json").read_text(encoding="utf-8"))

    def test_exact_supabase_pin(self) -> None:
        cli = self.pins["supabase_cli"]
        self.assertEqual(cli["version"], "2.109.1")
        self.assertEqual(cli["source_commit"], "6d4c19870ed213ba7f682f117d0345c8a40bfa94")
        self.assertEqual(cli["sha256"], "36d87b7fe6b4bcfe89ac47a4354e526cff22480224de426d7b370f6934556976")
        self.assertEqual(
            cli["member_manifest_sha256"],
            "290ab75309cc2cd39140125f6f408ca2ef06c26ffc9b057aa87299a02041f140",
        )
        self.assertEqual(
            cli["adjacency_sha256"],
            "889c5d358daebdfd07db6d21bba8460ce002137f1f85b4280d472ead3f290f7d",
        )
        self.assertEqual(
            [(member["name"], member["size"], member["sha256"]) for member in cli["members"]],
            [
                (
                    "supabase",
                    109918528,
                    "e9c1c33233b4341a0475f9acb2ecac35c41f6c9aa6cfdcd4f54b3761cc789c20",
                ),
                (
                    "supabase-go",
                    100909240,
                    "d10d8059b90d9fd68a69cb808b88dd3fe9f57ec458ffefc79a83083b3e810616",
                ),
            ],
        )
        for member in cli["members"]:
            self.assertEqual(member["archive_mode"], "0755")
            self.assertEqual(member["runtime_mode"], "0555")
            self.assertEqual(member["platform"], "linux/amd64")
            self.assertEqual(member["format"], "ELF64-little-x86-64")

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

    def test_manual_workflow_selects_only_fixed_firewall_rehearsal_mode(self) -> None:
        self.assertIn("Hosted replay containment smoke", self.workflow)
        self.assertEqual(self.workflow.count("./scripts/run-containment-smoke.sh\n"), 1)
        self.assertNotIn("run-containment-smoke.sh direct-port", self.workflow)
        self.assertNotIn("run-containment-smoke.sh run", self.workflow)
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

    def test_cli_containment_acquires_only_the_two_exact_images(self) -> None:
        pulls = re.findall(r"(?m)^\s*docker pull --platform linux/amd64 ", self.runner)
        self.assertEqual(len(pulls), 2)
        self.assertNotRegex(self.runner, r"(?m)^\s*docker (build|compose pull|image pull)\b")
        first_pull = self.runner.index('docker pull --platform linux/amd64 "$POSTGRES_PULL"')
        cli_start = self.runner.index('    db start\n) >"$RAW/supabase-db-start.log"')
        self.assertLess(first_pull, cli_start)
        self.assertIn('record images.pull_count int 2', self.runner)

    def test_direct_mode_isolated_from_cli_and_uses_one_exact_target(self) -> None:
        self.assertIn('run|direct-port|firewall-rehearsal|cleanup-only', self.runner)
        self.assertRegex(self.runner, r'(?s)if \[\[ "\$MODE" == "direct-port" \]\]; then\s+run_direct_port_probe\s+exit 0\s+fi')
        direct_function = self.runner[
            self.runner.index("run_direct_port_probe() {") : self.runner.index(
                "firewall_counter_value() {"
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

    def test_default_mode_is_fixed_firewall_rehearsal_without_cli(self) -> None:
        self.assertIn('MODE="${1:-firewall-rehearsal}"', self.runner)
        rehearsal = self.runner[
            self.runner.index("run_firewall_publication_rehearsal() {") : self.runner.index(
                "packet_object_counts() {"
            )
        ]
        self.assertNotIn("$RUNTIME/bin/supabase", rehearsal)
        self.assertNotIn("db start", rehearsal)
        self.assertNotIn('"$GOTRUE_PULL"', rehearsal)
        dispatch = 'if [[ "$MODE" == "firewall-rehearsal" ]]; then\n  run_firewall_publication_rehearsal\n  exit 0\nfi'
        self.assertIn(dispatch, self.runner)
        self.assertLess(self.runner.index(dispatch), self.runner.index('host_ips="$(hostname -I'))

    def test_firewall_rehearsal_uses_nat_loopback_network_and_one_pinned_image(self) -> None:
        for fragment in (
            'record network.internal bool false',
            '--gateway "$SUBNET_GATEWAY"',
            'com.docker.network.bridge.gateway_mode_ipv4=nat',
            'com.docker.network.bridge.host_binding_ipv4=127.0.0.1',
            'com.docker.network.bridge.name=${FIREWALL_BRIDGE_NAME}',
            'record network.default_route_present bool true',
            'record images.pull_count int 1',
        ):
            self.assertIn(fragment, self.runner)
        rehearsal = self.runner[
            self.runner.index("run_firewall_publication_rehearsal() {") : self.runner.index(
                "packet_object_counts() {"
            )
        ]
        self.assertEqual(rehearsal.count("docker run -d"), 3)
        self.assertEqual(rehearsal.count('"$POSTGRES_PULL"'), 4)
        self.assertEqual(rehearsal.count("--tmpfs"), 3)
        self.assertNotIn('"$GOTRUE_PULL"', rehearsal)
        self.assertNotRegex(rehearsal, r"docker (pull|build|network create|volume create)")

    def test_firewall_gateway_request_and_exact_ipam_readback_precede_mutation(self) -> None:
        request_check = 'gateway_contract request "$SUBNET" "$SUBNET_GATEWAY"'
        network_create = 'NETWORK_ID="$(docker network create "${network_args[@]}" "$NETWORK_NAME"'
        readback = 'validate_network_ipam_contract "$NETWORK_ID" after-create'
        dispatch = 'run_firewall_publication_rehearsal\n  exit 0'
        self.assertLess(self.runner.index(request_check), self.runner.index(network_create))
        self.assertLess(self.runner.index(network_create), self.runner.index(readback))
        self.assertLess(self.runner.index(readback), self.runner.index(dispatch))
        self.assertIn('ipam_gateway="$SUBNET_GATEWAY"', self.runner)
        self.assertIn("NETWORK_IPAM_CONTRACT_MISMATCH", self.runner)

    def test_gateway_request_rejects_nonusable_or_non_ipv4_addresses(self) -> None:
        self.assertEqual(
            run_gateway_contract("request", "172.31.253.0/24", "172.31.253.1").returncode,
            0,
        )
        rejected = (
            ("172.31.253.0/24", "172.31.253.0"),
            ("172.31.253.0/24", "172.31.253.255"),
            ("172.31.253.0/24", "172.31.252.1"),
            ("172.31.253.1/24", "172.31.253.1"),
            ("fd00::/64", "fd00::1"),
            ("malformed", "172.31.253.1"),
        )
        for subnet, gateway in rejected:
            with self.subTest(subnet=subnet, gateway=gateway):
                self.assertNotEqual(run_gateway_contract("request", subnet, gateway).returncode, 0)

    def test_ipam_readback_requires_one_exact_ipv4_row(self) -> None:
        exact = [{"Subnet": "172.31.253.0/24", "Gateway": "172.31.253.1"}]
        self.assertEqual(
            run_gateway_contract(
                "readback", "172.31.253.0/24", "172.31.253.1", exact
            ).returncode,
            0,
        )
        rejected = (
            [],
            [{"Subnet": "172.31.253.0/24"}],
            [{"Subnet": "172.31.253.0/24", "Gateway": "172.31.253.2"}],
            exact + exact,
            [{"Subnet": "172.31.253.0/24", "Gateway": "172.31.253.1", "IPRange": "172.31.253.0/25"}],
            [{"Subnet": "fd00::/64", "Gateway": "fd00::1"}],
            [{"Subnet": "172.31.253.0/24", "Gateway": "172.31.253.1", "Unexpected": "value"}],
            "malformed-shape",
        )
        for payload in rejected:
            with self.subTest(payload=payload):
                self.assertNotEqual(
                    run_gateway_contract(
                        "readback", "172.31.253.0/24", "172.31.253.1", payload
                    ).returncode,
                    0,
                )

    def test_firewall_is_active_before_first_container_and_removed_after_all_containers(self) -> None:
        rehearsal = self.runner[
            self.runner.index("run_firewall_publication_rehearsal() {") : self.runner.index(
                "packet_object_counts() {"
            )
        ]
        self.assertLess(
            rehearsal.index('firewall_boundary.py" install'),
            rehearsal.index("docker run -d"),
        )
        cleanup = self.runner[
            self.runner.index("cleanup_exact() {") : self.runner.index("finalize() {")
        ]
        self.assertLess(cleanup.index("docker rm -f"), cleanup.index('firewall_boundary.py" remove'))
        self.assertLess(cleanup.index('firewall_boundary.py" remove'), cleanup.index("docker network rm"))
        self.assertIn("FIREWALL_REMOVE_BLOCKED_BY_CONTAINER_RESIDUE", cleanup)
        self.assertLess(
            cleanup.index('record cleanup.containers_before_firewall_remove'),
            cleanup.index('firewall_boundary.py" remove'),
        )
        self.assertNotIn("docker system prune", cleanup)
        self.assertNotIn("docker stop --all", cleanup)

    def test_firewall_rehearsal_has_every_effective_canary_and_counter_correlation(self) -> None:
        rehearsal = self.runner[
            self.runner.index("run_firewall_publication_rehearsal() {") : self.runner.index(
                "packet_object_counts() {"
            )
        ]
        for fragment in (
            "same_network_connect",
            "external_dns forward_deny",
            "literal_ip forward_deny",
            "metadata forward_deny",
            "gateway input_deny",
            "host_listener input_deny",
            "foreign_network forward_deny",
            "docker_control_available",
            "native_listener_contract post_cli",
        ):
            self.assertIn(fragment, rehearsal)
        self.assertIn("(( after > before ))", self.runner)

    def test_immutable_workflow_config_pins_and_observer_hashes(self) -> None:
        expected = {
            ".github/workflows/containment-smoke.yml": "e0440e1748c4655c559fc82f5882e73b11c37b9cfd3e389bdbddf4ddecc7db99",
            "supabase/config.toml": "1b955c23161259dd41f3849f261bab41525b5ffeca83ab3074e44c5cc18ac0c6",
            "pins.json": "fe6105e121af3347a2de2494330d1e793a7bc3634f9d3d95964f6593ea990f50",
            "scripts/docker_api_boundary.py": "cf6e7cca0ded8c4aeca16837f454a948a68058d35602dbb923a991ee70b32f82",
        }
        for relative, digest in expected.items():
            self.assertEqual(hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(), digest)

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

    def test_exact_network_contract_precedes_the_contained_db_start(self) -> None:
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
            self.runner.index("assert_frozen_network pre_cli_start empty"),
            self.runner.index('    db start\n) >"$RAW/supabase-db-start.log"'),
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
        active_start = self.runner.index('exec 3<"$DOCKER_API_POLICY_FILE"')
        active_cli = self.runner.index('    db start\n) >"$RAW/supabase-db-start.log"')
        active_stop = self.runner.index("stop_docker_api_observer", active_cli)
        self.assertLess(active_start, active_cli)
        self.assertLess(active_cli, active_stop)
        self.assertNotIn("export DOCKER_HOST", self.runner[active_start:active_stop])

    def test_docker_api_observer_state_is_sanitized_and_transient(self) -> None:
        self.assertIn("DOCKER_API_OBSERVER_STATE_MISSING", self.runner)
        self.assertIn("DOCKER_API_OBSERVER_FAILED", self.runner)
        self.assertIn("DB_START_POLICY_COMPLETE", self.runner)
        self.assertIn("DB_START_POLICY_INCOMPLETE", self.runner)
        self.assertIn("DB_START_POLICY_VIOLATION", self.runner)
        self.assertIn("OBSERVER_FORWARDING_FAILED", self.runner)
        self.assertNotIn('cat "$RAW/docker-api-observer.log"', self.runner)
        self.assertIn('cat "$DOCKER_API_BOUNDARY_STATE_FILE" >>"$STATE_FILE"', self.runner)
        self.assertIn('rm -rf -- "$RUNTIME"', self.runner)

    def test_precli_object_listener_and_event_history_boundaries(self) -> None:
        freeze = "freeze_precli_objects_and_listeners"
        boundary = 'EVENT_SINCE="$(date -u +%s)"'
        cli_start = '    db start\n) >"$RAW/supabase-db-start.log"'
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

    def test_exact_db_start_source_contract_and_binary_hash(self) -> None:
        self.assertIn('CLI_COMMIT="6d4c19870ed213ba7f682f117d0345c8a40bfa94"', self.runner)
        self.assertIn(
            'CLI_BINARY_SHA="e9c1c33233b4341a0475f9acb2ecac35c41f6c9aa6cfdcd4f54b3761cc789c20"',
            self.runner,
        )
        self.assertIn('"$actual_cli_binary_sha" == "$CLI_BINARY_SHA"', self.runner)
        self.assertIn(
            'CLI_SIDECAR_SHA="d10d8059b90d9fd68a69cb808b88dd3fe9f57ec458ffefc79a83083b3e810616"',
            self.runner,
        )
        self.assertIn('CLI_BINARY_SIZE="109918528"', self.runner)
        self.assertIn('CLI_SIDECAR_SIZE="100909240"', self.runner)
        self.assertIn('[[ ! -v SUPABASE_GO_BINARY ]]', self.runner)
        self.assertNotRegex(self.runner, r"(?m)^\s*SUPABASE_GO_BINARY=")
        self.assertIn("validate_extract_cli_archive", self.runner)
        self.assertNotIn('tar -xzf "$RUNTIME/$CLI_ASSET"', self.runner)
        self.assertIn("record supabase_cli.sidecar_sha256", self.runner)
        self.assertIn("record supabase_cli.sidecar_size", self.runner)
        self.assertIn("record supabase_cli.sidecar_adjacent bool true", self.runner)
        validator_at = self.runner.index(
            'validate_extract_cli_archive "$RUNTIME/$CLI_ASSET" "$RUNTIME/bin"'
        )
        first_docker_pull = self.runner.index("docker pull --platform linux/amd64")
        first_prestart = self.runner.index("assert_frozen_network pre_cli_start")
        self.assertLess(validator_at, first_docker_pull)
        self.assertLess(validator_at, first_prestart)
        self.assertIn("record source_contract.command str supabase-db-start", self.runner)
        self.assertIn("record source_contract.root_persistent_prerun bool true", self.runner)
        self.assertIn("record source_contract.load_config bool true", self.runner)
        self.assertIn("record source_contract.docker_access_expected bool true", self.runner)
        self.assertIn("record source_contract.provider_access_enabled bool false", self.runner)
        self.assertEqual(
            self.runner.count('    db start\n) >"$RAW/supabase-db-start.log"'), 1
        )

    def test_db_start_execution_path_is_exact_clean_and_prohibits_remote_commands(self) -> None:
        start = self.runner.index('exec 3<"$DOCKER_API_POLICY_FILE"')
        end = self.runner.index('assert_frozen_network post_cli active', start)
        db_start = self.runner[start:end]
        exact = (
            'timeout --signal=TERM --kill-after=10s 300s "$RUNTIME/bin/supabase" \\\n'
            '    --workdir "$CLI_PROJECT_DIR" \\\n'
            '    --network-id "$NETWORK_NAME" \\\n'
            '    --yes \\\n'
            '    db start'
        )
        self.assertIn(exact, db_start)
        self.assertEqual(db_start.count("\n    db start\n"), 1)
        self.assertIn("env -i", db_start)
        self.assertIn('DOCKER_HOST="unix://$DOCKER_API_SOCKET"', db_start)
        for inherited in ("SUPABASE_[A-Z0-9_]*", "CI", "GITHUB_[A-Z0-9_]*", "RUNNER_[A-Z0-9_]*"):
            self.assertNotRegex(db_start, rf"(?m)^\s+{inherited}=")
        prohibited = (
            r"\bstatus\s+--ignore-health-check\b",
            r"\b(login|link|pull|push|dump)\b",
            r"\bdb\s+reset\b",
            r"--linked\b",
            r"--db-url\b",
        )
        for pattern in prohibited:
            self.assertNotRegex(db_start, pattern)
        self.assertIn('--policy-fd 3', db_start)
        self.assertIn('"nonce": os.urandom(32).hex()', self.runner)
        self.assertIn('exec 3<&-', db_start)
        self.assertIn('rm -f -- "$DOCKER_API_POLICY_FILE"', db_start)
        self.assertLess(db_start.index('rm -f -- "$DOCKER_API_POLICY_FILE"'), db_start.index('    db start'))
        self.assertLess(db_start.index('exec 3<&-'), db_start.index('    db start'))

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


class CliArchiveValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        runner = (ROOT / "scripts/run-containment-smoke.sh").read_text(encoding="utf-8")
        match = re.search(
            r"# BEGIN CLI_ARCHIVE_VALIDATOR_PYTHON\n(.*?)\n# END CLI_ARCHIVE_VALIDATOR_PYTHON",
            runner,
            re.DOTALL,
        )
        assert match
        namespace = {"__name__": "cli_archive_validator_tests"}
        exec(compile(match.group(1), "<cli-archive-validator>", "exec"), namespace)
        cls.validate_archive = staticmethod(namespace["validate_archive"])
        cls.contract_error = namespace["ArchiveContractError"]

    @staticmethod
    def elf_payload(marker: int) -> bytes:
        payload = bytearray(96)
        payload[:7] = b"\x7fELF\x02\x01\x01"
        payload[7] = 0
        struct.pack_into("<HHI", payload, 16, 2, 62, 1)
        struct.pack_into("<H", payload, 52, 64)
        payload[64:] = bytes((marker,)) * 32
        return bytes(payload)

    def expected(self) -> tuple[dict[str, object], ...]:
        members = []
        for index, (name, marker) in enumerate((("supabase", 65), ("supabase-go", 66)), start=1):
            payload = self.elf_payload(marker)
            members.append(
                {
                    "name": name,
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "mode": 0o755,
                    "uid": 1001,
                    "gid": 1001,
                    "uname": "runner",
                    "gname": "runner",
                    "mtime": index,
                    "payload": payload,
                }
            )
        return tuple(members)

    @staticmethod
    def octal(value: int, width: int) -> bytes:
        return f"{value:0{width - 1}o}".encode("ascii") + b"\0"

    def tar_header(
        self,
        member: dict[str, object],
        *,
        name: str | None = None,
        typeflag: bytes = b"0",
        mode: int | None = None,
        payload: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        body = member["payload"] if payload is None else payload
        assert isinstance(body, bytes)
        header = bytearray(512)
        encoded_name = (name or str(member["name"])).encode("ascii")
        header[: len(encoded_name)] = encoded_name
        header[100:108] = self.octal(int(member["mode"] if mode is None else mode), 8)
        header[108:116] = self.octal(int(member["uid"]), 8)
        header[116:124] = self.octal(int(member["gid"]), 8)
        header[124:136] = self.octal(len(body), 12)
        header[136:148] = self.octal(int(member["mtime"]), 12)
        header[148:156] = b" " * 8
        header[156:157] = typeflag
        header[257:263] = b"ustar "
        header[263:265] = b" \0"
        header[265:271] = b"runner"
        header[297:303] = b"runner"
        header[329:337] = self.octal(0, 8)
        header[337:345] = self.octal(0, 8)
        header[148:156] = f"{sum(header):06o}\0 ".encode("ascii")
        return bytes(header), body

    def write_archive(
        self,
        directory: Path,
        members: list[tuple[dict[str, object], dict[str, object]]],
    ) -> Path:
        tar_bytes = bytearray()
        for member, overrides in members:
            header, payload = self.tar_header(member, **overrides)
            tar_bytes.extend(header)
            tar_bytes.extend(payload)
            tar_bytes.extend(b"\0" * ((-len(payload)) % 512))
        tar_bytes.extend(b"\0" * 1024)
        archive = directory / "cli.tar.gz"
        archive.write_bytes(gzip.compress(bytes(tar_bytes), mtime=0))
        return archive

    def run_validator(
        self,
        directory: Path,
        archive: Path,
        expected: tuple[dict[str, object], ...],
    ) -> tuple[dict[str, object], Path]:
        destination = directory / "bin"
        destination.mkdir()
        result = self.validate_archive(
            archive,
            destination,
            expected=expected,
            expected_member_manifest_sha256=None,
            expected_adjacency_sha256=None,
        )
        return result, destination

    def test_exact_two_member_closure_extracts_adjacent_read_only_elf_files(self) -> None:
        expected = self.expected()
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            archive = self.write_archive(directory, [(member, {}) for member in expected])
            result, destination = self.run_validator(directory, archive, expected)
            self.assertEqual(result["member_count"], 2)
            extracted = sorted(destination.iterdir())
            self.assertEqual([path.name for path in extracted], ["supabase", "supabase-go"])
            self.assertEqual({path.parent for path in extracted}, {destination})
            self.assertTrue(all(path.is_file() and not path.is_symlink() for path in extracted))

    def test_rejects_missing_sidecar_and_removes_partial_extraction(self) -> None:
        expected = self.expected()
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            archive = self.write_archive(directory, [(expected[0], {})])
            destination = directory / "bin"
            destination.mkdir()
            with self.assertRaises(self.contract_error):
                self.validate_archive(
                    archive,
                    destination,
                    expected=expected,
                    expected_member_manifest_sha256=None,
                    expected_adjacency_sha256=None,
                )
            self.assertEqual(list(destination.iterdir()), [])

    def test_rejects_wrong_sidecar_hash_and_size(self) -> None:
        expected = self.expected()
        for label, payload in (
            ("hash", self.elf_payload(67)),
            ("size", self.elf_payload(66) + b"x"),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory_name:
                directory = Path(directory_name)
                archive = self.write_archive(
                    directory,
                    [(expected[0], {}), (expected[1], {"payload": payload})],
                )
                destination = directory / "bin"
                destination.mkdir()
                with self.assertRaises(self.contract_error):
                    self.validate_archive(
                        archive,
                        destination,
                        expected=expected,
                        expected_member_manifest_sha256=None,
                        expected_adjacency_sha256=None,
                    )
                self.assertEqual(list(destination.iterdir()), [])

    def test_rejects_extra_nested_duplicate_and_non_adjacent_members(self) -> None:
        expected = self.expected()
        extra = dict(expected[1])
        extra["name"] = "extra"
        cases = {
            "extra": [(expected[0], {}), (expected[1], {}), (extra, {})],
            "nested": [(expected[0], {"name": "nested/supabase"}), (expected[1], {})],
            "duplicate": [(expected[0], {}), (expected[1], {"name": "supabase"})],
        }
        for label, members in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory_name:
                directory = Path(directory_name)
                archive = self.write_archive(directory, members)
                destination = directory / "bin"
                destination.mkdir()
                with self.assertRaises(self.contract_error):
                    self.validate_archive(
                        archive,
                        destination,
                        expected=expected,
                        expected_member_manifest_sha256=None,
                        expected_adjacency_sha256=None,
                    )
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            archive = self.write_archive(directory, [(member, {}) for member in expected])
            destination = directory / "bin"
            destination.mkdir()
            (destination / "nested").mkdir()
            with self.assertRaises(self.contract_error):
                self.validate_archive(
                    archive,
                    destination,
                    expected=expected,
                    expected_member_manifest_sha256=None,
                    expected_adjacency_sha256=None,
                )

    def test_rejects_links_devices_pax_long_names_sparse_sockets_and_special_bits(self) -> None:
        expected = self.expected()
        for typeflag in (b"1", b"2", b"3", b"4", b"6", b"x", b"g", b"L", b"K", b"S", b"s"):
            with self.subTest(typeflag=typeflag), tempfile.TemporaryDirectory() as directory_name:
                directory = Path(directory_name)
                archive = self.write_archive(
                    directory,
                    [(expected[0], {"typeflag": typeflag}), (expected[1], {})],
                )
                destination = directory / "bin"
                destination.mkdir()
                with self.assertRaises(self.contract_error):
                    self.validate_archive(
                        archive,
                        destination,
                        expected=expected,
                        expected_member_manifest_sha256=None,
                        expected_adjacency_sha256=None,
                    )
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            archive = self.write_archive(
                directory,
                [(expected[0], {"mode": 0o4755}), (expected[1], {})],
            )
            destination = directory / "bin"
            destination.mkdir()
            with self.assertRaises(self.contract_error):
                self.validate_archive(
                    archive,
                    destination,
                    expected=expected,
                    expected_member_manifest_sha256=None,
                    expected_adjacency_sha256=None,
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
    def test_firewall_rehearsal_uses_existing_schema_with_null_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            state = temp / "state.tsv"
            audit = temp / "audit.jsonl"
            output = temp / "result.json"
            state.write_text(
                "result.profile\tstr\tcontainment-smoke-v1\n"
                "status\tstr\tFIREWALL_PUBLICATION_REHEARSAL_PASS\n"
                "failure\tjson\tnull\n"
                "packet\tstr\tFP-HOSTED-REPLAY-FIREWALL-PUBLICATION-REHEARSAL-001\n"
                "source_contract.command\tstr\tfirewall-publication-rehearsal\n"
                "source_contract.supabase_cli_invoked\tbool\tfalse\n",
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
            self.assertEqual(result["schema"], "fawxzzy.hosted-replay-harness.result.v1")
            self.assertEqual(result["status"], "FIREWALL_PUBLICATION_REHEARSAL_PASS")
            self.assertIsNone(result["failure"])
            self.assertFalse(result["source_contract"]["supabase_cli_invoked"])

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


class DbStartPolicyTests(unittest.TestCase):
    DB_ID = "c" * 64
    GOTRUE_ID = "d" * 64

    def policy_data(self, **updates: object) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": docker_api_boundary.POLICY_SCHEMA,
            "matrix_sha256": docker_api_boundary.POLICY_MATRIX_SHA256,
            "generation": 0,
            "nonce": "1" * 64,
            "api_version": "1.48",
            "project": "fp-hosted-replay-ro-001",
            "network_name": "fp-hosted-replay-ro-001-net",
            "network_id": "a" * 64,
            "db_name": "supabase_db_fp-hosted-replay-ro-001",
            "db_volume": "supabase_db_fp-hosted-replay-ro-001",
            "db_port": "56422",
            "postgres_image_ref": "public.ecr.aws/supabase/postgres:17.6.1.143",
            "postgres_image_id": "sha256:" + "b" * 64,
            "postgres_digest": "sha256:" + "2" * 64,
            "gotrue_image_ref": "public.ecr.aws/supabase/gotrue:v2.192.0",
            "gotrue_image_id": "sha256:" + "e" * 64,
            "gotrue_digest": "sha256:" + "3" * 64,
        }
        value.update(updates)
        return value

    @staticmethod
    def labels() -> dict[str, str]:
        return {
            "com.supabase.cli.project": "fp-hosted-replay-ro-001",
            "com.docker.compose.project": "fp-hosted-replay-ro-001",
        }

    def db_create_body(self) -> dict[str, object]:
        return {
            "Hostname": "",
            "Domainname": "",
            "User": "",
            "AttachStdin": False,
            "AttachStdout": False,
            "AttachStderr": False,
            "Tty": False,
            "OpenStdin": False,
            "StdinOnce": False,
            "Env": [
                "POSTGRES_PASSWORD=private-password",
                "POSTGRES_HOST=/var/run/postgresql",
                "JWT_SECRET=private-jwt",
                "JWT_EXP=3600",
            ],
            "Cmd": None,
            "Healthcheck": {
                "Test": ["CMD", "pg_isready", "-U", "postgres", "-h", "127.0.0.1", "-p", "5432"],
                "Interval": 10_000_000_000,
                "Timeout": 2_000_000_000,
                "Retries": 3,
            },
            "Image": "public.ecr.aws/supabase/postgres:17.6.1.143",
            "Volumes": None,
            "WorkingDir": "",
            "Entrypoint": ["sh", "-c", "schema material private-root-key\ndocker-entrypoint.sh postgres -D /etc/postgresql"],
            "OnBuild": None,
            "Labels": self.labels(),
            "HostConfig": {
                "Binds": ["supabase_db_fp-hosted-replay-ro-001:/var/lib/postgresql/data"],
                "NetworkMode": "fp-hosted-replay-ro-001-net",
                "PortBindings": {"5432/tcp": [{"HostIp": "", "HostPort": "56422"}]},
                "RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0},
                "ExtraHosts": ["host.docker.internal:host-gateway"],
            },
            "NetworkingConfig": {
                "EndpointsConfig": {
                    "fp-hosted-replay-ro-001-net": {
                        "Aliases": ["db", "db.supabase.internal"]
                    }
                }
            },
        }

    def gotrue_create_body(self) -> dict[str, object]:
        return {
            "Hostname": "",
            "Domainname": "",
            "User": "",
            "AttachStdin": False,
            "AttachStdout": False,
            "AttachStderr": False,
            "Tty": False,
            "OpenStdin": False,
            "StdinOnce": False,
            "Env": [
                "API_EXTERNAL_URL=http://127.0.0.1:54321",
                "GOTRUE_LOG_LEVEL=error",
                "GOTRUE_DB_DRIVER=postgres",
                "GOTRUE_DB_DATABASE_URL=postgresql://supabase_auth_admin:private-password@supabase_db_fp-hosted-replay-ro-001:5432/postgres",
                "GOTRUE_SITE_URL=http://localhost:3000",
                "GOTRUE_JWT_SECRET=private-jwt",
            ],
            "Cmd": ["gotrue", "migrate"],
            "Image": "public.ecr.aws/supabase/gotrue:v2.192.0",
            "Volumes": None,
            "WorkingDir": "",
            "Entrypoint": None,
            "OnBuild": None,
            "Labels": self.labels(),
            "HostConfig": {
                "NetworkMode": "fp-hosted-replay-ro-001-net",
                "ExtraHosts": ["host.docker.internal:host-gateway"],
            },
            "NetworkingConfig": {},
        }

    @staticmethod
    def shape_digest(body: dict[str, object]) -> str:
        canonical = "".join(
            f"{key}\t{docker_api_boundary._json_type(body[key])}\n"
            for key in sorted(body)
        ).encode()
        return hashlib.sha256(canonical).hexdigest()

    def test_moby_source_identity_and_exact_flat_create_shapes(self) -> None:
        self.assertEqual(docker_api_boundary.MOBY_VERSION, "v28.5.2")
        self.assertEqual(
            docker_api_boundary.MOBY_CREATE_REQUEST_BLOB_SHA,
            "e98dd6ad449b016b21e6be138b231c3a1c0907dd",
        )
        self.assertEqual(
            docker_api_boundary.MOBY_CONTAINER_CREATE_BLOB_SHA,
            "0625cb125ccb4df10be660265dcb4ed8075c619c",
        )
        nested_shape = {
            "Config": {},
            "HostConfig": {},
            "NetworkingConfig": {},
        }
        self.assertEqual(len(nested_shape), 3)
        self.assertEqual(
            self.shape_digest(nested_shape),
            docker_api_boundary.NESTED_CREATE_REQUEST_SHAPE_SHA256,
        )
        database = self.db_create_body()
        self.assertEqual(len(database), 20)
        self.assertEqual(
            self.shape_digest(database),
            docker_api_boundary.FLAT_CREATE_REQUEST_SHAPE_SHA256,
        )
        gotrue = self.gotrue_create_body()
        self.assertEqual(len(gotrue), 19)
        self.assertEqual(
            self.shape_digest(gotrue),
            docker_api_boundary.FLAT_GOTRUE_CREATE_REQUEST_SHAPE_SHA256,
        )
        self.assertNotIn("Config", database)
        self.assertNotIn("Config", gotrue)
        self.assertEqual(
            set(database) - {"HostConfig", "NetworkingConfig"},
            set(docker_api_boundary.DBStartPolicy.DB_CONFIG_WIRE_TYPES),
        )
        self.assertEqual(
            set(gotrue) - {"HostConfig", "NetworkingConfig"},
            set(docker_api_boundary.DBStartPolicy.GOTRUE_CONFIG_WIRE_TYPES),
        )
        policy = docker_api_boundary.DBStartPolicy(self.policy_data())
        policy._container_body(database, database=True)
        policy._container_body(gotrue, database=False)
        gotrue["Cmd"] = ["gotrue", "serve"]
        with self.assertRaisesRegex(docker_api_boundary.PolicyViolation, "POLICY_BODY_REJECTED"):
            policy._container_body(gotrue, database=False)

    def inspect_body(self, database: bool, health: str = "healthy") -> dict[str, object]:
        value: dict[str, object] = {
            "Id": self.DB_ID if database else self.GOTRUE_ID,
            "Image": "sha256:" + ("b" if database else "e") * 64,
            "NetworkSettings": {
                "Networks": {
                    "fp-hosted-replay-ro-001-net": {"NetworkID": "a" * 64}
                },
                "Ports": (
                    {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "56422"}]}
                    if database
                    else {}
                ),
            },
            "State": {"ExitCode": 0},
        }
        if database:
            value["Name"] = "/supabase_db_fp-hosted-replay-ro-001"
            value["State"] = {"Health": {"Status": health}, "ExitCode": 0}
        return value

    def exchange(
        self,
        policy: object,
        method: bytes,
        target: str,
        code: int,
        request: dict[str, object] | None = None,
        response: dict[str, object] | None = None,
        response_headers: dict[str, str] | None = None,
        stream_bytes: int = 0,
    ) -> None:
        request_body = (
            json.dumps(request, separators=(",", ":")).encode() if request is not None else b""
        )
        request_headers = {"content-type": "application/json"} if request is not None else {}
        decision = policy.authorize(method, target.encode(), request_headers, request_body)
        body = json.dumps(response, separators=(",", ":")).encode() if response is not None else b""
        headers = dict(response_headers or {})
        if response is not None:
            headers["content-type"] = "application/json"
        policy.accept(
            decision,
            code,
            headers,
            None if decision.stream else body,
            stream_bytes if decision.stream else len(body),
        )

    def advance_to_network(self, policy: object) -> None:
        self.exchange(policy, b"HEAD", "/_ping", 200, response_headers={"api-version": "1.48"})
        self.exchange(policy, b"GET", "/v1.48/containers/supabase_db_fp-hosted-replay-ro-001/json", 404)
        self.exchange(policy, b"GET", "/v1.48/volumes/supabase_db_fp-hosted-replay-ro-001", 404)
        self.exchange(
            policy,
            b"GET",
            "/v1.48/images/public.ecr.aws/supabase/postgres:17.6.1.143/json",
            200,
            response={"Id": "sha256:" + "b" * 64},
        )

    def complete_policy(self, health_probes: int = 1) -> object:
        policy = docker_api_boundary.DBStartPolicy(self.policy_data())
        self.advance_to_network(policy)
        network = {"Name": "fp-hosted-replay-ro-001-net", "Labels": self.labels()}
        volume = {"Name": "supabase_db_fp-hosted-replay-ro-001", "Labels": self.labels()}
        self.exchange(policy, b"POST", "/v1.48/networks/create", 409, request=network)
        self.exchange(policy, b"POST", "/v1.48/volumes/create", 201, request=volume, response={"Name": volume["Name"]})
        self.exchange(
            policy,
            b"POST",
            "/v1.48/containers/create?name=supabase_db_fp-hosted-replay-ro-001",
            201,
            request=self.db_create_body(),
            response={"Id": self.DB_ID, "Warnings": []},
        )
        self.exchange(policy, b"POST", f"/v1.48/containers/{self.DB_ID}/start", 204)
        for index in range(health_probes):
            health = "healthy" if index == health_probes - 1 else "starting"
            self.exchange(
                policy,
                b"GET",
                "/v1.48/containers/supabase_db_fp-hosted-replay-ro-001/json",
                200,
                response=self.inspect_body(True, health),
            )
        self.exchange(
            policy,
            b"GET",
            "/v1.48/images/public.ecr.aws/supabase/gotrue:v2.192.0/json",
            200,
            response={"Id": "sha256:" + "e" * 64},
        )
        self.exchange(policy, b"POST", "/v1.48/networks/create", 409, request=network)
        self.exchange(
            policy,
            b"POST",
            "/v1.48/containers/create",
            201,
            request=self.gotrue_create_body(),
            response={"Id": self.GOTRUE_ID, "Warnings": []},
        )
        self.exchange(policy, b"POST", f"/v1.48/containers/{self.GOTRUE_ID}/start", 204)
        self.exchange(
            policy,
            b"GET",
            f"/v1.48/containers/{self.GOTRUE_ID}/logs?follow=1&stderr=1&stdout=1&tail=",
            200,
            response_headers={"content-type": "application/vnd.docker.raw-stream"},
            stream_bytes=12,
        )
        self.exchange(
            policy,
            b"GET",
            f"/v1.48/containers/{self.GOTRUE_ID}/json",
            200,
            response=self.inspect_body(False),
        )
        self.exchange(
            policy,
            b"DELETE",
            f"/v1.48/containers/{self.GOTRUE_ID}?force=1&v=1",
            204,
        )
        return policy

    def test_full_exact_lifecycle_and_bounded_health_repeats(self) -> None:
        policy = self.complete_policy(health_probes=121)
        self.assertTrue(policy.complete)
        self.assertEqual(policy.health_probe_count, 121)
        receipt = docker_api_boundary.Receipt()
        receipt.attach_policy(policy)
        receipt.sync_policy(policy)
        result = receipt.sanitized()
        self.assertEqual(result["classification"], "DB_START_POLICY_COMPLETE")
        self.assertEqual(result["policy_matrix_sha256"], docker_api_boundary.POLICY_MATRIX_SHA256)
        self.assertNotIn(self.DB_ID, docker_api_boundary.format_state_lines(result))

    def test_order_id_replay_prefix_and_network_201_fail_closed(self) -> None:
        policy = docker_api_boundary.DBStartPolicy(self.policy_data())
        with self.assertRaisesRegex(docker_api_boundary.PolicyViolation, "POLICY_API_VERSION_REJECTED"):
            policy.authorize(b"HEAD", b"/v1.48/_ping", {}, b"")

        policy = docker_api_boundary.DBStartPolicy(self.policy_data())
        self.advance_to_network(policy)
        decision = policy.authorize(
            b"POST",
            b"/v1.48/networks/create",
            {"content-type": "application/json"},
            json.dumps({"Name": "fp-hosted-replay-ro-001-net", "Labels": self.labels()}).encode(),
        )
        with self.assertRaisesRegex(docker_api_boundary.PolicyViolation, "POLICY_STATUS_REJECTED"):
            policy.accept(decision, 201, {"content-type": "application/json"}, b"{}", 2)

        policy = self.complete_policy()
        with self.assertRaisesRegex(docker_api_boundary.PolicyViolation, "POLICY_ORDER_REJECTED"):
            policy.authorize(b"POST", f"/v1.48/containers/{self.GOTRUE_ID}/start".encode(), {}, b"")

    def test_identity_port_privilege_bind_capability_and_unknown_fields_rejected(self) -> None:
        mutations = (
            ("TopLevel", "Image", "drifted/image:tag"),
            ("TopLevel", "Labels", {"com.supabase.cli.project": "other"}),
            ("TopLevel", "Env", [
                "POSTGRES_PASSWORD=private-password",
                "POSTGRES_HOST=/var/run/postgresql",
                "JWT_SECRET=private-jwt",
                "JWT_EXP=3600",
                "UNEXPECTED=value",
            ]),
            ("TopLevel", "Healthcheck", {"Test": ["NONE"]}),
            ("TopLevel", "Entrypoint", ["sh", "-c", "unexpected"]),
            ("HostConfig", "NetworkMode", "other-network"),
            ("HostConfig", "PortBindings", {"5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": "56422"}]}),
            ("HostConfig", "Privileged", True),
            ("HostConfig", "PidMode", "host"),
            ("HostConfig", "IpcMode", "host"),
            ("HostConfig", "Binds", ["foreign:/var/lib/postgresql/data"]),
            ("HostConfig", "CapAdd", ["SYS_ADMIN"]),
            ("HostConfig", "Devices", [{"PathOnHost": "opaque"}]),
            ("HostConfig", "SecurityOpt", ["label:disable"]),
            ("HostConfig", "Mounts", [{"Type": "bind"}]),
            ("HostConfig", "UnknownField", "value"),
            ("NetworkingConfig", "EndpointsConfig", {
                "fp-hosted-replay-ro-001-net": {"Aliases": ["db", "db.supabase.internal"]},
                "foreign-network": {},
            }),
        )
        for section, key, value in mutations:
            with self.subTest(section=section, key=key):
                policy = docker_api_boundary.DBStartPolicy(self.policy_data())
                self.advance_to_network(policy)
                network = {"Name": "fp-hosted-replay-ro-001-net", "Labels": self.labels()}
                volume = {"Name": "supabase_db_fp-hosted-replay-ro-001", "Labels": self.labels()}
                self.exchange(policy, b"POST", "/v1.48/networks/create", 409, request=network)
                self.exchange(policy, b"POST", "/v1.48/volumes/create", 201, request=volume, response={"Name": volume["Name"]})
                body = self.db_create_body()
                if section == "TopLevel":
                    body[key] = value
                else:
                    body[section][key] = value
                with self.assertRaises(docker_api_boundary.PolicyViolation):
                    self.exchange(
                        policy,
                        b"POST",
                        "/v1.48/containers/create?name=supabase_db_fp-hosted-replay-ro-001",
                        201,
                        request=body,
                        response={"Id": self.DB_ID},
                    )

    def test_flat_create_shape_rejects_nested_missing_unknown_wrong_types_and_substitution(self) -> None:
        database = self.db_create_body()
        config = {
            key: value
            for key, value in database.items()
            if key not in {"HostConfig", "NetworkingConfig"}
        }
        invalid_bodies: list[dict[str, object]] = []

        nested = {
            "Config": config,
            "HostConfig": database["HostConfig"],
            "NetworkingConfig": database["NetworkingConfig"],
        }
        invalid_bodies.append(nested)
        for missing in ("Hostname", "Env", "HostConfig", "NetworkingConfig"):
            body = self.db_create_body()
            body.pop(missing)
            invalid_bodies.append(body)
        for key, value in (
            ("UnknownTopLevel", None),
            ("Hostname", None),
            ("AttachStdin", 0),
            ("Env", {}),
            ("Cmd", []),
            ("Healthcheck", []),
            ("HostConfig", []),
            ("NetworkingConfig", []),
        ):
            body = self.db_create_body()
            body[key] = value
            invalid_bodies.append(body)
        swapped = self.db_create_body()
        swapped["HostConfig"], swapped["NetworkingConfig"] = (
            swapped["NetworkingConfig"],
            swapped["HostConfig"],
        )
        invalid_bodies.append(swapped)

        for index, body in enumerate(invalid_bodies):
            with self.subTest(index=index):
                policy = docker_api_boundary.DBStartPolicy(self.policy_data())
                self.advance_to_network(policy)
                network = {"Name": "fp-hosted-replay-ro-001-net", "Labels": self.labels()}
                volume = {"Name": "supabase_db_fp-hosted-replay-ro-001", "Labels": self.labels()}
                self.exchange(policy, b"POST", "/v1.48/networks/create", 409, request=network)
                self.exchange(policy, b"POST", "/v1.48/volumes/create", 201, request=volume, response={"Name": volume["Name"]})
                with self.assertRaises(docker_api_boundary.PolicyViolation):
                    self.exchange(
                        policy,
                        b"POST",
                        "/v1.48/containers/create?name=supabase_db_fp-hosted-replay-ro-001",
                        201,
                        request=body,
                        response={"Id": self.DB_ID},
                    )

        duplicate = json.dumps(database, separators=(",", ":"))[:-1] + ',"Hostname":""}'
        with self.assertRaisesRegex(docker_api_boundary.PolicyViolation, "POLICY_BODY_REJECTED"):
            docker_api_boundary._closed_json(duplicate.encode(), 1024 * 1024)

    def test_rejected_create_is_not_forwarded_and_cleanup_list_is_separate(self) -> None:
        class FramedReader:
            def __init__(self, data: bytes) -> None:
                self.data = bytearray(data)

            async def readuntil(self, separator: bytes) -> bytes:
                index = self.data.find(separator)
                if index < 0:
                    partial = bytes(self.data)
                    self.data.clear()
                    raise asyncio.IncompleteReadError(partial, None)
                end = index + len(separator)
                value = bytes(self.data[:end])
                del self.data[:end]
                return value

            async def readexactly(self, size: int) -> bytes:
                if len(self.data) < size:
                    partial = bytes(self.data)
                    self.data.clear()
                    raise asyncio.IncompleteReadError(partial, size)
                value = bytes(self.data[:size])
                del self.data[:size]
                return value

        policy = docker_api_boundary.DBStartPolicy(self.policy_data())
        self.advance_to_network(policy)
        network = {"Name": "fp-hosted-replay-ro-001-net", "Labels": self.labels()}
        volume = {"Name": "supabase_db_fp-hosted-replay-ro-001", "Labels": self.labels()}
        self.exchange(policy, b"POST", "/v1.48/networks/create", 409, request=network)
        self.exchange(policy, b"POST", "/v1.48/volumes/create", 201, request=volume, response={"Name": volume["Name"]})

        flat = self.db_create_body()
        nested = {
            "Config": {
                key: value
                for key, value in flat.items()
                if key not in {"HostConfig", "NetworkingConfig"}
            },
            "HostConfig": flat["HostConfig"],
            "NetworkingConfig": flat["NetworkingConfig"],
        }
        raw = json.dumps(nested, separators=(",", ":")).encode()
        create_request = (
            b"POST /v1.48/containers/create?name=supabase_db_fp-hosted-replay-ro-001 HTTP/1.1\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(raw)}\r\n\r\n".encode()
            + raw
        )
        cleanup_request = b"GET /v1.48/containers/json HTTP/1.1\r\n\r\n"

        async def exercise() -> tuple[bytes, bytes, dict[str, object]]:
            receipt = docker_api_boundary.Receipt()
            server = docker_api_boundary.PolicyBoundaryServer(
                Path("packet.sock"), Path("docker.sock"), receipt, policy
            )
            upstream_writers = [
                DockerApiBoundaryTests.FakeWriter(),
                DockerApiBoundaryTests.FakeWriter(),
            ]
            upstreams = iter(
                (FramedReader(b""), writer) for writer in upstream_writers
            )

            async def open_upstream(_path: str) -> tuple[FramedReader, DockerApiBoundaryTests.FakeWriter]:
                return next(upstreams)

            with mock.patch.object(
                docker_api_boundary.asyncio,
                "open_unix_connection",
                side_effect=open_upstream,
                create=True,
            ):
                await server.handle(
                    FramedReader(create_request), DockerApiBoundaryTests.FakeWriter()
                )
                await server.handle(
                    FramedReader(cleanup_request), DockerApiBoundaryTests.FakeWriter()
                )
            return (
                bytes(upstream_writers[0].data),
                bytes(upstream_writers[1].data),
                receipt.sanitized(),
            )

        create_forwarded, cleanup_forwarded, result = asyncio.run(exercise())
        self.assertEqual(create_forwarded, b"")
        self.assertEqual(cleanup_forwarded, b"")
        self.assertEqual(result["policy_violation_count"], 2)
        self.assertEqual(result["policy_failure_code"], "POLICY_BODY_REJECTED")
        self.assertEqual(result["phase_counts"]["CONTAINER_CREATE"], 1)
        self.assertEqual(result["phase_counts"]["CONTAINER_LIST"], 1)
        self.assertEqual(result["response_count"], 0)

    def test_broad_cleanup_image_pull_exec_and_prune_are_denied(self) -> None:
        prohibited = (
            (b"GET", "/v1.48/containers/json"),
            (b"POST", "/v1.48/images/create"),
            (b"POST", "/v1.48/containers/prune"),
            (b"POST", "/v1.48/volumes/prune"),
            (b"POST", "/v1.48/networks/prune"),
            (b"POST", f"/v1.48/containers/{self.DB_ID}/exec"),
        )
        for method, target in prohibited:
            with self.subTest(target=target):
                policy = docker_api_boundary.DBStartPolicy(self.policy_data())
                with self.assertRaises(docker_api_boundary.PolicyViolation):
                    policy.authorize(method, target.encode(), {}, b"")

    def test_descriptor_is_one_shot_restart_is_lost_and_secrets_are_not_retained(self) -> None:
        read_fd, write_fd = os.pipe()
        os.write(write_fd, json.dumps(self.policy_data()).encode())
        os.close(write_fd)
        policy = docker_api_boundary.DBStartPolicy.from_fd(read_fd)
        with self.assertRaises(OSError):
            os.fstat(read_fd)
        self.assertRegex(policy.digest, r"^[0-9a-f]{64}$")
        with self.assertRaisesRegex(docker_api_boundary.PolicyViolation, "POLICY_LEDGER_LOST"):
            docker_api_boundary.DBStartPolicy(self.policy_data(generation=1))

        policy = self.complete_policy()
        receipt = docker_api_boundary.Receipt()
        receipt.attach_policy(policy)
        receipt.sync_policy(policy)
        rendered = docker_api_boundary.format_state_lines(receipt.sanitized())
        for forbidden in ("private-password", "private-jwt", "postgresql://", self.DB_ID, self.GOTRUE_ID):
            self.assertNotIn(forbidden, rendered)

    def test_framing_size_concurrency_and_schema_fail_closed(self) -> None:
        with self.assertRaisesRegex(docker_api_boundary.PolicyViolation, "POLICY_FRAMING_REJECTED"):
            docker_api_boundary._parse_head(
                b"POST /v1.48/containers/create HTTP/1.1\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n",
                request=True,
            )
        with self.assertRaisesRegex(docker_api_boundary.PolicyViolation, "POLICY_BODY_OVERSIZED"):
            docker_api_boundary._closed_json(b"{" + b"x" * 100 + b"}", 10)
        for malformed in (b'{"Name":"one","Name":"two"}', b'{"value":NaN}'):
            with self.subTest(malformed=malformed):
                with self.assertRaisesRegex(docker_api_boundary.PolicyViolation, "POLICY_BODY_REJECTED"):
                    docker_api_boundary._closed_json(malformed, 1024)
        policy = docker_api_boundary.DBStartPolicy(self.policy_data())
        receipt = docker_api_boundary.Receipt()
        server = docker_api_boundary.PolicyBoundaryServer(Path("packet.sock"), Path("docker.sock"), receipt, policy)

        async def check_lock() -> None:
            async with server.exchange_lock:
                with self.assertRaisesRegex(docker_api_boundary.PolicyViolation, "POLICY_CONCURRENT_REQUEST"):
                    server.ensure_exchange_available()

        asyncio.run(check_lock())


class DbStartLogClassifierTests(unittest.TestCase):
    def test_every_admitted_category_has_a_synthetic_fixture(self) -> None:
        fixtures = {
            "CLI_USAGE_ERROR": b"unknown flag: --not-real\n",
            "CONFIG_LOAD_OR_VALIDATION_FAILED": b"failed to parse config: fixture\n",
            "DOCKER_CLIENT_INITIALIZATION_FAILED": b"failed to initialize Docker client: fixture\n",
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
                    "normalization_status",
                    "sgr_count",
                    "rejected_control_count",
                    "matched_family_count",
                    "known_fingerprint",
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
                self.assertEqual(result["normalization_status"], "PLAIN")
                self.assertEqual(result["sgr_count"], 0)
                self.assertEqual(result["rejected_control_count"], 0)
                self.assertEqual(
                    result["matched_family_count"],
                    0 if expected == "UNKNOWN_SANITIZED" else 1,
                )
                self.assertFalse(result["known_fingerprint"])
                self.assertEqual(set(result), expected_keys)

    def test_empty_log_defaults_without_leaking_input(self) -> None:
        result = db_start_log.classify(b"", 7)
        self.assertEqual(result["category"], "UNKNOWN_SANITIZED")
        self.assertEqual(result["match_count"], 0)
        self.assertEqual(result["raw_byte_count"], 0)
        self.assertEqual(result["raw_line_count"], 0)
        rendered = db_start_log.format_state_lines(result)
        self.assertEqual(len(rendered.splitlines()), 14)

    def test_exact_cobra_and_pflag_source_phrases(self) -> None:
        fixtures = (
            b'unknown command "opaque" for "supabase db"\n',
            b"unknown flag: --opaque\n",
            b"unknown shorthand flag: 'x' in -xz\n",
            b"requires at least 2 arg(s), only received 1\n",
            b"accepts at most 1 arg(s), received 2\n",
            b"accepts 0 arg(s), received 1\n",
            b"accepts between 1 and 2 arg(s), received 3\n",
            b"flag needs an argument: --workdir\n",
            b"flag needs an argument: 'w' in -w\n",
            b'flag "opaque" does not exist\n',
            b"no such flag -x\n",
        )
        for raw in fixtures:
            with self.subTest(raw=raw):
                result = db_start_log.classify(raw, 1)
                self.assertEqual(result["category"], "CLI_USAGE_ERROR")
                self.assertEqual(result["matched_family_count"], 1)

    def test_every_admitted_config_prefix(self) -> None:
        prefixes = (
            "failed to get repo directory:",
            "failed to change directory:",
            "failed to parse environment file:",
            "failed to restore directory:",
            "failed to get working directory:",
            "failed to initialise config:",
            "failed to merge default values:",
            "failed to read file config:",
            "failed to merge file config:",
            "failed to merge remote config:",
            "failed to parse config:",
            "Missing required field in config:",
            "Invalid config for auth.jwt_secret.",
            "Failed reading config: Invalid db.major_version:",
            "duplicate project_id for [remotes.fixture] and [remotes.other]",
        )
        for prefix in prefixes:
            with self.subTest(prefix=prefix):
                result = db_start_log.classify((prefix + " fixture\n").encode(), 1)
                self.assertEqual(
                    result["category"], "CONFIG_LOAD_OR_VALIDATION_FAILED"
                )

    def test_exact_docker_initialization_wrappers(self) -> None:
        for wrapper in (
            b"Failed to create Docker client: fixture\n",
            b"Failed to initialize Docker client: fixture\n",
        ):
            with self.subTest(wrapper=wrapper):
                result = db_start_log.classify(b"prefix\n" + wrapper + wrapper, 1)
                self.assertEqual(
                    result["category"], "DOCKER_CLIENT_INITIALIZATION_FAILED"
                )
                self.assertEqual(result["match_count"], 2)
                self.assertEqual(result["first_match_line"], 2)

    def test_sgr_whole_line_and_token_splitting(self) -> None:
        fixtures = (
            b"\x1b[31munknown flag: --opaque\x1b[0m\n",
            b"unknown \x1b[1mflag\x1b[0m: --opaque\n",
            b"\x1b[38;5;9mfailed to parse config:\x1b[m fixture\n",
        )
        expected = (
            "CLI_USAGE_ERROR",
            "CLI_USAGE_ERROR",
            "CONFIG_LOAD_OR_VALIDATION_FAILED",
        )
        for raw, category in zip(fixtures, expected, strict=True):
            with self.subTest(category=category):
                result = db_start_log.classify(raw, 1)
                self.assertEqual(result["category"], category)
                self.assertEqual(result["normalization_status"], "SGR_STRIPPED")
                self.assertGreater(result["sgr_count"], 0)

    def test_unsupported_controls_fail_closed(self) -> None:
        fixtures = (
            b"\x1b]8;;https://invalid\x07unknown flag: --opaque\n",
            b"\x1b[31unknown flag: --opaque\n",
            b"\x00unknown flag: --opaque\n",
            "\u0085unknown flag: --opaque\n".encode(),
        )
        for raw in fixtures:
            with self.subTest(raw=raw):
                result = db_start_log.classify(raw, 1)
                self.assertEqual(result["category"], "UNKNOWN_SANITIZED")
                self.assertEqual(result["normalization_status"], "REJECTED_CONTROL")
                self.assertGreater(result["rejected_control_count"], 0)
                self.assertEqual(result["matched_family_count"], 0)

    def test_invalid_utf8_fails_closed(self) -> None:
        result = db_start_log.classify(b"unknown flag: --opaque\xff\n", 1)
        self.assertEqual(result["category"], "UNKNOWN_SANITIZED")
        self.assertEqual(result["normalization_status"], "INVALID_UTF8")
        self.assertGreater(result["rejected_control_count"], 0)

    def test_cross_family_input_is_ambiguous_and_unknown(self) -> None:
        raw = b"unknown flag: --opaque\nfailed to parse config: fixture\n"
        result = db_start_log.classify(raw, 1, debug_enabled=True)
        self.assertEqual(result["category"], "UNKNOWN_SANITIZED")
        self.assertEqual(result["matched_family_count"], 2)
        self.assertEqual(result["match_count"], 0)
        self.assertNotIn("first_match_line", result)
        self.assertTrue(result["debug_enabled"])

    def test_near_misses_remain_unknown(self) -> None:
        fixtures = (
            b"unknown flags: --opaque\n",
            b"accepts one arg(s), received two\n",
            b"failed parsing config: fixture\n",
            b"failed to initialize container client: fixture\n",
        )
        for raw in fixtures:
            with self.subTest(raw=raw):
                self.assertEqual(
                    db_start_log.classify(raw, 1)["category"], "UNKNOWN_SANITIZED"
                )

    def test_crlf_is_normalized_without_changing_raw_metadata(self) -> None:
        raw = b"prefix\r\nunknown flag: --opaque\r\n"
        result = db_start_log.classify(raw, 1)
        self.assertEqual(result["category"], "CLI_USAGE_ERROR")
        self.assertEqual(result["raw_byte_count"], len(raw))
        self.assertEqual(result["raw_line_count"], 2)
        self.assertEqual(result["raw_sha256"], hashlib.sha256(raw).hexdigest())

    def test_secret_shaped_input_is_counted_but_never_emitted(self) -> None:
        secrets = (
            "postgresql://worker:opaque-password@database.invalid/postgres\n"
            "Authorization: Bearer opaque-token-value\n"
            "JWT_SECRET=opaque-secret-value\n"
            "-----BEGIN PRIVATE KEY-----\n"
            "failed to parse config: fixture\n"
        ).encode()
        result = db_start_log.classify(secrets, 1, debug_enabled=True)
        rendered = db_start_log.format_state_lines(result)
        self.assertEqual(result["category"], "UNKNOWN_SANITIZED")
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

    def test_known_fingerprint_metadata_never_promotes_a_category(self) -> None:
        byte_count, line_count, digest = db_start_log.KNOWN_FINGERPRINT
        self.assertTrue(db_start_log.is_known_fingerprint(byte_count, line_count, digest))
        category, matches, family_count = db_start_log.classify_normalized(
            "opaque pre-docker failure"
        )
        self.assertEqual(category, "UNKNOWN_SANITIZED")
        self.assertEqual(matches, [])
        self.assertEqual(family_count, 0)

    def test_state_schema_is_closed_and_deterministic(self) -> None:
        result = db_start_log.classify(b"unknown flag: --opaque\n", 1)
        rendered = db_start_log.format_state_lines(result)
        self.assertEqual(rendered, db_start_log.format_state_lines(result))
        self.assertEqual(len(rendered.splitlines()), 15)
        with self.assertRaises(ValueError):
            db_start_log.validate_state_lines(
                rendered + "unclassified.raw\tstr\topaque\n",
                has_first_match=True,
            )

    def test_runner_deletes_the_transient_raw_file(self) -> None:
        runner = (ROOT / "scripts/run-containment-smoke.sh").read_text(encoding="utf-8")
        classify_at = runner.index('"$ROOT/scripts/classify_db_start_log.py"')
        delete_at = runner.index('rm -f -- "$RAW/supabase-db-start.log"', classify_at)
        assert_at = runner.index('[[ ! -e "$RAW/supabase-db-start.log" ]]', delete_at)
        self.assertLess(classify_at, delete_at)
        self.assertLess(delete_at, assert_at)

    def test_executable_path_emits_only_sanitized_state(self) -> None:
        raw = b"failed to parse config: opaque-fixture-text\n"
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
        self.assertEqual(len(completed.stdout.splitlines()), 15)
        self.assertIn("CONFIG_LOAD_OR_VALIDATION_FAILED", completed.stdout)
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

    def test_global_host_address_denominator_includes_ipv4_and_ipv6(self) -> None:
        fixture = json.dumps(
            [
                {"addr_info": [{"local": "192.0.2.10"}, {"local": "2001:db8::10"}]},
                {"addr_info": [{"local": "127.0.0.1"}, {"local": "fe80::1"}]},
            ]
        )
        completed = subprocess.CompletedProcess([], 0, stdout=fixture, stderr="")
        with mock.patch.object(direct_port.subprocess, "run", return_value=completed):
            self.assertEqual(direct_port.global_ip_addresses(), ["192.0.2.10", "2001:db8::10"])

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


def nft_entry(kind: str, **values: object) -> dict:
    payload = {"family": "inet", "table": firewall_boundary.TABLE, **values}
    if kind == "table":
        payload.pop("table")
        payload["name"] = firewall_boundary.TABLE
    return {kind: payload}


def owned_firewall_entries() -> list[dict]:
    return [
        nft_entry("table"),
        nft_entry("counter", name=firewall_boundary.INPUT_COUNTER, packets=0, bytes=0),
        nft_entry("counter", name=firewall_boundary.FORWARD_COUNTER, packets=0, bytes=0),
        nft_entry("chain", name=firewall_boundary.INPUT_CHAIN),
        nft_entry("chain", name=firewall_boundary.FORWARD_CHAIN),
        *[nft_entry("rule", chain="packet", expr=[]) for _ in range(5)],
    ]


class FirewallBoundaryTests(unittest.TestCase):
    def test_rule_batch_is_packet_scoped_ordered_and_never_broad(self) -> None:
        batch = firewall_boundary.build_batch(
            firewall_boundary.TABLE, "br-fpro001", "172.31.253.0/24"
        )
        lines = batch.splitlines()
        self.assertEqual(lines[0], f"add table inet {firewall_boundary.TABLE}")
        self.assertIn('iifname "br-fpro001" oifname "br-fpro001" ip saddr 172.31.253.0/24 ip daddr 172.31.253.0/24 accept', batch)
        self.assertIn("ct state established,related accept", batch)
        self.assertLess(batch.index("established,related accept"), batch.index("packet_input_deny drop"))
        self.assertLess(batch.index('oifname "br-fpro001"'), batch.index("packet_forward_deny drop"))
        for forbidden in ("flush ruleset", "flush table", "policy drop", "delete chain", "delete rule"):
            self.assertNotIn(forbidden, batch)
        self.assertEqual(batch.count(" iifname "), 5)
        self.assertEqual(batch.count("172.31.253.0/24"), 6)

    def test_backend_tool_and_privilege_absence_fail_before_mutation(self) -> None:
        with mock.patch.object(firewall_boundary.shutil, "which", return_value=None):
            with self.assertRaisesRegex(firewall_boundary.BoundaryError, "FIREWALL_TOOL_UNAVAILABLE"):
                firewall_boundary.locate_tools()
        denied = subprocess.CompletedProcess([], 1, stdout="", stderr="denied")
        with mock.patch.object(firewall_boundary, "locate_tools", return_value=("sudo", "nft")), mock.patch.object(
            firewall_boundary.shutil, "which", return_value="iptables"
        ), mock.patch.object(firewall_boundary, "_run", return_value=denied):
            with self.assertRaisesRegex(firewall_boundary.BoundaryError, "FIREWALL_PRIVILEGE_UNAVAILABLE"):
                firewall_boundary.privileged_prefix()
        success = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        nft_version = subprocess.CompletedProcess([], 0, stdout="nftables v1.0.9 (stable)\n", stderr="")
        legacy = subprocess.CompletedProcess([], 0, stdout="iptables v1.8.10 (legacy)\n", stderr="")
        with mock.patch.object(firewall_boundary, "locate_tools", return_value=("sudo", "nft")), mock.patch.object(
            firewall_boundary.shutil, "which", return_value="iptables"
        ), mock.patch.object(firewall_boundary, "_run", side_effect=[success, nft_version, legacy]):
            with self.assertRaisesRegex(firewall_boundary.BoundaryError, "FIREWALL_BACKEND_AMBIGUOUS"):
                firewall_boundary.privileged_prefix()

    def test_canonical_foreign_preimage_ignores_only_dynamic_metadata(self) -> None:
        first = [
            {"metainfo": {"version": "1"}},
            {"rule": {"family": "ip", "table": "foreign", "chain": "x", "handle": 1, "counter": {"packets": 2, "bytes": 9}}},
        ]
        second = [
            {"metainfo": {"version": "2"}},
            {"rule": {"family": "ip", "table": "foreign", "chain": "x", "handle": 99, "counter": {"packets": 200, "bytes": 900}}},
        ]
        self.assertEqual(
            firewall_boundary.canonical_snapshot(first),
            firewall_boundary.canonical_snapshot(second),
        )

    def test_install_rejects_collision_and_atomic_check_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            with mock.patch.object(firewall_boundary, "privileged_prefix", return_value=(["nft"], "nftables-v1")), mock.patch.object(
                firewall_boundary, "read_ruleset", return_value=owned_firewall_entries()
            ):
                with self.assertRaisesRegex(firewall_boundary.BoundaryError, "FIREWALL_TABLE_COLLISION"):
                    firewall_boundary.install(ledger, "br-fpro001", "172.31.253.0/24")
            foreign = [{"table": {"family": "ip", "name": "foreign"}}]
            failed = subprocess.CompletedProcess([], 1, stdout="", stderr="invalid")
            with mock.patch.object(firewall_boundary, "privileged_prefix", return_value=(["nft"], "nftables-v1")), mock.patch.object(
                firewall_boundary, "read_ruleset", return_value=foreign
            ), mock.patch.object(firewall_boundary, "_run", return_value=failed):
                with self.assertRaisesRegex(firewall_boundary.BoundaryError, "FIREWALL_ATOMIC_CHECK_FAILED"):
                    firewall_boundary.install(ledger, "br-fpro001", "172.31.253.0/24")
            self.assertFalse(ledger.exists())

    def test_atomic_install_and_exact_foreign_preservation(self) -> None:
        foreign = [{"table": {"family": "ip", "name": "foreign"}}]
        success = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            with mock.patch.object(firewall_boundary, "privileged_prefix", return_value=(["nft"], "nftables-v1")), mock.patch.object(
                firewall_boundary, "read_ruleset", side_effect=[foreign, foreign + owned_firewall_entries()]
            ), mock.patch.object(firewall_boundary, "_run", return_value=success), contextlib.redirect_stdout(io.StringIO()):
                firewall_boundary.install(ledger, "br-fpro001", "172.31.253.0/24")
            saved = firewall_boundary.read_ledger(ledger)
            self.assertTrue(saved["installed"])
            self.assertRegex(saved["owned_sha256"], r"^[0-9a-f]{64}$")
            expected_mode = "0o666" if os.name == "nt" else "0o600"
            self.assertEqual(oct(ledger.stat().st_mode & 0o777), expected_mode)

    def test_apply_failure_and_foreign_drift_retain_cleanup_ledger(self) -> None:
        foreign = [{"table": {"family": "ip", "name": "foreign"}}]
        changed = foreign + [{"chain": {"family": "ip", "table": "foreign", "name": "changed"}}]
        success = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        failed = subprocess.CompletedProcess([], 1, stdout="", stderr="rejected")
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            with mock.patch.object(firewall_boundary, "privileged_prefix", return_value=(["nft"], "nftables-v1")), mock.patch.object(
                firewall_boundary, "read_ruleset", return_value=foreign
            ), mock.patch.object(firewall_boundary, "_run", side_effect=[success, failed]):
                with self.assertRaisesRegex(firewall_boundary.BoundaryError, "FIREWALL_ATOMIC_INSTALL_FAILED"):
                    firewall_boundary.install(ledger, "br-fpro001", "172.31.253.0/24")
            self.assertTrue(ledger.exists())
            ledger.unlink()
            with mock.patch.object(firewall_boundary, "privileged_prefix", return_value=(["nft"], "nftables-v1")), mock.patch.object(
                firewall_boundary, "read_ruleset", side_effect=[foreign, changed + owned_firewall_entries()]
            ), mock.patch.object(firewall_boundary, "_run", return_value=success):
                with self.assertRaisesRegex(firewall_boundary.BoundaryError, "FIREWALL_FOREIGN_STATE_DRIFT"):
                    firewall_boundary.install(ledger, "br-fpro001", "172.31.253.0/24")
            self.assertTrue(ledger.exists())

    def test_counter_schema_is_closed_and_exact(self) -> None:
        entries = owned_firewall_entries()
        entries[1]["counter"]["packets"] = 7
        self.assertEqual(
            firewall_boundary.counter_packets(entries, firewall_boundary.INPUT_COUNTER), 7
        )
        entries.append(nft_entry("counter", name=firewall_boundary.INPUT_COUNTER, packets=8, bytes=0))
        with self.assertRaisesRegex(firewall_boundary.BoundaryError, "FIREWALL_COUNTER_INVALID"):
            firewall_boundary.counter_packets(entries, firewall_boundary.INPUT_COUNTER)

    def test_exact_atomic_rollback_and_duplicate_cleanup(self) -> None:
        foreign = [{"table": {"family": "ip", "name": "foreign"}}]
        pre_sha, pre_counts = firewall_boundary.canonical_snapshot(foreign)
        success = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            firewall_boundary.write_ledger(
                ledger,
                {
                    "schema": firewall_boundary.SCHEMA,
                    "table": firewall_boundary.TABLE,
                    "interface": "br-fpro001",
                    "subnet": "172.31.253.0/24",
                    "preimage_sha256": pre_sha,
                    "preimage_counts": pre_counts,
                    "installed": True,
                    "owned_sha256": "a" * 64,
                },
            )
            with mock.patch.object(firewall_boundary, "privileged_prefix", return_value=(["nft"], "nftables-v1")), mock.patch.object(
                firewall_boundary, "read_ruleset", side_effect=[foreign + owned_firewall_entries(), foreign]
            ), mock.patch.object(firewall_boundary, "_run", return_value=success), contextlib.redirect_stdout(io.StringIO()):
                firewall_boundary.remove(ledger)
            self.assertFalse(ledger.exists())
            with mock.patch.object(firewall_boundary, "privileged_prefix", return_value=(["nft"], "nftables-v1")), mock.patch.object(
                firewall_boundary, "read_ruleset", return_value=foreign
            ), contextlib.redirect_stdout(io.StringIO()):
                firewall_boundary.remove(ledger)

    def test_rollback_check_failure_retains_ledger_for_always_cleanup(self) -> None:
        foreign = [{"table": {"family": "ip", "name": "foreign"}}]
        pre_sha, pre_counts = firewall_boundary.canonical_snapshot(foreign)
        failed = subprocess.CompletedProcess([], 1, stdout="", stderr="invalid")
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            firewall_boundary.write_ledger(
                ledger,
                {
                    "schema": firewall_boundary.SCHEMA,
                    "table": firewall_boundary.TABLE,
                    "interface": "br-fpro001",
                    "subnet": "172.31.253.0/24",
                    "preimage_sha256": pre_sha,
                    "preimage_counts": pre_counts,
                    "installed": True,
                    "owned_sha256": "a" * 64,
                },
            )
            with mock.patch.object(firewall_boundary, "privileged_prefix", return_value=(["nft"], "nftables-v1")), mock.patch.object(
                firewall_boundary, "read_ruleset", return_value=foreign + owned_firewall_entries()
            ), mock.patch.object(firewall_boundary, "_run", return_value=failed):
                with self.assertRaisesRegex(firewall_boundary.BoundaryError, "FIREWALL_ATOMIC_ROLLBACK_CHECK_FAILED"):
                    firewall_boundary.remove(ledger)
            self.assertTrue(ledger.exists())

    def test_inspection_and_ledger_schema_fail_closed_without_raw_output(self) -> None:
        with self.assertRaisesRegex(firewall_boundary.BoundaryError, "FIREWALL_INSPECTION_FAILED"):
            firewall_boundary.parse_ruleset("not-json")
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            ledger.write_text('{"unexpected":true}\n', encoding="utf-8")
            with self.assertRaisesRegex(firewall_boundary.BoundaryError, "FIREWALL_LEDGER_INVALID"):
                firewall_boundary.read_ledger(ledger)


class SubnetTests(unittest.TestCase):
    def test_detects_overlap(self) -> None:
        self.assertEqual(subnets.overlaps("172.31.253.0/24", ["172.31.0.0/16"]), ["172.31.0.0/16"])

    def test_accepts_collision_free_prefix(self) -> None:
        self.assertEqual(subnets.overlaps("172.31.253.0/24", ["172.17.0.0/16", "10.0.0.0/8"]), [])


if __name__ == "__main__":
    unittest.main()
