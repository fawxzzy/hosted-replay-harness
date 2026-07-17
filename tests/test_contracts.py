from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


watch = load_module("container_watch", "scripts/container_watch.py")
subnets = load_module("check_subnet", "scripts/check_subnet.py")
db_start_log = load_module("classify_db_start_log", "scripts/classify_db_start_log.py")


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

    def test_exactly_two_digest_pulls(self) -> None:
        pulls = re.findall(r"(?m)^docker pull --platform linux/amd64 ", self.runner)
        self.assertEqual(len(pulls), 2)
        self.assertNotRegex(self.runner, r"(?m)^\s*docker (build|compose pull|image pull)\b")

    def test_contract_tests_do_not_leave_bytecode(self) -> None:
        self.assertIn('python3 -B -m unittest discover', self.runner)

    def test_exact_network_contract_and_actual_id_pass_through(self) -> None:
        for fragment in (
            "--internal",
            "--ipv6=false",
            'com.docker.network.bridge.host_binding_ipv4=127.0.0.1',
            'com.docker.network.bridge.gateway_mode_ipv4=isolated',
            '--network-id "$NETWORK_ID"',
        ):
            self.assertIn(fragment, self.runner)
        self.assertIn("record network.ipam_gateway", self.runner)
        self.assertIn("16) block PACKET_GATEWAY_REACHABLE", self.runner)
        self.assertIn(
            'timeout --signal=TERM --kill-after=10s 300s "$RUNTIME/bin/supabase"',
            self.runner,
        )
        self.assertIn('block SUPABASE_DB_START_TIMEOUT', self.runner)
        self.assertLess(
            self.runner.index('block SUPABASE_DB_START_TIMEOUT'),
            self.runner.index('project_network_count="$(docker network ls'),
        )

    def test_db_start_log_is_sanitized_before_failure_mapping(self) -> None:
        classifier = 'python3 -B "$ROOT/scripts/classify_db_start_log.py"'
        self.assertIn(classifier, self.runner)
        self.assertNotIn("--debug", self.runner)
        self.assertLess(
            self.runner.index(classifier),
            self.runner.index('block SUPABASE_DB_START_TIMEOUT'),
        )
        self.assertLess(
            self.runner.index(classifier),
            self.runner.index('block SUPABASE_DB_START_FAILED'),
        )

    def test_prohibited_operations_are_absent(self) -> None:
        prohibited = (
            r"docker\s+(system|container|volume|network|image)\s+prune",
            r"docker\s+stop\s+--all",
            r"supabase\s+(login|link|pull|push|dump)\b",
            r"--linked\b",
            r"--db-url\b",
            r"secrets:inherit",
        )
        for pattern in prohibited:
            self.assertNotRegex(self.runner, pattern)

    def test_cleanup_is_exactly_correlated(self) -> None:
        self.assertIn('label=com.supabase.cli.project=${PROJECT}', self.runner)
        self.assertIn('label=io.fawxzzy.packet=${PACKET}', self.runner)
        self.assertNotIn("docker rm -f $(docker ps", self.runner)
        self.assertNotIn("supabase stop", self.runner)
        self.assertIn('if [[ "$MODE" == "cleanup-only" ]]', self.runner)
        self.assertIn('20s docker rm -f "$id"', self.runner)
        self.assertIn('20s docker volume rm "$id"', self.runner)
        self.assertIn('20s docker network rm "$id"', self.runner)


class ResultWriterTests(unittest.TestCase):
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


class DbStartLogClassifierTests(unittest.TestCase):
    def test_every_admitted_category_has_a_synthetic_fixture(self) -> None:
        fixtures = {
            "CONFIG_VALIDATION_FAILED": b"failed to validate config\n",
            "CLI_USAGE_ERROR": b"unknown flag: --not-real\n",
            "IMAGE_RESOLUTION_FAILED": b"manifest unknown\n",
            "NETWORK_CONFIGURATION_REJECTED": b"failed to create docker network\n",
            "CONTAINER_CREATE_FAILED": b"failed to create the container\n",
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
                self.assertEqual(
                    set(result),
                    {"category", "exit_code", "raw_byte_count", "raw_line_count", "raw_sha256"},
                )

    def test_specific_network_rule_precedes_generic_daemon_rule(self) -> None:
        raw = b"Error response from daemon: failed to create docker network\n"
        self.assertEqual(
            db_start_log.classify(raw, 1)["category"],
            "NETWORK_CONFIGURATION_REJECTED",
        )

    def test_empty_log_defaults_without_leaking_input(self) -> None:
        result = db_start_log.classify(b"", 7)
        self.assertEqual(result["category"], "UNKNOWN_SANITIZED")
        self.assertEqual(result["raw_byte_count"], 0)
        self.assertEqual(result["raw_line_count"], 0)
        rendered = db_start_log.format_state_lines(result)
        self.assertEqual(len(rendered.splitlines()), 5)

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
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        self.assertEqual(len(completed.stdout.splitlines()), 5)
        self.assertIn("NETWORK_CONFIGURATION_REJECTED", completed.stdout)
        self.assertNotIn("opaque-fixture-text", completed.stdout)
        self.assertEqual(completed.stderr, "")


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
        "network_mode": network_id,
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
        role, violations = watch.classify_and_validate(data, "a" * 64, "sha256:postgres", "sha256:gotrue")
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
        role, violations = watch.classify_and_validate(data, "a" * 64, "sha256:postgres", "sha256:gotrue")
        self.assertEqual(role, "gotrue_migration")
        self.assertEqual(violations, [])

    def test_rejects_privilege_network_capability_and_socket(self) -> None:
        data = base_inspection()
        data["privileged"] = True
        data["network_mode"] = "bridge"
        data["cap_add"] = ["NET_ADMIN"]
        data["binds"] = ["/var/run/docker.sock:/var/run/docker.sock"]
        _, violations = watch.classify_and_validate(data, "a" * 64, "sha256:postgres", "sha256:gotrue")
        self.assertIn("PRIVILEGED_MODE_REJECTED", violations)
        self.assertIn("NETWORK_ATTACHMENT_MISMATCH", violations)
        self.assertIn("ADDED_CAPABILITY_REJECTED", violations)
        self.assertIn("DOCKER_SOCKET_REJECTED", violations)


class SubnetTests(unittest.TestCase):
    def test_detects_overlap(self) -> None:
        self.assertEqual(subnets.overlaps("172.31.253.0/24", ["172.31.0.0/16"]), ["172.31.0.0/16"])

    def test_accepts_collision_free_prefix(self) -> None:
        self.assertEqual(subnets.overlaps("172.31.253.0/24", ["172.17.0.0/16", "10.0.0.0/8"]), [])


if __name__ == "__main__":
    unittest.main()
