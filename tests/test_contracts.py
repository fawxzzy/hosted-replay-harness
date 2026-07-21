from __future__ import annotations

import asyncio
import copy
import contextlib
import gzip
import hashlib
import importlib.util
import inspect
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
private_netns_probe = load_module(
    "private_docker_netns_probe", "scripts/private_docker_netns_probe.py"
)


class FitnessStackIsolationContractTests(unittest.TestCase):
    FOUNDATION = "82cbd3b195dd5a07c3b437946f4404041f749508"
    ALLOWLIST = {
        ".github/workflows/fitness-full-chain-replay.yml",
        "docs/FITNESS_FULL_CHAIN_REPLAY_CONTRACT.md",
        "fitness/contract.v1.json",
        "fitness/source-manifest.v1.json",
        "fitness/receipt.schema.v1.json",
        "scripts/fitness_full_chain_replay.py",
        "scripts/fitness_replay_fixture.sql",
        "scripts/verify_fitness_replay_receipt.py",
        "tests/test_fitness_full_chain_replay.py",
        "tests/fixtures/fitness_replay_receipt.valid.json",
        "tests/test_contracts.py",
        "README.md",
    }
    IMMUTABLE = {
        ".github/workflows/containment-smoke.yml": "e0440e1748c4655c559fc82f5882e73b11c37b9cfd3e389bdbddf4ddecc7db99",
        "scripts/run-containment-smoke.sh": "d295d7964d05af58bf27c8cb9fc9caf36d83a69ee1e3a1a7fad2b09042b0317d",
        "scripts/private_docker_netns_probe.py": "83deb14241b170a1040fcf6e2582a0d252e1dd0aa29808b14d6cd3fa86b9cdbe",
        "scripts/docker_api_boundary.py": "cf6e7cca0ded8c4aeca16837f454a948a68058d35602dbb923a991ee70b32f82",
        "scripts/write_result.py": "883c2a6b4ecb9cc26b5bd025d1c6e0637d844a76f1dfb58947e6bee79fd8d6d6",
        "pins.json": "fe6105e121af3347a2de2494330d1e793a7bc3634f9d3d95964f6593ea990f50",
        "supabase/config.toml": "1b955c23161259dd41f3849f261bab41525b5ffeca83ab3074e44c5cc18ac0c6",
    }

    def test_stack_is_descended_from_exact_foundation(self) -> None:
        result = subprocess.run(
            ["git", "merge-base", "--is-ancestor", self.FOUNDATION, "HEAD"],
            cwd=ROOT, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0)

    def test_cumulative_and_worktree_scope_never_exceeds_allowlist(self) -> None:
        committed = subprocess.run(
            ["git", "diff", "--name-only", f"{self.FOUNDATION}..HEAD"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout.splitlines()
        status = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout.splitlines()
        worktree = []
        for line in status:
            path = line[3:]
            if " -> " in path:
                path = path.split(" -> ", 1)[1]
            worktree.append(path.replace("\\", "/"))
        self.assertTrue(set(committed) | set(worktree))
        self.assertLessEqual(set(committed) | set(worktree), self.ALLOWLIST)

    def test_generic_containment_foundation_is_byte_identical(self) -> None:
        for relative, expected in self.IMMUTABLE.items():
            with self.subTest(path=relative):
                actual = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
                self.assertEqual(actual, expected)


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

    def test_manual_workflow_selects_only_the_fixed_default_mode(self) -> None:
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

    @classmethod
    def runner_functions(cls, *names: str) -> str:
        functions: list[str] = []
        for name in names:
            match = re.search(
                rf"(?ms)^{re.escape(name)}\(\) \{{\n.*?^\}}\n",
                cls.runner,
            )
            assert match, name
            functions.append(match.group(0))
        return "\n".join(functions)

    @staticmethod
    def run_bash(source: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [BASH, "-c", source],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_cli_containment_acquires_only_the_two_exact_images(self) -> None:
        pulls = re.findall(r"(?m)^\s*docker pull --platform linux/amd64 ", self.runner)
        self.assertEqual(len(pulls), 2)
        self.assertNotRegex(self.runner, r"(?m)^\s*docker (build|compose pull|image pull)\b")
        first_pull = self.runner.index('docker pull --platform linux/amd64 "$POSTGRES_PULL"')
        cli_start = self.runner.index('    db start\n) >"$RAW/supabase-db-start.log"')
        self.assertLess(first_pull, cli_start)
        self.assertIn('record images.pull_count int 2', self.runner)

    def test_direct_mode_isolated_from_cli_and_uses_one_exact_target(self) -> None:
        self.assertIn('run|direct-port|firewall-rehearsal|private-netns-probe|cleanup-only', self.runner)
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

    def test_default_mode_is_fixed_private_netns_probe_without_cli(self) -> None:
        self.assertIn('MODE="${1:-private-netns-probe}"', self.runner)
        probe_function = self.runner[
            self.runner.index("run_private_docker_netns_probe() {") : self.runner.index(
                "firewall_counter_value() {"
            )
        ]
        self.assertIn('python3 -B "$helper" probe', probe_function)
        self.assertIn('sudo -n env -i', probe_function)
        self.assertIn('STANDARD_RUNNER_PRIVATE_NETNS_PASS:0:PASS', probe_function)
        self.assertIn('PRIVATE_NETNS_PROBE_DIAGNOSTIC_STOP', probe_function)
        self.assertNotIn("$RUNTIME/bin/supabase", probe_function)
        self.assertNotIn("db start", probe_function)
        self.assertNotIn('"$GOTRUE_PULL"', probe_function)
        dispatch = 'if [[ "$MODE" == "private-netns-probe" ]]; then\n  run_private_docker_netns_probe\n  exit 0\nfi'
        self.assertIn(dispatch, self.runner)
        self.assertLess(self.runner.index(dispatch), self.runner.index("mapfile -t existing_prefixes"))

    def test_firewall_rehearsal_remains_inactive_and_cli_free(self) -> None:
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
        for exact_tmpfs in (
            '--tmpfs "/var/lib/postgresql/data:rw,nosuid,nodev,noexec,size=1g"',
            '--tmpfs "/var/lib/postgresql/data:rw,nosuid,nodev,noexec,size=64m"',
        ):
            self.assertIn(exact_tmpfs, rehearsal)
        self.assertNotIn('"$GOTRUE_PULL"', rehearsal)
        self.assertNotRegex(rehearsal, r"docker (pull|build|network create|volume create)")

    def test_unpublished_container_uses_exact_legacy_tmpfs_inspection_contract(self) -> None:
        validator = self.runner[
            self.runner.index("validate_unpublished_container() {") : self.runner.index(
                "run_firewall_publication_rehearsal() {"
            )
        ]
        for fragment in (
            "{{len .HostConfig.Binds}}",
            "{{len .HostConfig.Mounts}}",
            "{{len .HostConfig.VolumesFrom}}",
            "{{len .Mounts}}",
            "{{json .HostConfig.Tmpfs}}",
            "from direct_port_probe import legacy_tmpfs_matches",
        ):
            self.assertIn(fragment, validator)
        self.assertIn("legacy_tmpfs_matches(payload, sys.argv[2])", validator)
        self.assertNotIn("expected_mount_count", validator)
        self.assertIn(
            'validate_unpublished_container "$client_id" "$NETWORK_ID" 64m FIREWALL_CLIENT',
            self.runner,
        )
        self.assertIn(
            'validate_unpublished_container "$foreign_id" bridge 1g FOREIGN_CANARY',
            self.runner,
        )

    def test_unpublished_container_uses_shared_closed_publication_shape_contract(self) -> None:
        validator = self.runner[
            self.runner.index("validate_unpublished_container() {") : self.runner.index(
                "run_firewall_publication_rehearsal() {"
            )
        ]
        self.assertIn('direct_port_probe.py" validate-unpublished', validator)
        self.assertIn('cat "$publication_state" >>"$STATE_FILE"', validator)
        self.assertIn("PUBLICATION_SHAPE_SAFE", validator)
        self.assertNotIn("len (index .NetworkSettings.Ports", validator)

    def test_firewall_client_launcher_remains_exactly_unpublished(self) -> None:
        rehearsal = self.runner[
            self.runner.index("run_firewall_publication_rehearsal() {") : self.runner.index(
                "packet_object_counts() {"
            )
        ]
        client = rehearsal[
            rehearsal.index('client_id="$(timeout') : rehearsal.index(
                'validate_unpublished_container "$client_id"'
            )
        ]
        self.assertIn('--network "$NETWORK_ID"', client)
        self.assertIn(
            '--tmpfs "/var/lib/postgresql/data:rw,nosuid,nodev,noexec,size=64m"',
            client,
        )
        self.assertIn('"$POSTGRES_PULL" sleep 300', client)
        for forbidden in ("--publish ", "--publish-all", "--expose", "-P "):
            self.assertNotIn(forbidden, client)

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

    def test_network_ipam_readback_path_is_nounset_safe(self) -> None:
        match = re.search(
            r"(?ms)^validate_network_ipam_contract\(\) \{\n.*?^\}\n",
            self.runner,
        )
        self.assertIsNotNone(match)
        assert match

        with tempfile.TemporaryDirectory() as directory:
            raw = Path(directory) / "raw"
            raw.mkdir()
            expected_path = raw / "network-ipam-after-create.json"
            script = f"""
set -u
RAW={shlex.quote(raw.as_posix())}
SUBNET=172.31.253.0/24
SUBNET_GATEWAY=172.31.253.1
docker() {{
  [[ "$1" == network && "$2" == inspect && "$3" == --format ]]
  printf '%s\n' '[{{"Subnet":"172.31.253.0/24","Gateway":"172.31.253.1"}}]'
}}
gateway_contract() {{
  [[ "$1" == readback ]]
  [[ "$2" == "$SUBNET" && "$3" == "$SUBNET_GATEWAY" ]]
  [[ "$4" == "$RAW/network-ipam-after-create.json" ]]
  grep -Fxq '[{{"Subnet":"172.31.253.0/24","Gateway":"172.31.253.1"}}]' "$4"
}}
{match.group(0)}
validate_network_ipam_contract fixture-network after-create
"""
            completed = subprocess.run(
                [BASH, "-c", script],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertNotIn("unbound variable", completed.stderr)
            self.assertTrue(expected_path.is_file())

    def test_firewall_is_prepared_before_network_and_finalized_after_network_removal(self) -> None:
        network_create = self.runner.index('NETWORK_ID="$(docker network create')
        prepare = self.runner.index('firewall_boundary.py" prepare')
        self.assertLess(prepare, network_create)
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
        boundary = self.runner[
            self.runner.index("cleanup_firewall_boundary() {") : self.runner.index("cleanup_exact() {")
        ]
        self.assertIn('firewall_boundary.py" remove', boundary)
        self.assertLess(cleanup.index("docker rm -f"), cleanup.index("docker network rm"))
        self.assertLess(cleanup.index("docker network rm"), cleanup.index("cleanup_firewall_boundary"))
        self.assertIn("FIREWALL_REMOVE_BLOCKED_BY_CONTAINER_RESIDUE", boundary)
        self.assertIn("FIREWALL_REMOVE_BLOCKED_BY_NETWORK_RESIDUE", boundary)
        self.assertLess(
            boundary.index('record cleanup.containers_before_firewall_remove'),
            boundary.index('firewall_boundary.py" remove'),
        )
        self.assertLess(
            boundary.index('record cleanup.volumes_before_firewall_remove'),
            boundary.index('firewall_boundary.py" remove'),
        )
        self.assertLess(
            boundary.index('record cleanup.networks_before_firewall_remove'),
            boundary.index('firewall_boundary.py" remove'),
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
            "same_network_resolution",
            "same_network_connect",
            "external_dns output_deny",
            "literal_ip forward_deny",
            "metadata forward_deny",
            "gateway input_deny",
            "host_listener input_deny",
            "foreign_network forward_deny",
            "docker_control_available",
            "native_listener_contract post_cli",
        ):
            self.assertIn(fragment, rehearsal)
        self.assertIn("firewall_validate_marker_deltas", self.runner)
        self.assertIn("(( marker_delta > 0 ))", self.runner)
        self.assertIn("FIREWALL_MARKER_UNEXPECTED_DELTA", self.runner)

    def test_immutable_workflow_config_pins_and_observer_hashes(self) -> None:
        expected = {
            ".github/workflows/containment-smoke.yml": "e0440e1748c4655c559fc82f5882e73b11c37b9cfd3e389bdbddf4ddecc7db99",
            "supabase/config.toml": "1b955c23161259dd41f3849f261bab41525b5ffeca83ab3074e44c5cc18ac0c6",
            "pins.json": "fe6105e121af3347a2de2494330d1e793a7bc3634f9d3d95964f6593ea990f50",
            "scripts/docker_api_boundary.py": "cf6e7cca0ded8c4aeca16837f454a948a68058d35602dbb923a991ee70b32f82",
            "scripts/firewall_boundary.py": "2670436b34c9891f0b3671c23119626ed727b6d22a15ea0e7c1435873c0594ad",
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

    def test_cleanup_mode_contract_is_closed_atomic_and_retry_bounded(self) -> None:
        functions = self.runner_functions(
            "record",
            "cleanup_mode_firewall_required",
            "cleanup_mode_payload",
            "write_cleanup_mode_contract",
            "read_cleanup_mode_contract",
            "resolve_cleanup_mode_contract",
            "retire_cleanup_mode_contract",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).as_posix()
            script = f"""set -Eeuo pipefail
ROOT={shlex.quote(root)}
mkdir -p "$ROOT/artifacts"
STATE_FILE="$ROOT/artifacts/state.tsv"
CLEANUP_MODE_FILE="$ROOT/artifacts/.cleanup-mode.tsv"
CLEANUP_MODE_STAGE_FILE="$ROOT/artifacts/.cleanup-mode.tsv.stage"
CLEANUP_MODE_SCHEMA=fawxzzy.hosted-replay-harness.cleanup-mode.v1
CLEANUP_ORIGINAL_MODE=""
CLEANUP_FIREWALL_REQUIRED=""
{functions}
stat() {{
  if [[ "$1" == -c && "$2" == %a ]]; then printf '600\n'; return 0; fi
  command stat "$@"
}}
for mode in run direct-port firewall-rehearsal private-netns-probe; do
  : >"$STATE_FILE"
  write_cleanup_mode_contract "$mode"
  resolve_cleanup_mode_contract "$mode"
  printf 'MODE:%s:%s\n' "$CLEANUP_ORIGINAL_MODE" "$CLEANUP_FIREWALL_REQUIRED"
  resolve_cleanup_mode_contract cleanup-only
  retire_cleanup_mode_contract
  ! read_cleanup_mode_contract
done
! write_cleanup_mode_contract cleanup-only
write_cleanup_mode_contract run
! resolve_cleanup_mode_contract direct-port
resolve_cleanup_mode_contract cleanup-only
sed -i 's/payload_sha256.*$/payload_sha256\tstr\t{'0' * 64}/' "$CLEANUP_MODE_FILE"
! read_cleanup_mode_contract
rm -f "$CLEANUP_MODE_FILE"
: >"$CLEANUP_MODE_STAGE_FILE"
! write_cleanup_mode_contract run
rm -f "$CLEANUP_MODE_STAGE_FILE"
"""
            completed = self.run_bash(script)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            completed.stdout.splitlines(),
            [
                "MODE:run:false",
                "MODE:direct-port:false",
                "MODE:firewall-rehearsal:true",
                "MODE:private-netns-probe:false",
            ],
        )

    def test_cleanup_docker_query_contract_distinguishes_empty_failure_partial_and_malformed(self) -> None:
        functions = self.runner_functions(
            "record",
            "record_cleanup_docker_query_failure",
            "docker_cleanup_parse_query_file",
            "docker_cleanup_query_ids",
        )

        def execute(
            resource: str,
            fail_call: int = 0,
            malformed: bool = False,
            valid_output: bool = False,
        ) -> subprocess.CompletedProcess[str]:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory).as_posix()
                script = f"""set -Eeuo pipefail
ROOT={shlex.quote(root)}
RAW="$ROOT/raw"
STATE_FILE="$ROOT/state.tsv"
mkdir -p "$RAW"
CONTAINMENT_PACKET=containment
DIRECT_PACKET=direct
FIREWALL_PACKET=firewall
PRIVATE_NETNS_PACKET=private
PROJECT=project
CLEANUP_DOCKER_QUERY_FAILURE_RECORDED=0
DOCKER_CLEANUP_QUERY_VALUES=()
DOCKER_CLEANUP_QUERY_RECORDS=()
printf '0\n' >"$ROOT/docker-call"
FAIL_CALL={fail_call}
MALFORMED={'1' if malformed else '0'}
VALID_OUTPUT={'1' if valid_output else '0'}
docker() {{
  DOCKER_CALL="$(<"$ROOT/docker-call")"
  DOCKER_CALL=$((DOCKER_CALL + 1))
  printf '%s\n' "$DOCKER_CALL" >"$ROOT/docker-call"
  if [[ "$FAIL_CALL" != 0 && "$DOCKER_CALL" == "$FAIL_CALL" ]]; then
    printf '%064d\n' 0
    return 1
  fi
  if [[ "$MALFORMED" == 1 ]]; then
    printf 'not admitted output\n'
  elif [[ "$VALID_OUTPUT" == 1 ]]; then
    printf '%064d\n' 0
  fi
}}
{functions}
set +e
docker_cleanup_query_ids {resource} FINAL_RESIDUE
rc="$?"
residue="$(find "$RAW" -maxdepth 1 -type f -name 'cleanup-docker-query.??????' | wc -l)"
printf 'RC:%s COUNT:%s CALLS:%s RESIDUE:%s\n' "$rc" "${{#DOCKER_CLEANUP_QUERY_VALUES[@]}}" "$(<"$ROOT/docker-call")" "$residue"
cat "$STATE_FILE" 2>/dev/null || true
exit "$rc"
"""
                return self.run_bash(script)

        for resource in ("CONTAINER", "VOLUME", "NETWORK"):
            for fail_call in range(1, 5):
                with self.subTest(resource=resource, kind="filter-failure", call=fail_call):
                    failed = execute(resource, fail_call=fail_call)
                    self.assertNotEqual(failed.returncode, 0)
                    self.assertIn(f"RC:1 COUNT:0 CALLS:{fail_call} RESIDUE:0", failed.stdout)
                    self.assertIn(f"cleanup.docker_query.resource\tstr\t{resource}", failed.stdout)
                    self.assertIn("cleanup.docker_query.failure_class\tstr\tCOMMAND_FAILED", failed.stdout)
                    self.assertIn("cleanup.docker_query.operation\tstr\tLIST", failed.stdout)
                    self.assertNotIn("0" * 64, failed.stdout)
            with self.subTest(resource=resource, kind="malformed"):
                malformed = execute(resource, malformed=True)
                self.assertNotEqual(malformed.returncode, 0)
                self.assertIn("MALFORMED_OUTPUT", malformed.stdout)
            with self.subTest(resource=resource, kind="successful-empty"):
                empty = execute(resource)
                self.assertEqual(empty.returncode, 0, empty.stderr)
                self.assertIn("RC:0 COUNT:0 CALLS:5 RESIDUE:0", empty.stdout)
                self.assertNotIn("cleanup.docker_query.", empty.stdout)
            with self.subTest(resource=resource, kind="cross-filter-overlap"):
                overlap = execute(resource, valid_output=True)
                self.assertEqual(overlap.returncode, 0, overlap.stderr)
                self.assertIn("RC:0 COUNT:1 CALLS:5 RESIDUE:0", overlap.stdout)

    def test_cleanup_docker_query_framing_rejects_blank_duplicate_and_ambiguous_records(self) -> None:
        functions = self.runner_functions(
            "record",
            "record_cleanup_docker_query_failure",
            "docker_cleanup_parse_query_file",
        )
        valid_a = b"a" * 64
        valid_b = b"b" * 64

        def execute(payload: bytes) -> subprocess.CompletedProcess[str]:
            with tempfile.TemporaryDirectory() as directory:
                root_path = Path(directory)
                raw = root_path / "raw"
                raw.mkdir()
                query = raw / "query.out"
                query.write_bytes(payload)
                script = f"""set -Eeuo pipefail
ROOT={shlex.quote(root_path.as_posix())}
RAW="$ROOT/raw"
STATE_FILE="$ROOT/state.tsv"
CLEANUP_DOCKER_QUERY_FAILURE_RECORDED=0
DOCKER_CLEANUP_QUERY_RECORDS=()
{functions}
set +e
docker_cleanup_parse_query_file CONTAINER FINAL_RESIDUE "$RAW/query.out"
rc="$?"
printf 'RC:%s COUNT:%s\n' "$rc" "${{#DOCKER_CLEANUP_QUERY_RECORDS[@]}}"
cat "$STATE_FILE" 2>/dev/null || true
exit "$rc"
"""
                return self.run_bash(script)

        accepted = {
            "zero-byte": b"",
            "one-record": valid_a + b"\n",
            "two-records": valid_a + b"\n" + valid_b + b"\n",
        }
        for name, payload in accepted.items():
            with self.subTest(name=name):
                result = execute(payload)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("MALFORMED_OUTPUT", result.stdout)

        rejected = {
            "one-blank": b"\n",
            "multiple-blank": b"\n\n",
            "spaces": b"   \n",
            "tabs": b"\t\n",
            "crlf-only": b"\r\n",
            "valid-crlf": valid_a + b"\r\n",
            "trailing-blank": valid_a + b"\n\n",
            "middle-blank": valid_a + b"\n\n" + valid_b + b"\n",
            "valid-plus-spaces": valid_a + b"\n \n",
            "malformed-id": b"abc\n",
            "duplicate-id": valid_a + b"\n" + valid_a + b"\n",
            "unterminated-record": valid_a,
            "nul-in-record": valid_a[:32] + b"\x00" + valid_a[32:] + b"\n",
            "invalid-byte": b"\xff\n",
        }
        for name, payload in rejected.items():
            with self.subTest(name=name):
                result = execute(payload)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("cleanup.docker_query.failure_class\tstr\tMALFORMED_OUTPUT", result.stdout)
                self.assertIn("RC:1 COUNT:0", result.stdout)

    def test_cleanup_docker_ownership_reads_are_explicit_and_fail_closed(self) -> None:
        functions = self.runner_functions(
            "record",
            "record_cleanup_docker_query_failure",
            "docker_cleanup_verify_ownership",
        )

        def execute(fail_call: int = 0, packet: str = "containment", project: str = "project") -> subprocess.CompletedProcess[str]:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory).as_posix()
                script = f"""set -Eeuo pipefail
ROOT={shlex.quote(root)}
RAW="$ROOT/raw"
STATE_FILE="$ROOT/state.tsv"
mkdir -p "$RAW"
CONTAINMENT_PACKET=containment
DIRECT_PACKET=direct
FIREWALL_PACKET=firewall
PRIVATE_NETNS_PACKET=private
PROJECT=project
CLEANUP_DOCKER_QUERY_FAILURE_RECORDED=0
printf '0\n' >"$ROOT/docker-call"
FAIL_CALL={fail_call}
docker() {{
  DOCKER_CALL="$(<"$ROOT/docker-call")"
  DOCKER_CALL=$((DOCKER_CALL + 1))
  printf '%s\n' "$DOCKER_CALL" >"$ROOT/docker-call"
  [[ "$FAIL_CALL" == 0 || "$DOCKER_CALL" != "$FAIL_CALL" ]] || return 1
  if [[ "$DOCKER_CALL" == 1 ]]; then printf '%s\n' {shlex.quote(packet)}; else printf '%s\n' {shlex.quote(project)}; fi
}}
{functions}
set +e
docker_cleanup_verify_ownership CONTAINER "$('a' * 64)" ENUMERATE
rc="$?"
printf 'RC:%s CALLS:%s\n' "$rc" "$(<"$ROOT/docker-call")"
cat "$STATE_FILE" 2>/dev/null || true
exit "$rc"
"""
                return self.run_bash(script)

        accepted = execute()
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertIn("RC:0 CALLS:2", accepted.stdout)
        for call, operation in ((1, "PACKET_LABEL_INSPECT"), (2, "PROJECT_LABEL_INSPECT")):
            with self.subTest(call=call):
                failed = execute(fail_call=call)
                self.assertNotEqual(failed.returncode, 0)
                self.assertIn(f"cleanup.docker_query.operation\tstr\t{operation}", failed.stdout)
                self.assertIn("COMMAND_FAILED", failed.stdout)
        malformed = execute(packet="unclassified-value")
        self.assertNotEqual(malformed.returncode, 0)
        self.assertIn("MALFORMED_OUTPUT", malformed.stdout)
        mismatch = execute(packet="<no value>", project="<no value>")
        self.assertNotEqual(mismatch.returncode, 0)
        self.assertIn("OWNERSHIP_MISMATCH", mismatch.stdout)

    def test_cleanup_exact_requires_successful_docker_queries_before_zero_or_firewall_removal(self) -> None:
        cleanup = self.runner_functions(
            "record",
            "record_cleanup_docker_query_failure",
            "docker_cleanup_query_ids",
            "docker_cleanup_verify_ownership",
            "cleanup_exact",
        )
        self.assertNotRegex(
            cleanup,
            r"docker (?:ps|volume ls|network ls|inspect|volume inspect|network inspect).*\|\| true",
        )
        self.assertIn("FIREWALL_REMOVE_BLOCKED_BY_DOCKER_QUERY_FAILURE", cleanup)
        self.assertIn('[[ "$cleanup_query_rc" == "0" ]] || return 1', cleanup)
        self.assertRegex(
            cleanup,
            r'if \[\[ "\$cleanup_query_rc" == "0" && -n "\$pre_firewall_container_count" '
            r'\\\n\s+&& -n "\$pre_firewall_volume_count" && -n "\$pre_firewall_network_count" \]\]; then',
        )
        self.assertEqual(cleanup.count("cleanup_query_rc=0"), 1)
        self.assertLess(
            cleanup.index("docker_cleanup_query_ids CONTAINER PRE_FIREWALL"),
            cleanup.index("cleanup_firewall_boundary"),
        )
        self.assertNotIn('record cleanup.containers_remaining int "0"', cleanup)
        self.assertNotIn('record cleanup.volumes_remaining int "0"', cleanup)
        self.assertNotIn('record cleanup.networks_remaining int "0"', cleanup)

    def test_cumulative_query_failure_always_withholds_firewall_removal(self) -> None:
        functions = self.runner_functions(
            "record",
            "record_cleanup_docker_query_failure",
            "docker_cleanup_parse_query_file",
            "docker_cleanup_query_ids",
            "docker_cleanup_verify_ownership",
            "cleanup_exact",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).as_posix()
            script = f"""set -Eeuo pipefail
ROOT={shlex.quote(root)}
MODE=firewall-rehearsal
DB_PORT=56422
CONTAINMENT_PACKET=containment
DIRECT_PACKET=direct
FIREWALL_PACKET=firewall
PRIVATE_NETNS_PACKET=private
PROJECT=project
FIREWALL_LEDGER="$ROOT/firewall-ledger"
LISTENER_SNAPSHOT_COUNT=0
LISTENER_FAILURE_CODE=""
LISTENER_LAST_PHASE=""
SCENARIO=EMPTY
FAIL_AT=0
DOCKER_CALL=0
CURRENT_CASE=""
docker() {{
  DOCKER_CALL=$((DOCKER_CALL + 1))
  if [[ "$FAIL_AT" != 0 && "$DOCKER_CALL" == "$FAIL_AT" ]]; then return 1; fi
  if [[ "$SCENARIO" == OWNERSHIP_FAIL || "$SCENARIO" == OWNERSHIP_MISMATCH ]]; then
    if [[ "$1" == ps && "$DOCKER_CALL" == 1 ]]; then printf '%064d\\n' 0; return 0; fi
    if [[ "$1" == inspect ]]; then
      if [[ "$SCENARIO" == OWNERSHIP_FAIL && "$DOCKER_CALL" == 5 ]]; then return 1; fi
      if [[ "$SCENARIO" == OWNERSHIP_MISMATCH ]]; then printf '<no value>\\n'; else printf 'project\\n'; fi
    fi
  fi
}}
resolve_cleanup_mode_contract() {{ return 0; }}
stop_docker_api_observer() {{ return 0; }}
stop_watcher() {{ return 0; }}
stop_host_test_listener() {{ return 0; }}
cleanup_firewall_boundary() {{ printf 'CALLED\\n' >"$ROOT/$CURRENT_CASE.firewall"; return 0; }}
capture_listener_snapshot() {{ LISTENER_SNAPSHOT_COUNT=0; return 0; }}
native_listener_contract() {{ return 0; }}
timeout() {{ return 1; }}
{functions}
run_case() {{
  CURRENT_CASE="$1"
  SCENARIO="$2"
  FAIL_AT="$3"
  DOCKER_CALL=0
  CLEANUP_DOCKER_QUERY_FAILURE_RECORDED=0
  DOCKER_CLEANUP_QUERY_VALUES=()
  DOCKER_CLEANUP_QUERY_RECORDS=()
  RAW="$ROOT/$CURRENT_CASE.raw"
  STATE_FILE="$ROOT/$CURRENT_CASE.tsv"
  mkdir -p "$RAW"
  if cleanup_exact; then return 90; fi
  [[ ! -e "$ROOT/$CURRENT_CASE.firewall" ]]
  grep -Fq $'cleanup.firewall.failure_code\\tstr\\tFIREWALL_REMOVE_BLOCKED_BY_DOCKER_QUERY_FAILURE' "$STATE_FILE"
}}
for fail_at in 1 5 9 13 17 21; do run_case "LIST-$fail_at" EMPTY "$fail_at"; done
run_case OWNERSHIP-FAIL OWNERSHIP_FAIL 0
run_case OWNERSHIP-MISMATCH OWNERSHIP_MISMATCH 0
printf 'CASES:8\\n'
"""
            completed = subprocess.run(
                [BASH],
                input=script,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "CASES:8\n")

    def test_mode_aware_firewall_cleanup_never_uses_evidence_absence_as_the_selector(self) -> None:
        functions = self.runner_functions("record", "cleanup_firewall_boundary")

        def execute(
            original_mode: str,
            required: str,
            helper_rc: int = 0,
            mode_rc: int = 0,
            precontainers: int = 0,
            prevolumes: int = 0,
            prenetworks: int = 0,
            create_ledger: bool = False,
        ) -> subprocess.CompletedProcess[str]:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory).as_posix()
                script = f"""set -Eeuo pipefail
ROOT={shlex.quote(root)}
mkdir -p "$ROOT/artifacts" "$ROOT/raw" "$ROOT/runtime"
STATE_FILE="$ROOT/state.tsv"
RAW="$ROOT/raw"
FIREWALL_LEDGER="$ROOT/artifacts/ledger.json"
FIREWALL_COMPLETION="$FIREWALL_LEDGER.restoration-complete"
FIREWALL_COMPLETION_STAGE="$ROOT/artifacts/.ledger.json.restoration-complete.stage"
FIREWALL_ROLLBACK_RECEIPT="$ROOT/artifacts/rollback.tsv"
FIREWALL_STATE_FILE="$ROOT/runtime/firewall.tsv"
MODE={'cleanup-only' if original_mode != 'firewall-rehearsal' else 'firewall-rehearsal'}
CLEANUP_ORIGINAL_MODE={shlex.quote(original_mode)}
CLEANUP_FIREWALL_REQUIRED={shlex.quote(required)}
HELPER_RC={helper_rc}
python3() {{
  printf 'CALL\n' >>"$ROOT/helper.calls"
  if [[ "$HELPER_RC" == 0 ]]; then
    printf 'firewall.rollback_idempotent\tbool\ttrue\n' >"$FIREWALL_STATE_FILE"
  else
    printf 'firewall.failure_code\tstr\tFIREWALL_RESTORATION_EVIDENCE_MISSING\n' >"$FIREWALL_STATE_FILE"
  fi
  return "$HELPER_RC"
}}
{functions}
{'touch "$FIREWALL_LEDGER"' if create_ledger else ':'}
set +e
cleanup_firewall_boundary {precontainers} {mode_rc} {prenetworks} {prevolumes}
rc="$?"
if [[ -f "$ROOT/helper.calls" ]]; then
  printf 'CALLS:%s\n' "$(wc -l <"$ROOT/helper.calls")"
else
  printf 'CALLS:0\n'
fi
cat "$STATE_FILE"
exit "$rc"
"""
                return self.run_bash(script)

        for mode in ("run", "direct-port", "private-netns-probe"):
            with self.subTest(mode=mode):
                result = execute(mode, "false")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("CALLS:0", result.stdout)
                self.assertIn(f"cleanup.firewall.skipped_mode\tstr\t{mode}", result.stdout)
        firewall = execute("firewall-rehearsal", "true")
        self.assertEqual(firewall.returncode, 0, firewall.stderr)
        self.assertIn("CALLS:1", firewall.stdout)
        missing = execute("firewall-rehearsal", "true", helper_rc=1)
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("FIREWALL_RESTORATION_EVIDENCE_MISSING", missing.stdout)
        mismatch = execute("run", "false", create_ledger=True)
        self.assertNotEqual(mismatch.returncode, 0)
        self.assertIn("CLEANUP_MODE_FIREWALL_STATE_MISMATCH", mismatch.stdout)
        invalid = execute("run", "false", mode_rc=1)
        self.assertNotEqual(invalid.returncode, 0)
        self.assertIn("CLEANUP_MODE_CONTRACT_INVALID", invalid.stdout)
        residue = execute("firewall-rehearsal", "true", precontainers=1)
        self.assertNotEqual(residue.returncode, 0)
        self.assertIn("FIREWALL_REMOVE_BLOCKED_BY_CONTAINER_RESIDUE", residue.stdout)
        network_residue = execute("firewall-rehearsal", "true", prenetworks=1)
        self.assertNotEqual(network_residue.returncode, 0)
        self.assertIn("CALLS:0", network_residue.stdout)
        self.assertIn("FIREWALL_REMOVE_BLOCKED_BY_NETWORK_RESIDUE", network_residue.stdout)
        volume_residue = execute("firewall-rehearsal", "true", prevolumes=1)
        self.assertNotEqual(volume_residue.returncode, 0)
        self.assertIn("CALLS:0", volume_residue.stdout)
        self.assertIn("FIREWALL_REMOVE_BLOCKED_BY_VOLUME_RESIDUE", volume_residue.stdout)

    def test_finalize_result_writer_failure_blocks_pass_and_preserves_prior_failure(self) -> None:
        functions = self.runner_functions("record", "current_failure_code", "finalize")

        def execute(smoke_passed: int, initial_failure: str, original_rc: int) -> subprocess.CompletedProcess[str]:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory).as_posix()
                script = f"""set -uo pipefail
ROOT={shlex.quote(root)}
mkdir -p "$ROOT/artifacts" "$ROOT/raw" "$ROOT/runtime"
STATE_FILE="$ROOT/artifacts/.state.tsv"
RESULT_FILE="$ROOT/artifacts/result.json"
RESULT_STAGE_FILE="$ROOT/artifacts/result.stage"
RAW="$ROOT/raw"
RUNTIME="$ROOT/runtime"
AUDIT_FILE="$RUNTIME/audit"
MODE=direct-port
FINALIZING=0
SMOKE_PASSED={smoke_passed}
NETWORK_ID=""
printf 'status\tstr\tBLOCKED\nfailure.code\tstr\t{initial_failure}\nfailure.detail\tstr\tfrozen\n' >"$STATE_FILE"
{functions}
current_listener_phase() {{ :; }}
listener_phase_is_unexpected() {{ return 1; }}
cleanup_exact() {{ return 0; }}
cleanup_packet_scratch() {{ return 0; }}
network_contract_code() {{ printf 'PASS\n'; }}
publish_result_receipt() {{ return 1; }}
set +e
(
  if [[ {original_rc} == 0 ]]; then true; else false; fi
  finalize
)
rc="$?"
cat "$STATE_FILE" >&2
exit "$rc"
"""
                return self.run_bash(script)

        passing = execute(1, "HARNESS_INTERRUPTED", 0)
        self.assertNotEqual(passing.returncode, 0)
        self.assertNotIn("DIRECT_DOCKER_PORT_PATH_PASS", passing.stdout)
        self.assertIn("BLOCKED: RESULT_RECEIPT_PUBLICATION_FAILED", passing.stdout)
        self.assertIn("failure.code\tstr\tRESULT_RECEIPT_PUBLICATION_FAILED", passing.stderr)
        self.assertNotRegex(passing.stdout, r"(?m)^DIRECT_DOCKER_PORT_PATH_PASS$")
        blocked = execute(0, "DATABASE_HEALTH_FAILED", 1)
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("BLOCKED: RESULT_RECEIPT_PUBLICATION_FAILED", blocked.stdout)
        failure_codes = re.findall(r"(?m)^failure\.code\tstr\t(\S+)$", blocked.stderr)
        self.assertEqual(failure_codes, ["DATABASE_HEALTH_FAILED"])
        self.assertIn(
            "receipt.publication_failure_code\tstr\tRESULT_RECEIPT_PUBLICATION_FAILED",
            blocked.stderr,
        )

    def test_cleanup_recovery_writer_failure_is_nonzero_and_retains_state(self) -> None:
        functions = self.runner_functions("record", "current_failure_code", "cleanup_only")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).as_posix()
            script = f"""set -uo pipefail
ROOT={shlex.quote(root)}
RUNTIME="$ROOT/runtime"
RAW="$RUNTIME/raw"
RUNTIME_HOME="$RUNTIME/home"
PROJECT_DIR="$RUNTIME/project"
STATE_FILE="$ROOT/artifacts/.state.tsv"
CLEANUP_STATE_FILE="$ROOT/artifacts/.cleanup-state.tsv"
RESULT_FILE="$ROOT/artifacts/result.json"
RESULT_STAGE_FILE="$ROOT/artifacts/result.stage"
AUDIT_FILE="$RUNTIME/audit"
FIREWALL_ROLLBACK_RECEIPT="$ROOT/artifacts/rollback.tsv"
RESULT_PROFILE=""
mkdir -p "$ROOT/artifacts"
printf 'status\tstr\tBLOCKED\nfailure.code\tstr\tDATABASE_HEALTH_FAILED\nreceipt.publication_failure_code\tstr\tRESULT_RECEIPT_PUBLICATION_FAILED\n' >"$STATE_FILE"
{functions}
cleanup_exact() {{ return 0; }}
cleanup_packet_scratch() {{ return 0; }}
publish_result_receipt() {{ return 1; }}
retire_cleanup_mode_contract() {{ printf 'RETIRED\n'; }}
result_receipt_status() {{ printf 'BLOCKED\n'; }}
cleanup_only
"""
            completed = self.run_bash(script)
            state_path = Path(directory) / "artifacts" / ".state.tsv"
            state_retained = state_path.is_file()
            state_text = state_path.read_text(encoding="utf-8") if state_retained else ""
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn("CLEANUP_EXACT_PASS", completed.stdout)
        self.assertNotIn("RETIRED", completed.stdout)
        self.assertTrue(state_retained)
        self.assertIn("failure.code\tstr\tDATABASE_HEALTH_FAILED", state_text)
        self.assertIn("receipt.recovery_attempted\tbool\ttrue", state_text)

    def test_cleanup_writer_failure_preserves_blocked_receipt_and_removes_pass_receipt(self) -> None:
        functions = self.runner_functions(
            "record",
            "current_failure_code",
            "cleanup_only",
        )

        def execute(status: str, failure: dict[str, str] | None) -> tuple[subprocess.CompletedProcess[str], bool, str]:
            with tempfile.TemporaryDirectory() as directory:
                root_path = Path(directory)
                root = root_path.as_posix()
                artifacts = root_path / "artifacts"
                artifacts.mkdir()
                result_path = artifacts / "result.json"
                schema = (
                    "fawxzzy.hosted-replay-harness.direct-port-result.v1"
                    if status == "DIRECT_DOCKER_PORT_PATH_PASS"
                    else "fawxzzy.hosted-replay-harness.result.v1"
                )
                result_path.write_text(
                    json.dumps({"schema": schema, "status": status, "failure": failure}),
                    encoding="utf-8",
                )
                script = f"""set -uo pipefail
ROOT={shlex.quote(root)}
RUNTIME="$ROOT/runtime"
RAW="$RUNTIME/raw"
RUNTIME_HOME="$RUNTIME/home"
PROJECT_DIR="$RUNTIME/project"
STATE_FILE="$ROOT/artifacts/.state.tsv"
CLEANUP_STATE_FILE="$ROOT/artifacts/.cleanup-state.tsv"
RESULT_FILE="$ROOT/artifacts/result.json"
RESULT_STAGE_FILE="$ROOT/artifacts/result.stage"
AUDIT_FILE="$RUNTIME/audit"
FIREWALL_ROLLBACK_RECEIPT="$ROOT/artifacts/rollback.tsv"
RESULT_PROFILE=""
EXISTING_STATUS={shlex.quote(status)}
EXISTING_FAILURE={shlex.quote((failure or {}).get('code', ''))}
{functions}
cleanup_exact() {{ return 0; }}
cleanup_packet_scratch() {{ return 0; }}
publish_result_receipt() {{ return 1; }}
retire_cleanup_mode_contract() {{ printf 'RETIRED\n'; }}
result_receipt_status() {{ printf '%s\n' "$EXISTING_STATUS"; }}
result_receipt_failure_code() {{ printf '%s\n' "$EXISTING_FAILURE"; }}
cleanup_only
"""
                completed = self.run_bash(script)
                retained = result_path.is_file()
                state_path = artifacts / ".cleanup-state.tsv"
                state = state_path.read_text(encoding="utf-8") if state_path.is_file() else ""
                return completed, retained, state

        blocked, blocked_retained, blocked_state = execute(
            "BLOCKED",
            {"code": "DATABASE_HEALTH_FAILED", "detail": "sanitized"},
        )
        self.assertNotEqual(blocked.returncode, 0)
        self.assertTrue(blocked_retained)
        self.assertIn("failure.code\tstr\tDATABASE_HEALTH_FAILED", blocked_state)
        self.assertIn("receipt.original_failure_code\tstr\tDATABASE_HEALTH_FAILED", blocked_state)
        passed, pass_retained, pass_state = execute("DIRECT_DOCKER_PORT_PATH_PASS", None)
        self.assertNotEqual(passed.returncode, 0)
        self.assertFalse(pass_retained)
        self.assertIn("failure.code\tstr\tRESULT_RECEIPT_PUBLICATION_FAILED", pass_state)
        self.assertNotIn("CLEANUP_EXACT_PASS", passed.stdout)

    def test_cleanup_without_prior_receipt_publishes_blocked_replace_even_when_cleanup_fails(self) -> None:
        functions = self.runner_functions("record", "current_failure_code", "cleanup_only")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).as_posix()
            script = f"""set -uo pipefail
ROOT={shlex.quote(root)}
RUNTIME="$ROOT/runtime"
RAW="$RUNTIME/raw"
RUNTIME_HOME="$RUNTIME/home"
PROJECT_DIR="$RUNTIME/project"
STATE_FILE="$ROOT/artifacts/.state.tsv"
CLEANUP_STATE_FILE="$ROOT/artifacts/.cleanup-state.tsv"
RESULT_FILE="$ROOT/artifacts/result.json"
RESULT_STAGE_FILE="$ROOT/artifacts/result.stage"
AUDIT_FILE="$RUNTIME/audit"
FIREWALL_ROLLBACK_RECEIPT="$ROOT/artifacts/rollback.tsv"
RESULT_PROFILE=""
{functions}
cleanup_exact() {{ return 1; }}
cleanup_packet_scratch() {{ return 0; }}
publish_result_receipt() {{ printf 'PUBLISH:%s:%s\n' "$1" "$2"; return 0; }}
retire_cleanup_mode_contract() {{ printf 'RETIRED\n'; }}
result_receipt_status() {{ return 1; }}
cleanup_only
"""
            completed = self.run_bash(script)
            state_path = Path(directory) / "artifacts" / ".cleanup-state.tsv"
            state = state_path.read_text(encoding="utf-8") if state_path.is_file() else ""
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("PUBLISH:BLOCKED:replace", completed.stdout)
        self.assertNotIn("CLEANUP_EXACT_PASS", completed.stdout)
        self.assertNotIn("RETIRED", completed.stdout)
        self.assertIn("failure.code\tstr\tCLEANUP_RESIDUE", state)

    def test_result_receipt_publication_is_staged_validated_and_fail_closed(self) -> None:
        publisher = self.runner_functions(
            "publish_result_receipt",
        )
        self.assertIn('RESULT_STAGE_FILE="$ROOT/artifacts/.containment-smoke.json.stage"', self.runner)
        self.assertIn('sanitize_public_result_receipt "$RESULT_STAGE_FILE" "$expected_status" "$writer_rc"', publisher)
        self.assertIn('published_status="$(public_receipt_tool status "$RESULT_STAGE_FILE")"', publisher)
        self.assertIn('validate_result_receipt "$RESULT_STAGE_FILE" "$published_status"', publisher)
        self.assertIn('mv -f -- "$RESULT_STAGE_FILE" "$RESULT_FILE"', publisher)
        self.assertIn('validate_result_receipt "$RESULT_FILE" "$published_status"', publisher)
        self.assertIn('rm -f -- "$RESULT_FILE"', publisher)
        self.assertIn("# BEGIN PUBLIC_RECEIPT_TOOL", self.runner)
        self.assertIn("mandatory leak scan rejected", self.runner)
        finalize = self.runner_functions("finalize")
        self.assertLess(
            finalize.index('publish_result_receipt "$final_status" replace'),
            finalize.index("printf '%s\\n' \"$final_status\""),
        )
        self.assertIn("RESULT_RECEIPT_PUBLICATION_FAILED", finalize)
        self.assertIn('[[ "$receipt_failure" != "0" ]] || rm -f -- "$STATE_FILE"', finalize)

    def test_packet_scratch_proof_is_closed_sanitized_and_precedes_receipt(self) -> None:
        scratch_match = re.search(
            r"(?ms)^# BEGIN PACKET_SCRATCH_FUNCTION\n(?P<source>.*?)^# END PACKET_SCRATCH_FUNCTION$",
            self.runner,
        )
        self.assertIsNotNone(scratch_match)
        cleanup_source = self.runner_functions("record") + "\n" + scratch_match.group("source")
        self.assertIn("fawxzzy.hosted-replay-harness.packet-scratch-proof.v1", self.runner)
        self.assertIn("stat.S_ISLNK", cleanup_source)
        self.assertIn("FILE_ATTRIBUTE_REPARSE_POINT", cleanup_source)
        self.assertIn("ownership_mismatch_count", cleanup_source)
        self.assertIn("allowlist_mismatch_count", cleanup_source)
        self.assertIn("os.path.commonpath", cleanup_source)
        self.assertNotIn('rm -rf -- "$RUNTIME"', self.runner)
        for function_name, phase in (("finalize", "primary"), ("cleanup_only", "cleanup")):
            source = self.runner_functions(function_name)
            self.assertLess(
                source.index(f"cleanup_packet_scratch {phase}"),
                source.index("publish_result_receipt"),
            )
        if os.name == "nt":
            # Git Bash cannot pass its POSIX-translated private paths to the
            # native Python used by this repository. The exact same fixture is
            # executed on the required Ubuntu hosted runner.
            return

        def execute(*, audit: bool = True, unexpected: bool = False) -> tuple[subprocess.CompletedProcess[str], bool, bool, str]:
            with tempfile.TemporaryDirectory() as directory:
                root_path = Path(directory)
                runtime = root_path / ".smoke-runtime"
                raw = runtime / "raw"
                artifacts = root_path / "artifacts"
                raw.mkdir(parents=True)
                artifacts.mkdir()
                (raw / "sanitized.log").write_text("private\n", encoding="utf-8")
                if audit:
                    (runtime / "container-audit.jsonl").write_text("", encoding="utf-8")
                if unexpected:
                    (runtime / "unowned-entry").write_text("blocked\n", encoding="utf-8")
                python_path = Path(sys.executable).as_posix()
                if re.match(r"^[A-Za-z]:/", python_path):
                    python_path = f"/{python_path[0].lower()}{python_path[2:]}"
                script = f"""set -Eeuo pipefail
ROOT={shlex.quote(root_path.as_posix())}
RUNTIME="$ROOT/.smoke-runtime"
AUDIT_FILE="$RUNTIME/container-audit.jsonl"
STATE_FILE="$ROOT/artifacts/state.tsv"
SCRATCH_AUDIT_STAGE_FILE="$ROOT/artifacts/.packet-scratch-audit.jsonl.stage"
SCRATCH_PROOF_STAGE_FILE="$ROOT/artifacts/.packet-scratch-proof.tsv.stage"
SCRATCH_PROOF_SCHEMA=fawxzzy.hosted-replay-harness.packet-scratch-proof.v1
PACKET=FP-HOSTED-REPLAY-FIREWALL-PUBLICATION-REHEARSAL-001
python3() {{ {shlex.quote(python_path)} "$@"; }}
{cleanup_source}
set +e
cleanup_packet_scratch primary
rc="$?"
cat "$STATE_FILE" 2>/dev/null || true
exit "$rc"
"""
                completed = self.run_bash(script)
                state_path = artifacts / "state.tsv"
                state = state_path.read_text(encoding="utf-8") if state_path.is_file() else ""
                return (
                    completed,
                    runtime.exists(),
                    (artifacts / ".packet-scratch-audit.jsonl.stage").is_file(),
                    state,
                )

        success, runtime_exists, audit_staged, state = execute()
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertFalse(runtime_exists)
        self.assertTrue(audit_staged)
        self.assertIn("scratch.primary.proof_status\tstr\tPASS", state)
        self.assertIn("scratch.primary.remaining_entry_count\tint\t0", state)
        self.assertNotIn(str(Path(tempfile.gettempdir())), state)

        missing, runtime_exists, audit_staged, state = execute(audit=False)
        self.assertNotEqual(missing.returncode, 0)
        self.assertTrue(runtime_exists)
        self.assertFalse(audit_staged)
        self.assertIn("scratch.primary.proof_status\tstr\tAUDIT_INVALID", state)

        rejected, runtime_exists, audit_staged, state = execute(unexpected=True)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertTrue(runtime_exists)
        self.assertTrue(audit_staged)
        self.assertIn("scratch.primary.allowlist_mismatch_count\tint\t1", state)
        self.assertIn("scratch.primary.proof_status\tstr\tALLOWLIST_REJECTED", state)

    def test_public_receipt_is_closed_canonical_and_safely_diagnostic(self) -> None:
        marker = re.search(
            r"(?ms)^# BEGIN PUBLIC_RECEIPT_TOOL\n(?P<source>.*?)^# END PUBLIC_RECEIPT_TOOL$",
            self.runner,
        )
        self.assertIsNotNone(marker)
        public_tool = marker.group("source")
        public_python = public_tool.split("<<'PY'\n", 1)[1].rsplit("\nPY\n}", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state.tsv"
            result = root / "result.json"
            state.write_bytes((
                "status\tstr\tBLOCKED\n"
                "failure.code\tstr\tPACKET_SCRATCH_PROOF_FAILED\n"
                "failure.detail\tstr\tprivate detail never published\n"
                "cleanup.containers_remaining\tint\t0\n"
                "cleanup.volumes_remaining\tint\t0\n"
                "cleanup.networks_remaining\tint\t0\n"
                "cleanup.listeners_remaining\tint\t0\n"
                "scratch.primary.proof_status\tstr\tPASS\n"
                "scratch.primary.remaining_entry_count\tint\t0\n"
            ).encode("utf-8"))
            completed = subprocess.run(
                [
                    sys.executable, "-B", "-", "build", str(result), "BLOCKED", "0",
                    "run", str(ROOT), str(state),
                ],
                input=public_python,
                capture_output=True,
                text=True,
                check=False,
            )
            serialized = result.read_text(encoding="utf-8") if result.exists() else ""
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "")
        receipt = json.loads(serialized) if serialized else None
        self.assertIsNotNone(receipt)
        self.assertEqual(
            set(receipt),
            {"schema", "status", "binding", "failure", "evidence", "cleanup", "receipt"},
        )
        self.assertEqual(receipt["failure"]["stage"], "CLEANUP")
        self.assertEqual(receipt["failure"]["failed_invariant"], "SCRATCH_CLEANUP")
        self.assertEqual(receipt["cleanup"]["status"], "EXACT_ZERO")
        self.assertTrue(receipt["evidence"]["raw_details_withheld"])
        self.assertNotIn("private detail", serialized)

    def test_public_receipt_redacts_raw_failures_and_missing_pass_evidence(self) -> None:
        marker = re.search(
            r"(?ms)^# BEGIN PUBLIC_RECEIPT_TOOL\n(?P<source>.*?)^# END PUBLIC_RECEIPT_TOOL$",
            self.runner,
        )
        self.assertIsNotNone(marker)
        public_tool = marker.group("source")
        public_python = public_tool.split("<<'PY'\n", 1)[1].rsplit("\nPY\n}", 1)[0]
        injections = (
            "198.51.100.9",
            "2001:db8::9",
            "https://example.invalid/path",
            r"C:\\Users\\runner\\secret.txt",
            "postgresql://user:pass@example.invalid/db",
            "project_ref_abcdefghijklmnopqrst",
            "Bearer abcdefghijklmnop",
            "eyJhbGciOiJIUzI1NiJ9.abcdefghijklm.signature",
            "HOME=/home/runner TOKEN=value",
            "docker inspect --format raw-output",
            "RuntimeError: arbitrary exception text",
            "free form detail with spaces",
            "MALFORMED-enum",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, injected in enumerate(injections):
                state = root / f"state-{index}.tsv"
                result = root / f"result-{index}.json"
                state.write_bytes((
                    "status\tstr\tBLOCKED\n"
                    f"failure.code\tstr\t{injected}\n"
                    f"failure.detail\tstr\t{injected}\n"
                    f"failure.extra.nested\tstr\t{injected}\n"
                    "cleanup.containers_remaining\tint\t0\n"
                    "cleanup.volumes_remaining\tint\t0\n"
                    "cleanup.networks_remaining\tint\t0\n"
                    "cleanup.listeners_remaining\tint\t0\n"
                    "scratch.primary.proof_status\tstr\tPASS\n"
                    "scratch.primary.remaining_entry_count\tint\t0\n"
                ).encode("utf-8"))
                completed = subprocess.run(
                    [
                        sys.executable, "-B", "-", "build", str(result), "BLOCKED", "0",
                        "run", str(ROOT), str(state),
                    ],
                    input=public_python,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, (injected, completed.stderr))
                serialized = result.read_text(encoding="utf-8")
                receipt = json.loads(serialized)
                self.assertEqual(receipt["failure"]["code"], "UNKNOWN_SANITIZED")
                self.assertNotIn(injected, serialized)

            missing_state = root / "missing-pass.tsv"
            missing_result = root / "missing-pass.json"
            missing_state.write_bytes(b"status\tstr\tCONTAINMENT_SMOKE_PASS\n")
            completed = subprocess.run(
                [
                    sys.executable, "-B", "-", "build", str(missing_result),
                    "CONTAINMENT_SMOKE_PASS", "0", "run", str(ROOT), str(missing_state),
                ],
                input=public_python,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            receipt = json.loads(missing_result.read_text(encoding="utf-8"))
            self.assertEqual(receipt["status"], "BLOCKED")
            self.assertEqual(receipt["cleanup"]["status"], "UNVERIFIED")

    def test_public_receipt_pass_requires_exact_private_terminal_status(self) -> None:
        marker = re.search(
            r"(?ms)^# BEGIN PUBLIC_RECEIPT_TOOL\n(?P<source>.*?)^# END PUBLIC_RECEIPT_TOOL$",
            self.runner,
        )
        self.assertIsNotNone(marker)
        public_python = marker.group("source").split("<<'PY'\n", 1)[1].rsplit("\nPY\n}", 1)[0]
        exact_cleanup = (
            "cleanup.containers_remaining\tint\t0\n"
            "cleanup.volumes_remaining\tint\t0\n"
            "cleanup.networks_remaining\tint\t0\n"
            "cleanup.listeners_remaining\tint\t0\n"
            "scratch.primary.proof_status\tstr\tPASS\n"
            "scratch.primary.remaining_entry_count\tint\t0\n"
        )
        invalid_status_rows = {
            "missing": "",
            "null": "status\tjson\tnull\n",
            "malformed": "status\tbool\ttrue\n",
            "unknown": "status\tstr\tNOT_A_STATUS\n",
            "mismatched": "status\tstr\tBLOCKED\n",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for case, status_row in invalid_status_rows.items():
                with self.subTest(case=case):
                    state = root / f"{case}.tsv"
                    result = root / f"{case}.json"
                    state.write_bytes((status_row + exact_cleanup).encode("utf-8"))
                    completed = subprocess.run(
                        [
                            sys.executable, "-B", "-", "build", str(result),
                            "CONTAINMENT_SMOKE_PASS", "0", "run", str(ROOT), str(state),
                        ],
                        input=public_python,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(completed.returncode, 0, (case, completed.stderr))
                    receipt = json.loads(result.read_text(encoding="utf-8"))
                    self.assertEqual(receipt["status"], "BLOCKED")
                    self.assertEqual(receipt["failure"]["code"], "UNKNOWN_SANITIZED")
                    self.assertEqual(receipt["cleanup"]["status"], "EXACT_ZERO")
                    self.assertTrue(receipt["cleanup"]["proof_complete"])

    def test_public_receipt_validator_rejects_unknown_nested_and_noncanonical_data(self) -> None:
        marker = re.search(
            r"(?ms)^# BEGIN PUBLIC_RECEIPT_TOOL\n(?P<source>.*?)^# END PUBLIC_RECEIPT_TOOL$",
            self.runner,
        )
        self.assertIsNotNone(marker)
        public_tool = marker.group("source")
        public_python = public_tool.split("<<'PY'\n", 1)[1].rsplit("\nPY\n}", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "unsafe.json"
            path.write_text(
                '{"schema":"fawxzzy.hosted-replay-harness.public-receipt.v1",'
                '"status":"BLOCKED","unknown":{"raw":"https://example.invalid"}}\n',
                encoding="utf-8",
            )
            completed = subprocess.run(
                [sys.executable, "-B", "-", "validate", str(path), "BLOCKED"],
                input=public_python,
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertNotEqual(completed.returncode, 0)

    def test_private_probe_public_receipt_preserves_only_closed_failure_and_cleanup_evidence(self) -> None:
        marker = re.search(
            r"(?ms)^# BEGIN PUBLIC_RECEIPT_TOOL\n(?P<source>.*?)^# END PUBLIC_RECEIPT_TOOL$",
            self.runner,
        )
        self.assertIsNotNone(marker)
        public_python = marker.group("source").split("<<'PY'\n", 1)[1].rsplit("\nPY\n}", 1)[0]
        private = private_netns_probe.default_receipt()
        private["diagnostic.private_netns.failure_code"] = "PRIVATE_CONTAINERD_START_FAILED"
        private["diagnostic.private_netns.startup.terminal_substage"] = "SOCKET_READINESS_TIMEOUT"
        private["diagnostic.private_netns.startup.proof_complete"] = True
        private["diagnostic.private_netns.startup.process_started"] = True
        private["diagnostic.private_netns.startup.socket_wait_timeout"] = True
        private["diagnostic.private_netns.cleanup.attempted"] = True
        private["diagnostic.private_netns.cleanup.succeeded"] = True
        private["diagnostic.private_netns.cleanup.proof_complete"] = True
        private["diagnostic.private_netns.cleanup.completeness_finalized"] = True
        for category in ("query", "action"):
            private[f"diagnostic.private_netns.cleanup.{category}_required_count"] = 1
            private[f"diagnostic.private_netns.cleanup.{category}_attempted_count"] = 1
            private[f"diagnostic.private_netns.cleanup.{category}_succeeded_count"] = 1
            private[f"diagnostic.private_netns.cleanup.{category}_complete"] = True
        private["diagnostic.private_netns.host_firewall.semantic_restored"] = True
        private["diagnostic.private_netns.host_firewall.canonical_restored"] = True
        private["diagnostic.private_netns.host_links.restored"] = True
        private_netns_probe.finalize_receipt(private)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state.tsv"
            result = root / "result.json"
            state.write_bytes(
                (
                    "status\tstr\tBLOCKED\n"
                    "failure.code\tstr\tSTANDARD_RUNNER_REJECTED_JIT_REQUIRED\n"
                    "failure.detail\tstr\tprivate runtime details withheld\n"
                    + private_netns_probe.format_receipt(private)
                    + "cleanup.containers_remaining\tint\t0\n"
                    "cleanup.volumes_remaining\tint\t0\n"
                    "cleanup.networks_remaining\tint\t0\n"
                    "cleanup.listeners_remaining\tint\t0\n"
                    "scratch.primary.proof_status\tstr\tPASS\n"
                    "scratch.primary.remaining_entry_count\tint\t0\n"
                ).encode("utf-8")
            )
            completed = subprocess.run(
                [
                    sys.executable, "-B", "-", "build", str(result), "BLOCKED", "0",
                    "private-netns-probe", str(ROOT), str(state),
                ],
                input=public_python,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            serialized = result.read_text(encoding="utf-8")
            receipt = json.loads(serialized)
        self.assertEqual(receipt["failure"]["code"], "PRIVATE_CONTAINERD_START_FAILED")
        self.assertEqual(receipt["failure"]["stage"], "PRIVATE_RUNTIME")
        self.assertEqual(receipt["failure"]["failed_invariant"], "PRIVATE_DAEMON_ISOLATION")
        self.assertEqual(receipt["evidence"]["status"], "COMPLETE")
        self.assertEqual(receipt["cleanup"]["status"], "EXACT_ZERO")
        self.assertEqual(receipt["cleanup"]["private_residue_remaining"], 0)
        self.assertEqual(
            receipt["evidence"]["private_runtime_startup_substage"],
            "SOCKET_READINESS_TIMEOUT",
        )
        self.assertTrue(receipt["evidence"]["private_runtime_socket_wait_timeout"])
        self.assertTrue(receipt["cleanup"]["private_query_complete"])
        self.assertTrue(receipt["cleanup"]["private_action_complete"])
        self.assertTrue(receipt["cleanup"]["private_proof_complete"])
        self.assertNotIn("private runtime details withheld", serialized)

    def test_zero_residue_never_overrides_incomplete_or_malformed_private_proof(self) -> None:
        marker = re.search(
            r"(?ms)^# BEGIN PUBLIC_RECEIPT_TOOL\n(?P<source>.*?)^# END PUBLIC_RECEIPT_TOOL$",
            self.runner,
        )
        self.assertIsNotNone(marker)
        public_python = marker.group("source").split("<<'PY'\n", 1)[1].rsplit("\nPY\n}", 1)[0]
        private = private_netns_probe.default_receipt()
        private["diagnostic.private_netns.failure_code"] = "PRIVATE_CONTAINERD_START_FAILED"
        private["diagnostic.private_netns.startup.terminal_substage"] = "SOCKET_READINESS_TIMEOUT"
        private["diagnostic.private_netns.startup.proof_complete"] = True
        private["diagnostic.private_netns.startup.process_started"] = True
        private["diagnostic.private_netns.startup.socket_wait_timeout"] = True
        private["diagnostic.private_netns.cleanup.attempted"] = True
        private["diagnostic.private_netns.cleanup.completeness_finalized"] = True
        private["diagnostic.private_netns.cleanup.query_required_count"] = 1
        private["diagnostic.private_netns.cleanup.query_attempted_count"] = 1
        private["diagnostic.private_netns.cleanup.query_failure_count"] = 1
        private["diagnostic.private_netns.cleanup.action_required_count"] = 1
        private["diagnostic.private_netns.cleanup.action_attempted_count"] = 1
        private["diagnostic.private_netns.cleanup.action_succeeded_count"] = 1
        private["diagnostic.private_netns.cleanup.action_complete"] = True
        private["diagnostic.private_netns.cleanup.command_failure_count"] = 1
        private_netns_probe.finalize_receipt(private)
        rendered = private_netns_probe.format_receipt(private)
        outer = (
            "status\tstr\tBLOCKED\n"
            "failure.code\tstr\tSTANDARD_RUNNER_REJECTED_JIT_REQUIRED\n"
            "cleanup.containers_remaining\tint\t0\n"
            "cleanup.volumes_remaining\tint\t0\n"
            "cleanup.networks_remaining\tint\t0\n"
            "cleanup.listeners_remaining\tint\t0\n"
            "scratch.primary.proof_status\tstr\tPASS\n"
            "scratch.primary.remaining_entry_count\tint\t0\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, private_rows, expected_code in (
                ("incomplete", rendered, "PRIVATE_CONTAINERD_START_FAILED"),
                (
                    "malformed",
                    "\n".join(
                        line
                        for line in rendered.splitlines()
                        if not line.startswith(
                            "diagnostic.private_netns.startup.terminal_substage\t"
                        )
                    )
                    + "\n",
                    "UNKNOWN_SANITIZED",
                ),
            ):
                state = root / f"{name}.tsv"
                result = root / f"{name}.json"
                state.write_bytes((outer + private_rows).encode())
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-B",
                        "-",
                        "build",
                        str(result),
                        "BLOCKED",
                        "0",
                        "private-netns-probe",
                        str(ROOT),
                        str(state),
                    ],
                    input=public_python,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, (name, completed.stderr))
                receipt = json.loads(result.read_text(encoding="utf-8"))
                self.assertEqual(receipt["status"], "BLOCKED")
                self.assertEqual(receipt["failure"]["code"], expected_code)
                self.assertEqual(receipt["cleanup"]["status"], "UNVERIFIED")
                self.assertFalse(receipt["cleanup"]["proof_complete"])
                self.assertEqual(receipt["cleanup"]["private_residue_remaining"], 0)
                if name == "incomplete":
                    self.assertEqual(receipt["cleanup"]["private_query_failure_count"], 1)
                    self.assertFalse(receipt["cleanup"]["private_query_complete"])
                else:
                    self.assertEqual(
                        receipt["evidence"]["private_runtime_startup_substage"],
                        "UNKNOWN_SANITIZED",
                    )
                    self.assertFalse(
                        receipt["evidence"]["private_runtime_startup_proof_complete"]
                    )

    def test_public_receipt_writer_failure_publishes_safe_blocked_fallback(self) -> None:
        marker = re.search(
            r"(?ms)^# BEGIN PUBLIC_RECEIPT_TOOL\n(?P<source>.*?)^# END PUBLIC_RECEIPT_TOOL$",
            self.runner,
        )
        self.assertIsNotNone(marker)
        public_python = marker.group("source").split("<<'PY'\n", 1)[1].rsplit("\nPY\n}", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state.tsv"
            result = root / "result.json"
            state.write_bytes(b"status\tstr\tCONTAINMENT_SMOKE_PASS\n")
            completed = subprocess.run(
                [
                    sys.executable, "-B", "-", "build", str(result),
                    "CONTAINMENT_SMOKE_PASS", "1", "run", str(ROOT), str(state),
                ],
                input=public_python,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            receipt = json.loads(result.read_text(encoding="utf-8"))
        self.assertEqual(receipt["status"], "BLOCKED")
        self.assertEqual(receipt["failure"]["code"], "RESULT_RECEIPT_PUBLICATION_FAILED")
        self.assertEqual(receipt["failure"]["failed_invariant"], "RECEIPT_INTEGRITY")

    def test_publication_pipeline_replaces_private_writer_output_before_atomic_publish(self) -> None:
        marker = re.search(
            r"(?ms)^# BEGIN PUBLIC_RECEIPT_TOOL\n(?P<source>.*?)^# END PUBLIC_RECEIPT_TOOL$",
            self.runner,
        )
        self.assertIsNotNone(marker)
        functions = "\n".join(
            (
                marker.group("source"),
                self.runner_functions("sanitize_public_result_receipt"),
                self.runner_functions("validate_result_receipt"),
                self.runner_functions("result_receipt_status"),
                self.runner_functions("publish_result_receipt"),
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            state = temp / "state.tsv"
            audit = temp / "audit.jsonl"
            result = temp / "result.json"
            stage = temp / "result.stage"
            state.write_bytes(
                b"status\tstr\tBLOCKED\n"
                b"failure.code\tstr\tPACKET_SCRATCH_PROOF_FAILED\n"
                b"failure.detail\tstr\thttps://raw.invalid/private\n"
                b"cleanup.containers_remaining\tint\t0\n"
                b"cleanup.volumes_remaining\tint\t0\n"
                b"cleanup.networks_remaining\tint\t0\n"
                b"cleanup.listeners_remaining\tint\t0\n"
                b"scratch.primary.proof_status\tstr\tPASS\n"
                b"scratch.primary.remaining_entry_count\tint\t0\n"
            )
            audit.write_bytes(
                b'{"role":"database","container_id":"raw-id","command":["raw-command"]}\n'
            )
            python_path = Path(sys.executable).as_posix()
            if re.match(r"^[A-Za-z]:/", python_path):
                python_path = f"/{python_path[0].lower()}{python_path[2:]}"
            script = temp / "pipeline.sh"
            script.write_text(
                "set -Eeuo pipefail\n"
                f"PYTHON={shlex.quote(python_path)}\n"
                "python3() { \"$PYTHON\" \"$@\"; }\n"
                f"ROOT={shlex.quote(ROOT.as_posix())}\n"
                f"STATE_FILE={shlex.quote(state.as_posix())}\n"
                f"AUDIT_FILE={shlex.quote(audit.as_posix())}\n"
                f"RESULT_FILE={shlex.quote(result.as_posix())}\n"
                f"RESULT_STAGE_FILE={shlex.quote(stage.as_posix())}\n"
                f"SCRATCH_AUDIT_STAGE_FILE={shlex.quote((temp / 'audit.stage').as_posix())}\n"
                f"SCRATCH_PROOF_STAGE_FILE={shlex.quote((temp / 'proof.stage').as_posix())}\n"
                "MODE=run\n"
                f"{functions}\n"
                "publish_result_receipt BLOCKED replace\n"
                "validate_result_receipt \"$RESULT_FILE\" BLOCKED\n",
                encoding="utf-8",
                newline="\n",
            )
            completed = subprocess.run(
                [BASH, str(script)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            serialized = result.read_text(encoding="utf-8")
            receipt = json.loads(serialized)
        self.assertEqual(receipt["failure"]["code"], "PACKET_SCRATCH_PROOF_FAILED")
        self.assertNotIn("raw.invalid", serialized)
        self.assertNotIn("raw-command", serialized)
        self.assertNotIn("raw-id", serialized)

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
        self.assertNotIn('rm -rf -- "$RUNTIME"', self.runner)
        self.assertIn("cleanup_packet_scratch primary", self.runner)
        self.assertIn("cleanup_packet_scratch cleanup", self.runner)

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
        query = self.runner_functions("docker_cleanup_query_ids")
        self.assertEqual(query.count('label=io.fawxzzy.packet=${DIRECT_PACKET}'), 1)
        cleanup = self.runner_functions("cleanup_exact")
        for resource in ("CONTAINER", "VOLUME", "NETWORK"):
            self.assertIn(f"docker_cleanup_query_ids {resource} ENUMERATE", cleanup)
            self.assertIn(f"docker_cleanup_query_ids {resource} FINAL_RESIDUE", cleanup)
        self.assertIn('[[ "$listener_count" == "0" ]] || return 1', self.runner)
        self.assertRegex(
            self.runner,
            r'(?s)if \[\[ ! -f "\$RESULT_FILE" \]\]; then\s+publish_operation=replace.*?'
            r'elif \[\[ "\$recovery_state" == "0" && "\$cleanup_rc" == "0" '
            r'&& "\$RESULT_PROFILE" == "direct-docker-port-v1" \]\]; then\s+'
            r'record result.profile str direct-docker-port-v1',
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
        "host_mounts": [],
        "volumes_from": [],
        "tmpfs": {
            "/var/lib/postgresql/data": "rw,nosuid,nodev,noexec,size=1g"
        },
        "devices": [],
        "device_requests": [],
        "cap_add": [],
        "security_opt": [],
        "extra_hosts": [],
        "config_exposed_ports": {"5432/tcp": {}},
        "port_bindings": {"5432/tcp": [{"HostIp": "", "HostPort": "56422"}]},
        "publish_all_ports": False,
        "restart_policy": {"Name": "no", "MaximumRetryCount": 0},
        "mounts": [],
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


def direct_group_payloads(container_id: str = "b" * 64) -> dict[str, dict]:
    inspection = direct_inspection()
    inspection["id"] = container_id
    return {
        "IDENTITY_CONFIG": {
            "schema_version": 1,
            **{
                key: inspection[key]
                for key in ("id", "name", "image_id", "config_image", "labels")
            },
        },
        "HOSTCONFIG_SECURITY_TMPFS": {
            "schema_version": 1,
            **{
                key: inspection[key]
                for key in (
                    "network_mode",
                    "privileged",
                    "pid_mode",
                    "ipc_mode",
                    "binds",
                    "host_mounts",
                    "volumes_from",
                    "tmpfs",
                    "devices",
                    "device_requests",
                    "cap_add",
                    "security_opt",
                    "extra_hosts",
                    "restart_policy",
                )
            },
        },
        "PUBLICATION": {
            "schema_version": 1,
            "config": {"exposed_ports": inspection["config_exposed_ports"]},
            "host_config": {
                "port_bindings": inspection["port_bindings"],
                "publish_all_ports": inspection["publish_all_ports"],
            },
            "network_settings": {"ports": inspection["published_ports"]},
        },
        "NETWORK_RUNTIME_MOUNTS": {
            "schema_version": 1,
            "mounts": inspection["mounts"],
            "networks": inspection["networks"],
        },
        "STATE_HEALTH": {
            "schema_version": 1,
            "restart_count": inspection["restart_count"],
            "state": inspection["state"],
            "health": inspection["health"],
        },
    }


def inspect_completed(
    payload: object, returncode: int = 0, stderr: bytes = b""
) -> subprocess.CompletedProcess[bytes]:
    stdout = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)


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
        self.assertIn("{{json .HostConfig.Mounts}}", direct_port.INSPECT_TEMPLATE)
        self.assertIn("{{json .HostConfig.VolumesFrom}}", direct_port.INSPECT_TEMPLATE)
        self.assertIn("{{json .Config.ExposedPorts}}", direct_port.INSPECT_TEMPLATE)
        self.assertIn("{{json .HostConfig.PublishAllPorts}}", direct_port.INSPECT_TEMPLATE)

    def test_legacy_tmpfs_requires_one_exact_destination_and_normalized_options(self) -> None:
        destination = "/var/lib/postgresql/data"
        self.assertTrue(
            direct_port.legacy_tmpfs_matches(
                {destination: "size=1g,noexec,nodev,nosuid,rw"}, "1g"
            )
        )
        rejected = (
            None,
            {},
            {destination: "rw,nosuid,nodev,noexec"},
            {destination: "rw,nosuid,nodev,noexec,size=64m"},
            {destination: "rw,nosuid,nodev,noexec,size=1g,rw"},
            {destination: "rw,nosuid,nodev,noexec,size=1g,exec"},
            {destination: ["rw", "nosuid", "nodev", "noexec", "size=1g"]},
            {"/unexpected": "rw,nosuid,nodev,noexec,size=1g"},
            {
                destination: "rw,nosuid,nodev,noexec,size=1g",
                "/unexpected": "rw,nosuid,nodev,noexec,size=1g",
            },
        )
        for payload in rejected:
            with self.subTest(payload=payload):
                self.assertFalse(direct_port.legacy_tmpfs_matches(payload, "1g"))
        exact_options = {"rw", "nosuid", "nodev", "noexec", "size=1g"}
        for removed in exact_options:
            with self.subTest(removed=removed):
                remaining = sorted(exact_options - {removed})
                self.assertFalse(
                    direct_port.legacy_tmpfs_matches(
                        {destination: ",".join(remaining)}, "1g"
                    )
                )

    def publication_shape(
        self,
        *,
        exposed_ports: object = None,
        port_bindings: object = None,
        publish_all_ports: object = False,
        published_ports: object = None,
    ) -> dict:
        if port_bindings is None:
            port_bindings = {}
        if published_ports is None:
            published_ports = {}
        return {
            "schema_version": 1,
            "config": {"exposed_ports": exposed_ports},
            "host_config": {
                "port_bindings": port_bindings,
                "publish_all_ports": publish_all_ports,
            },
            "network_settings": {"ports": published_ports},
        }

    def classify_publication(self, payload: dict) -> dict:
        return direct_port.classify_unpublished_publication_shape(payload)

    def test_unpublished_shape_accepts_absent_null_empty_and_exposed_only(self) -> None:
        fixtures = (
            ({}, "ABSENT", False),
            ({"5432/tcp": None}, "NULL", False),
            ({"5432/tcp": []}, "EMPTY_LIST", False),
            ({"5432/tcp": None}, "NULL", True),
        )
        digests: list[str] = []
        for ports, value_class, exposed in fixtures:
            with self.subTest(value_class=value_class, exposed=exposed):
                payload = self.publication_shape(
                    exposed_ports={"5432/tcp": {}} if exposed else None,
                    published_ports=ports,
                )
                result = self.classify_publication(payload)
                self.assertEqual(result["class"], "FIREWALL_CLIENT_PUBLICATION_SHAPE_SAFE")
                self.assertEqual(result["network_ports_5432_value_class"], value_class)
                self.assertEqual(result["config_exposed_ports_5432_present"], exposed)
                self.assertRegex(result["digest"], r"^[0-9a-f]{64}$")
                self.assertEqual(
                    result["digest"], self.classify_publication(payload)["digest"]
                )
                digests.append(result["digest"])
        self.assertEqual(len(digests), len(set(digests)))
        null_request = self.publication_shape()
        null_request["host_config"]["port_bindings"] = None
        self.assertEqual(
            self.classify_publication(null_request)["class"],
            "FIREWALL_CLIENT_PUBLICATION_SHAPE_SAFE",
        )

    def test_unpublished_shape_rejects_every_nonempty_binding_class(self) -> None:
        bindings = (
            {"HostIp": "127.0.0.1", "HostPort": "56422"},
            {"HostIp": "0.0.0.0", "HostPort": "56422"},
            {"HostIp": "::", "HostPort": "56422"},
            {"HostIp": "2001:db8::10", "HostPort": "56422"},
        )
        for binding in bindings:
            with self.subTest(binding_class=binding["HostIp"]):
                mapping = {"5432/tcp": [binding]}
                result = self.classify_publication(
                    self.publication_shape(
                        port_bindings=mapping,
                        published_ports=mapping,
                    )
                )
                self.assertEqual(
                    result["class"], "FIREWALL_CLIENT_PUBLICATION_REQUEST_REJECTED"
                )
                self.assertEqual(result["host_port_bindings_total_binding_count"], 1)
                self.assertEqual(result["network_ports_total_binding_count"], 1)
                self.assertNotIn(binding["HostIp"], json.dumps(result))

    def test_unpublished_shape_rejects_publish_all_other_port_and_one_sided_bindings(self) -> None:
        other = {"8080/tcp": [{"HostIp": "", "HostPort": "49152"}]}
        request = {"5432/tcp": [{"HostIp": "", "HostPort": "56422"}]}
        cases = (
            (
                self.publication_shape(publish_all_ports=True),
                "FIREWALL_CLIENT_PUBLICATION_REQUEST_REJECTED",
            ),
            (
                self.publication_shape(port_bindings=other, published_ports=other),
                "FIREWALL_CLIENT_PUBLICATION_REQUEST_REJECTED",
            ),
            (
                self.publication_shape(port_bindings=request),
                "FIREWALL_CLIENT_PUBLICATION_REQUEST_REJECTED",
            ),
            (
                self.publication_shape(published_ports=request),
                "FIREWALL_CLIENT_PUBLICATION_RUNTIME_REJECTED",
            ),
        )
        for payload, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(self.classify_publication(payload)["class"], expected)

    def test_unpublished_shape_rejects_conflicts_wrong_types_and_missing_objects(self) -> None:
        request = {"5432/tcp": [{"HostIp": "", "HostPort": "56422"}]}
        conflicting = {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "56422"}]}
        fixtures = [
            self.publication_shape(port_bindings=request, published_ports=conflicting),
            self.publication_shape(
                port_bindings=request,
                published_ports={
                    "5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "56423"}]
                },
            ),
            self.publication_shape(exposed_ports=[]),
            self.publication_shape(port_bindings=[]),
            self.publication_shape(publish_all_ports="false"),
            self.publication_shape(published_ports=[]),
            self.publication_shape(published_ports={"5432/tcp": "wrong"}),
            self.publication_shape(port_bindings={"5432/tcp": [{}]}),
            {"schema_version": 1},
        ]
        for payload in fixtures:
            with self.subTest(payload=payload):
                result = self.classify_publication(payload)
                self.assertEqual(
                    result["class"], "FIREWALL_CLIENT_PUBLICATION_SCHEMA_REJECTED"
                )

    def test_publication_json_parser_rejects_malformed_duplicate_and_invalid_utf8(self) -> None:
        malformed = (
            b"{",
            b'{"schema_version":1,"schema_version":1}',
            b'{"schema_version":"\xff"}',
        )
        for raw in malformed:
            with self.subTest(raw_hash=hashlib.sha256(raw).hexdigest()):
                with self.assertRaises((ValueError, UnicodeDecodeError)):
                    direct_port.strict_json_object(raw)

    def test_publication_inspect_failure_and_state_schema_never_emit_raw_values(self) -> None:
        failed = subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"sensitive")
        with mock.patch.object(direct_port.subprocess, "run", return_value=failed):
            result = direct_port.inspect_unpublished_publication(
                "opaque-container-id", "FIREWALL_CLIENT"
            )
        self.assertEqual(
            result, {"class": "FIREWALL_CLIENT_PUBLICATION_INSPECT_FAILED"}
        )
        lines = direct_port.publication_state_lines("firewall_client", result)
        self.assertEqual(len(lines), 1)
        rendered = "\n".join(lines)
        self.assertNotIn("opaque-container-id", rendered)
        self.assertNotIn("sensitive", rendered)
        malformed = subprocess.CompletedProcess([], 0, stdout=b"{", stderr=b"")
        with mock.patch.object(direct_port.subprocess, "run", return_value=malformed):
            result = direct_port.inspect_unpublished_publication(
                "opaque-container-id", "FIREWALL_CLIENT"
            )
        self.assertEqual(
            result, {"class": "FIREWALL_CLIENT_PUBLICATION_PARSE_FAILED"}
        )
        with self.assertRaises(ValueError):
            direct_port.publication_state_lines(
                "firewall_client",
                {"class": "FIREWALL_CLIENT_PUBLICATION_SHAPE_SAFE", "raw": "forbidden"},
            )
        with self.assertRaises(ValueError):
            direct_port.publication_state_lines(
                "firewall_client", {"class": "arbitrary-unclassified-text"}
            )

    def test_rejects_every_mount_substitution_and_requires_empty_top_level_mounts(self) -> None:
        substitutions = (
            ("binds", ["named:/var/lib/postgresql/data"], "DIRECT_BIND_MOUNT_REJECTED"),
            (
                "host_mounts",
                [{"Type": "tmpfs", "Target": "/var/lib/postgresql/data"}],
                "DIRECT_MOUNT_CONTRACT_MISMATCH",
            ),
            ("volumes_from", ["foreign:rw"], "DIRECT_MOUNT_CONTRACT_MISMATCH"),
            (
                "mounts",
                [
                    {
                        "Type": "volume",
                        "Source": "opaque",
                        "Destination": "/var/lib/postgresql/data",
                        "RW": True,
                    }
                ],
                "DIRECT_MOUNT_CONTRACT_MISMATCH",
            ),
        )
        for field, value, code in substitutions:
            with self.subTest(field=field):
                data = direct_inspection()
                data[field] = value
                self.assertIn(code, self.validate(data))

        socket_data = direct_inspection()
        socket_data["host_mounts"] = [
            {"Type": "bind", "Source": "/var/run/docker.sock", "Target": "/socket"}
        ]
        self.assertIn("DIRECT_DOCKER_SOCKET_REJECTED", self.validate(socket_data))

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

    def test_full_inspection_accepts_only_one_strict_json_object(self) -> None:
        payload = direct_inspection()
        completed = subprocess.CompletedProcess(
            [], 0, stdout=json.dumps(payload).encode("utf-8"), stderr=b""
        )
        with mock.patch.object(direct_port.subprocess, "run", return_value=completed):
            observed, diagnostic = direct_port.safe_inspect("opaque-id", 7)
        self.assertEqual(observed, payload)
        self.assertIsNone(diagnostic)

    def test_full_inspection_parse_failures_have_exact_terminal_classes(self) -> None:
        fixtures = (
            (b'\xff', "INVALID_UTF8", "DIRECT_INSPECT_INVALID_UTF8"),
            (b'{', "JSON_SYNTAX", "DIRECT_INSPECT_JSON_REJECTED"),
            (
                b'{"schema_version":1,"schema_version":1}',
                "DUPLICATE_KEY",
                "DIRECT_INSPECT_DUPLICATE_KEY_REJECTED",
            ),
            (b'[]', "TOPLEVEL_TYPE", "DIRECT_INSPECT_TOPLEVEL_REJECTED"),
        )
        for raw, parse_class, terminal_class in fixtures:
            with self.subTest(parse_class=parse_class):
                completed = subprocess.CompletedProcess(
                    [], 0, stdout=raw, stderr=b"private-stderr"
                )
                with mock.patch.object(
                    direct_port.subprocess, "run", return_value=completed
                ):
                    observed, diagnostic = direct_port.safe_inspect("opaque-id", 3)
                self.assertIsNone(observed)
                assert diagnostic is not None
                self.assertEqual(diagnostic["parse_class"], parse_class)
                self.assertEqual(diagnostic["terminal_class"], terminal_class)
                self.assertEqual(diagnostic["attempt_index"], 3)
                self.assertEqual(diagnostic["command_exit_class"], "ZERO")
                self.assertEqual(diagnostic["first_failed_group"], "NONE")

    def test_command_failure_distinguishes_object_loss_and_every_field_group(self) -> None:
        failed = subprocess.CompletedProcess(
            [], 1, stdout=b"partial\n", stderr=b"private-command-error\n"
        )
        container_id = "b" * 64
        availability = inspect_completed({"schema_version": 1, "id": container_id})
        payloads = direct_group_payloads(container_id)

        with mock.patch.object(
            direct_port.subprocess, "run", side_effect=[failed, failed]
        ):
            observed, diagnostic = direct_port.safe_inspect(container_id, 1)
        self.assertIsNone(observed)
        assert diagnostic is not None
        self.assertEqual(
            diagnostic["terminal_class"], "DIRECT_INSPECT_OBJECT_UNAVAILABLE"
        )
        self.assertEqual(diagnostic["first_failed_group"], "IDENTITY_CONFIG")
        self.assertEqual(diagnostic["successful_group_count"], 0)

        for index, (group, terminal_class, _) in enumerate(
            direct_port.INSPECT_FIELD_GROUPS
        ):
            with self.subTest(group=group):
                prior = [
                    inspect_completed(payloads[prior_group])
                    for prior_group, _, _ in direct_port.INSPECT_FIELD_GROUPS[:index]
                ]
                sequence = [failed, availability, *prior, failed]
                with mock.patch.object(
                    direct_port.subprocess, "run", side_effect=sequence
                ):
                    observed, diagnostic = direct_port.safe_inspect(container_id, 2)
                self.assertIsNone(observed)
                assert diagnostic is not None
                self.assertEqual(diagnostic["terminal_class"], terminal_class)
                self.assertEqual(diagnostic["first_failed_group"], group)
                self.assertEqual(diagnostic["successful_group_count"], index)

    def test_all_fixed_groups_compose_to_exact_flat_inspection(self) -> None:
        container_id = "b" * 64
        failed = subprocess.CompletedProcess([], -9, stdout=b"", stderr=b"private")
        payloads = direct_group_payloads(container_id)
        sequence = [
            failed,
            inspect_completed({"schema_version": 1, "id": container_id}),
            *[
                inspect_completed(payloads[group])
                for group, _, _ in direct_port.INSPECT_FIELD_GROUPS
            ],
        ]
        with mock.patch.object(
            direct_port.subprocess, "run", side_effect=sequence
        ) as run:
            observed, diagnostic = direct_port.safe_inspect(container_id, 4)
        expected = direct_inspection()
        expected["id"] = container_id
        self.assertEqual(observed, expected)
        self.assertIsNone(diagnostic)
        self.assertEqual(
            direct_port.compose_group_payloads(container_id, payloads), expected
        )
        self.assertEqual(len(run.call_args_list), 7)
        self.assertTrue(
            all(call.args[0][-1] == container_id for call in run.call_args_list)
        )
        self.assertTrue(
            all(len(call.args[0][-1]) == 64 for call in run.call_args_list)
        )

    def test_group_contracts_reject_unknown_missing_schema_and_wrong_types(self) -> None:
        payloads = direct_group_payloads()
        wrong_types = {
            "IDENTITY_CONFIG": ("id", 7),
            "HOSTCONFIG_SECURITY_TMPFS": ("privileged", "false"),
            "PUBLICATION": ("host_config", []),
            "NETWORK_RUNTIME_MOUNTS": ("networks", []),
            "STATE_HEALTH": ("state", []),
        }
        for group, payload in payloads.items():
            with self.subTest(group=group, mutation="unknown"):
                unknown = json.loads(json.dumps(payload))
                unknown["unknown"] = None
                with self.assertRaises(ValueError):
                    direct_port.validate_group_payload(group, unknown)
            with self.subTest(group=group, mutation="missing"):
                missing = json.loads(json.dumps(payload))
                missing.pop(next(key for key in missing if key != "schema_version"))
                with self.assertRaises(ValueError):
                    direct_port.validate_group_payload(group, missing)
            for invalid_schema in (2, True, "1"):
                with self.subTest(group=group, schema=invalid_schema):
                    schema = json.loads(json.dumps(payload))
                    schema["schema_version"] = invalid_schema
                    with self.assertRaises(ValueError):
                        direct_port.validate_group_payload(group, schema)
            with self.subTest(group=group, mutation="wrong_type"):
                wrong_type = json.loads(json.dumps(payload))
                key, value = wrong_types[group]
                wrong_type[key] = value
                with self.assertRaises(ValueError):
                    direct_port.validate_group_payload(group, wrong_type)

        nested_cases = (
            ("PUBLICATION", "config"),
            ("PUBLICATION", "host_config"),
            ("PUBLICATION", "network_settings"),
            ("STATE_HEALTH", "state"),
            ("STATE_HEALTH", "health"),
        )
        for group, nested_key in nested_cases:
            for mutation in ("unknown", "missing"):
                with self.subTest(group=group, nested=nested_key, mutation=mutation):
                    payload = json.loads(json.dumps(payloads[group]))
                    if mutation == "unknown":
                        payload[nested_key]["unknown"] = None
                    else:
                        payload[nested_key].pop(next(iter(payload[nested_key])))
                    with self.assertRaises(ValueError):
                        direct_port.validate_group_payload(group, payload)

    def test_fallback_group_parse_and_schema_failures_preserve_order(self) -> None:
        container_id = "b" * 64
        failed = inspect_completed(b"partial", returncode=1, stderr=b"private")
        availability = inspect_completed({"schema_version": 1, "id": container_id})
        payloads = direct_group_payloads(container_id)
        for index, (group, terminal_class, _) in enumerate(
            direct_port.INSPECT_FIELD_GROUPS
        ):
            prior = [
                inspect_completed(payloads[prior_group])
                for prior_group, _, _ in direct_port.INSPECT_FIELD_GROUPS[:index]
            ]
            invalid_payloads = (
                b"{",
                b'{"schema_version":1,"schema_version":1}',
                {**payloads[group], "unknown": None},
            )
            for invalid in invalid_payloads:
                with self.subTest(group=group, invalid_type=type(invalid).__name__):
                    sequence = [failed, availability, *prior, inspect_completed(invalid)]
                    with mock.patch.object(
                        direct_port.subprocess, "run", side_effect=sequence
                    ):
                        observed, diagnostic = direct_port.safe_inspect(container_id, 2)
                    self.assertIsNone(observed)
                    assert diagnostic is not None
                    self.assertEqual(diagnostic["terminal_class"], terminal_class)
                    self.assertEqual(diagnostic["first_failed_group"], group)
                    self.assertEqual(diagnostic["successful_group_count"], index)

    def test_composition_rejects_identity_group_set_and_field_conflicts(self) -> None:
        container_id = "b" * 64
        payloads = direct_group_payloads(container_id)
        mismatched = json.loads(json.dumps(payloads))
        mismatched["IDENTITY_CONFIG"]["id"] = "c" * 64
        with self.assertRaises(direct_port.CompositionContractError) as identity_error:
            direct_port.compose_group_payloads(container_id, mismatched)
        self.assertEqual(identity_error.exception.group, "IDENTITY_CONFIG")
        with self.assertRaises(direct_port.CompositionContractError):
            direct_port.compose_group_payloads("short-id", payloads)
        missing_group = dict(payloads)
        missing_group.pop("STATE_HEALTH")
        with self.assertRaises(direct_port.CompositionContractError):
            direct_port.compose_group_payloads(container_id, missing_group)
        with self.assertRaises(direct_port.CompositionContractError) as conflict:
            direct_port._merge_unique(
                {"published_ports": None},
                {"published_ports": {}},
                "PUBLICATION",
            )
        self.assertEqual(conflict.exception.group, "PUBLICATION")

    def test_fallback_identity_disagreement_is_closed_composition_failure(self) -> None:
        container_id = "b" * 64
        failed = inspect_completed(b"partial", returncode=1, stderr=b"private")
        payloads = direct_group_payloads(container_id)
        payloads["IDENTITY_CONFIG"]["id"] = "c" * 64
        sequence = [
            failed,
            inspect_completed({"schema_version": 1, "id": container_id}),
            *[
                inspect_completed(payloads[group])
                for group, _, _ in direct_port.INSPECT_FIELD_GROUPS
            ],
        ]
        with mock.patch.object(
            direct_port.subprocess, "run", side_effect=sequence
        ):
            observed, diagnostic = direct_port.safe_inspect(container_id, 6)
        self.assertIsNone(observed)
        assert diagnostic is not None
        self.assertEqual(
            diagnostic["terminal_class"], "DIRECT_INSPECT_COMPOSITION_FAILED"
        )
        self.assertEqual(diagnostic["first_failed_group"], "IDENTITY_CONFIG")
        self.assertEqual(
            diagnostic["successful_group_count"],
            len(direct_port.INSPECT_FIELD_GROUPS),
        )

    def test_availability_identity_disagreement_stops_before_field_groups(self) -> None:
        container_id = "b" * 64
        failed = inspect_completed(b"partial", returncode=1, stderr=b"private")
        availability = inspect_completed({"schema_version": 1, "id": "c" * 64})
        with mock.patch.object(
            direct_port.subprocess, "run", side_effect=[failed, availability]
        ) as run:
            observed, diagnostic = direct_port.safe_inspect(container_id, 7)
        self.assertIsNone(observed)
        assert diagnostic is not None
        self.assertEqual(len(run.call_args_list), 2)
        self.assertEqual(
            diagnostic["terminal_class"], "DIRECT_INSPECT_COMPOSITION_FAILED"
        )
        self.assertEqual(diagnostic["first_failed_group"], "IDENTITY_CONFIG")
        self.assertEqual(diagnostic["successful_group_count"], 0)

    def test_group_raw_failure_bytes_never_enter_diagnostic_output(self) -> None:
        container_id = "b" * 64
        failed = inspect_completed(b"partial", returncode=1, stderr=b"private-full")
        availability = inspect_completed({"schema_version": 1, "id": container_id})
        group_raw = b"secret-shaped-group-output"
        with mock.patch.object(
            direct_port.subprocess,
            "run",
            side_effect=[failed, availability, inspect_completed(group_raw)],
        ):
            observed, diagnostic = direct_port.safe_inspect(container_id, 8)
        self.assertIsNone(observed)
        assert diagnostic is not None
        rendered = "\n".join(direct_port.inspection_state_lines(diagnostic))
        self.assertNotIn(group_raw.decode(), rendered)
        self.assertNotIn(container_id, rendered)

    def test_inspection_envelope_is_closed_deterministic_and_never_emits_raw(self) -> None:
        stdout = b"credential-shaped-output\nsecond-line\n"
        stderr = b"secret-shaped-error\n"
        failed = subprocess.CompletedProcess([], 125, stdout=stdout, stderr=stderr)
        with mock.patch.object(
            direct_port.subprocess, "run", side_effect=[failed, failed]
        ):
            _, diagnostic = direct_port.safe_inspect("opaque-container-id", 5)
        assert diagnostic is not None
        expected_keys = {
            "terminal_class",
            "attempt_index",
            "command_exit_class",
            "command_exit_code",
            "stdout_byte_count",
            "stdout_line_count",
            "stdout_sha256",
            "stderr_byte_count",
            "stderr_line_count",
            "stderr_sha256",
            "utf8_status",
            "parse_class",
            "first_failed_group",
            "successful_group_count",
            "digest",
        }
        self.assertEqual(set(diagnostic), expected_keys)
        self.assertEqual(diagnostic["stdout_byte_count"], len(stdout))
        self.assertEqual(diagnostic["stdout_line_count"], 2)
        self.assertEqual(diagnostic["stdout_sha256"], hashlib.sha256(stdout).hexdigest())
        self.assertEqual(diagnostic["stderr_sha256"], hashlib.sha256(stderr).hexdigest())
        lines = direct_port.inspection_state_lines(diagnostic)
        rendered = "\n".join(lines)
        for forbidden in (
            "credential-shaped-output",
            "secret-shaped-error",
            "opaque-container-id",
        ):
            self.assertNotIn(forbidden, rendered)
        self.assertEqual(lines, direct_port.inspection_state_lines(dict(diagnostic)))
        corrupted = dict(diagnostic, digest="0" * 64)
        with self.assertRaises(ValueError):
            direct_port.inspection_state_lines(corrupted)
        with self.assertRaises(ValueError):
            direct_port.inspection_state_lines(dict(diagnostic, raw="forbidden"))
        inconsistent_cases = (
            dict(diagnostic, command_exit_class="ZERO"),
            dict(diagnostic, utf8_status="INVALID"),
            dict(diagnostic, successful_group_count=1),
            dict(diagnostic, first_failed_group="NONE"),
        )
        for inconsistent in inconsistent_cases:
            canonical = json.dumps(
                {key: value for key, value in inconsistent.items() if key != "digest"},
                sort_keys=True,
                separators=(",", ":"),
            )
            inconsistent["digest"] = hashlib.sha256(canonical.encode()).hexdigest()
            with self.subTest(field_delta=set(inconsistent.items()) - set(diagnostic.items())):
                with self.assertRaises(ValueError):
                    direct_port.inspection_state_lines(inconsistent)

    def test_probe_main_emits_closed_envelope_and_exact_terminal_failure(self) -> None:
        completed = subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"private")
        diagnostic = direct_port._diagnostic_envelope(
            completed,
            attempt_index=1,
            terminal_class="DIRECT_INSPECT_OBJECT_UNAVAILABLE",
            utf8_status="VALID",
            parse_class="JSON_SYNTAX",
            first_failed_group="IDENTITY_CONFIG",
            successful_group_count=0,
        )
        output = io.StringIO()
        argv = [
            "direct_port_probe.py",
            "--container-id",
            "opaque-container-id",
            "--network-id",
            "opaque-network-id",
            "--image-id",
            "opaque-image-id",
            "--image-reference",
            "pinned-image-reference",
        ]
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(
                direct_port, "safe_inspect", return_value=(None, diagnostic)
            ),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(direct_port.main(), 1)
        rendered = output.getvalue()
        self.assertIn(
            "diagnostic.inspection.terminal_class\tstr\tDIRECT_INSPECT_OBJECT_UNAVAILABLE",
            rendered,
        )
        self.assertIn(
            "diagnostic.probe.failure_code\tstr\tDIRECT_INSPECT_OBJECT_UNAVAILABLE",
            rendered,
        )
        for forbidden in (
            "opaque-container-id",
            "opaque-network-id",
            "opaque-image-id",
            "pinned-image-reference",
            "private",
        ):
            self.assertNotIn(forbidden, rendered)

    def test_fallback_denominator_is_exact_and_never_requests_environment(self) -> None:
        self.assertEqual(
            [group for group, _, _ in direct_port.INSPECT_FIELD_GROUPS],
            [
                "IDENTITY_CONFIG",
                "HOSTCONFIG_SECURITY_TMPFS",
                "PUBLICATION",
                "NETWORK_RUNTIME_MOUNTS",
                "STATE_HEALTH",
            ],
        )
        templates = [
            direct_port.INSPECT_TEMPLATE,
            direct_port.OBJECT_AVAILABILITY_TEMPLATE,
            *(template for _, _, template in direct_port.INSPECT_FIELD_GROUPS),
        ]
        self.assertTrue(all(".Config.Env" not in template for template in templates))
        self.assertEqual(len(direct_port.INSPECT_TERMINAL_CLASSES), 11)

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
        nft_entry("counter", name=firewall_boundary.OUTPUT_COUNTER, packets=0, bytes=0),
        nft_entry(
            "chain",
            name=firewall_boundary.INPUT_CHAIN,
            type="filter",
            hook="input",
            prio=-10,
            policy="accept",
        ),
        nft_entry(
            "chain",
            name=firewall_boundary.FORWARD_CHAIN,
            type="filter",
            hook="forward",
            prio=-10,
            policy="accept",
        ),
        nft_entry(
            "chain",
            name=firewall_boundary.OUTPUT_CHAIN,
            type="filter",
            hook="output",
            prio=-10,
            policy="accept",
        ),
        nft_entry("rule", chain=firewall_boundary.INPUT_CHAIN, expr=[{"accept": None}]),
        nft_entry(
            "rule",
            chain=firewall_boundary.INPUT_CHAIN,
            expr=[{"counter": {"name": firewall_boundary.INPUT_COUNTER}}, {"drop": None}],
        ),
        nft_entry(
            "rule",
            chain=firewall_boundary.FORWARD_CHAIN,
            expr=[{"match": {"class": "same-bridge"}}, {"accept": None}],
        ),
        nft_entry(
            "rule",
            chain=firewall_boundary.FORWARD_CHAIN,
            expr=[{"match": {"class": "established-related"}}, {"accept": None}],
        ),
        nft_entry(
            "rule",
            chain=firewall_boundary.FORWARD_CHAIN,
            expr=[{"counter": {"name": firewall_boundary.FORWARD_COUNTER}}, {"drop": None}],
        ),
        nft_entry(
            "rule",
            chain=firewall_boundary.OUTPUT_CHAIN,
            expr=[{"match": {"protocol": "udp", "uid": 0, "port": 53}}, {"counter": {"name": firewall_boundary.OUTPUT_COUNTER}}, {"drop": None}],
        ),
        nft_entry(
            "rule",
            chain=firewall_boundary.OUTPUT_CHAIN,
            expr=[{"match": {"protocol": "tcp", "uid": 0, "port": 53}}, {"counter": {"name": firewall_boundary.OUTPUT_COUNTER}}, {"drop": None}],
        ),
    ]


def owned_firewall_entries_with_markers() -> list[dict]:
    entries = owned_firewall_entries()
    entries.extend(
        nft_entry("counter", name=name, packets=0, bytes=0)
        for name in firewall_boundary.MARKER_COUNTERS.values()
    )
    entries.extend(
        (
            nft_entry(
                "chain",
                name=firewall_boundary.MARKER_INPUT_CHAIN,
                type="filter",
                hook="input",
                prio=-20,
                policy="accept",
            ),
            nft_entry(
                "chain",
                name=firewall_boundary.MARKER_FORWARD_CHAIN,
                type="filter",
                hook="forward",
                prio=-20,
                policy="accept",
            ),
            nft_entry(
                "chain",
                name=firewall_boundary.MARKER_OUTPUT_CHAIN,
                type="filter",
                hook="output",
                prio=-20,
                policy="accept",
            ),
        )
    )
    expected = firewall_boundary.expected_marker_rule_expressions(
        firewall_boundary.TABLE,
        "br-fpro001",
        "172.31.253.0/24",
        "172.31.253.10",
        "172.31.253.11",
        "172.17.0.4",
        "172.31.253.1",
        18080,
    )
    entries.extend(
        nft_entry("rule", chain=chain, expr=copy.deepcopy(expressions))
        for chain, rules in expected.items()
        for expressions in rules
    )
    return entries


class PrivateDockerNetnsProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (ROOT / "scripts/private_docker_netns_probe.py").read_text(
            encoding="utf-8"
        )
        cls.runner = (ROOT / "scripts/run-containment-smoke.sh").read_text(
            encoding="utf-8"
        )

    def test_closed_receipt_roundtrip_and_digest(self) -> None:
        receipt = private_netns_probe.default_receipt()
        receipt["diagnostic.private_netns.failure_code"] = "ROOT_PRIVILEGE_UNAVAILABLE"
        private_netns_probe.finalize_receipt(receipt)
        rendered = private_netns_probe.format_receipt(receipt).encode()
        self.assertEqual(private_netns_probe.parse_receipt(rendered), receipt)
        self.assertEqual(
            set(receipt), {key for key, _ in private_netns_probe.FIELD_SPECS}
        )
        self.assertNotIn("/home/runner", rendered.decode())
        self.assertNotIn("password", rendered.decode().lower())
        self.assertNotIn("token", rendered.decode().lower())

    def test_receipt_rejects_missing_duplicate_wrong_type_and_digest_drift(self) -> None:
        receipt = private_netns_probe.default_receipt()
        receipt["diagnostic.private_netns.failure_code"] = "CAPABILITY_TOOL_MISSING"
        private_netns_probe.finalize_receipt(receipt)
        rendered = private_netns_probe.format_receipt(receipt)
        with self.assertRaises(ValueError):
            private_netns_probe.parse_receipt("\n".join(rendered.splitlines()[1:]).encode() + b"\n")
        first = rendered.splitlines()[0]
        with self.assertRaises(ValueError):
            private_netns_probe.parse_receipt((rendered + first + "\n").encode())
        with self.assertRaises(ValueError):
            private_netns_probe.parse_receipt(
                rendered.replace(
                    "diagnostic.private_netns.cleanup.succeeded\tbool\tfalse",
                    "diagnostic.private_netns.cleanup.succeeded\tbool\t0",
                ).encode()
            )
        with self.assertRaises(ValueError):
            private_netns_probe.parse_receipt(
                rendered.replace(
                    receipt["diagnostic.private_netns.receipt_sha256"], "f" * 64
                ).encode()
            )
        contradictory_cleanup = private_netns_probe.default_receipt()
        contradictory_cleanup[
            "diagnostic.private_netns.cleanup.query_required_count"
        ] = 1
        private_netns_probe.finalize_receipt(contradictory_cleanup)
        with self.assertRaises(ValueError):
            private_netns_probe.format_receipt(contradictory_cleanup)
        contradictory_startup = private_netns_probe.default_receipt()
        contradictory_startup[
            "diagnostic.private_netns.startup.terminal_substage"
        ] = "READY"
        contradictory_startup[
            "diagnostic.private_netns.startup.proof_complete"
        ] = True
        private_netns_probe.finalize_receipt(contradictory_startup)
        with self.assertRaises(ValueError):
            private_netns_probe.format_receipt(contradictory_startup)

    def test_startup_substages_are_closed_deterministic_and_raw_output_free(self) -> None:
        class ExitedProcess:
            def poll(self) -> int:
                return 1

        probe = self.probe_fixture()
        probe.containerd_process = ExitedProcess()
        probe.receipt["diagnostic.private_netns.startup.process_started"] = True
        with mock.patch.object(Path, "is_socket", return_value=False):
            with self.assertRaises(private_netns_probe.ProbeFailure) as raised:
                probe.wait_for_containerd_socket()
        self.assertEqual(raised.exception.code, "PRIVATE_CONTAINERD_START_FAILED")
        self.assertEqual(
            probe.receipt["diagnostic.private_netns.startup.terminal_substage"],
            "PROCESS_EXIT_BEFORE_SOCKET",
        )

        class RunningProcess:
            def poll(self) -> None:
                return None

        timeout_probe = self.probe_fixture()
        timeout_probe.containerd_process = RunningProcess()
        timeout_probe.receipt["diagnostic.private_netns.startup.process_started"] = True
        with mock.patch.object(Path, "is_socket", return_value=False):
            with mock.patch.object(
                private_netns_probe.time, "monotonic", side_effect=(0.0, 31.0)
            ):
                with self.assertRaises(private_netns_probe.ProbeFailure) as raised:
                    timeout_probe.wait_for_containerd_socket()
        self.assertEqual(raised.exception.code, "PRIVATE_CONTAINERD_START_FAILED")
        self.assertEqual(
            timeout_probe.receipt["diagnostic.private_netns.startup.terminal_substage"],
            "SOCKET_READINESS_TIMEOUT",
        )

        for results, expected in (
            (
                [subprocess.CompletedProcess([], 1, b"RAW_STARTUP_SENTINEL", b"RAW_STARTUP_SENTINEL")],
                "NAMESPACE_CREATE_INITIAL_FAILED",
            ),
            (
                [
                    subprocess.CompletedProcess([], 0, b"RAW_STARTUP_SENTINEL", b"RAW_STARTUP_SENTINEL"),
                    subprocess.CompletedProcess([], 1, b"RAW_STARTUP_SENTINEL", b"RAW_STARTUP_SENTINEL"),
                ],
                "NAMESPACE_CREATE_RETRY_FAILED",
            ),
        ):
            with self.subTest(substage=expected):
                namespace_probe = self.probe_fixture()
                namespace_probe.receipt["diagnostic.private_netns.startup.process_started"] = True
                namespace_probe.receipt["diagnostic.private_netns.startup.socket_observed"] = True
                with mock.patch.object(
                    private_netns_probe, "run_command", side_effect=results
                ):
                    with self.assertRaises(private_netns_probe.ProbeFailure) as raised:
                        namespace_probe.create_private_containerd_namespaces()
                self.assertEqual(raised.exception.code, "PRIVATE_CONTAINERD_START_FAILED")
                self.assertEqual(
                    namespace_probe.receipt[
                        "diagnostic.private_netns.startup.terminal_substage"
                    ],
                    expected,
                )
                namespace_probe.receipt["diagnostic.private_netns.failure_code"] = raised.exception.code
                private_netns_probe.finalize_receipt(namespace_probe.receipt)
                rendered = private_netns_probe.format_receipt(namespace_probe.receipt)
                self.assertNotIn("RAW_STARTUP_SENTINEL", rendered)

        for result, expected in (
            (
                subprocess.CompletedProcess(
                    [], 1, b"RAW_STARTUP_SENTINEL", b"RAW_STARTUP_SENTINEL"
                ),
                "NAMESPACE_READBACK_FAILED",
            ),
            (
                subprocess.CompletedProcess(
                    [],
                    0,
                    (
                        private_netns_probe.CONTAINERD_NAMESPACE
                        + "\n"
                        + private_netns_probe.CONTAINERD_PLUGINS_NAMESPACE
                        + "\n"
                    ).encode(),
                    b"RAW_STARTUP_SENTINEL",
                ),
                "READY",
            ),
        ):
            with self.subTest(readback=expected):
                readback_probe = self.probe_fixture()
                readback_probe.receipt["diagnostic.private_netns.startup.process_started"] = True
                readback_probe.receipt["diagnostic.private_netns.startup.socket_observed"] = True
                readback_probe.receipt[
                    "diagnostic.private_netns.startup.namespace_create_attempted_count"
                ] = 2
                readback_probe.receipt[
                    "diagnostic.private_netns.startup.namespace_create_succeeded_count"
                ] = 2
                with mock.patch.object(private_netns_probe, "run_command", return_value=result):
                    if expected == "READY":
                        readback_probe.verify_private_containerd_namespaces()
                    else:
                        with self.assertRaises(private_netns_probe.ProbeFailure):
                            readback_probe.verify_private_containerd_namespaces()
                self.assertEqual(
                    readback_probe.receipt[
                        "diagnostic.private_netns.startup.terminal_substage"
                    ],
                    expected,
                )

    def test_multiple_daemon_commands_are_fully_distinct_and_unix_only(self) -> None:
        runtime = Path("/packet/private-netns")
        containerd = private_netns_probe.build_containerd_command(
            "/usr/bin/containerd", runtime
        )
        dockerd = private_netns_probe.build_dockerd_command(
            "/usr/bin/dockerd", runtime
        )
        rendered = "\n".join((*containerd, *dockerd))
        for fragment in (
            "/packet/private-netns/containerd.sock",
            "/packet/private-netns/containerd.toml",
            "/packet/private-netns/containerd-state",
            "/packet/private-netns/containerd-root",
            "--host=unix:///packet/private-netns/docker.sock",
            "--config-file=/packet/private-netns/daemon.json",
            "--pidfile=/packet/private-netns/dockerd.pid",
            "--data-root=/packet/private-netns/docker-data",
            "--exec-root=/packet/private-netns/docker-exec",
            "--bridge=none",
            "--firewall-backend=iptables",
            f"--containerd-namespace={private_netns_probe.CONTAINERD_NAMESPACE}",
            f"--containerd-plugins-namespace={private_netns_probe.CONTAINERD_PLUGINS_NAMESPACE}",
            f"--cgroup-parent=/{private_netns_probe.CGROUP_NAME}",
        ):
            self.assertIn(fragment, rendered)
        self.assertNotIn("tcp://", rendered)
        self.assertNotIn("/run/containerd/containerd.sock", rendered)
        self.assertIn('disabled_plugins = ["io.containerd.grpc.v1.cri"]', self.source)
        self.assertRegex(self.source, r'"namespaces",\n\s+"create"')

    def test_private_firewall_is_namespace_local_and_same_bridge_only(self) -> None:
        batch = private_netns_probe.build_private_firewall_batch().decode()
        self.assertIn(
            f"add table inet {private_netns_probe.PRIVATE_TABLE}", batch
        )
        self.assertIn(
            f'iifname "{private_netns_probe.BRIDGE_NAME}" oifname "{private_netns_probe.BRIDGE_NAME}" accept',
            batch,
        )
        self.assertIn(
            f'iifname "{private_netns_probe.BRIDGE_NAME}" drop', batch
        )
        self.assertNotIn("0.0.0.0", batch)
        self.assertNotIn("172.31.253", batch)

    def private_container_fixture(self) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        service_id = "a" * 64
        client_id = "b" * 64

        def container(role: str, size: str) -> dict[str, object]:
            return {
                "Config": {
                    "Labels": {
                        "io.fawxzzy.packet": "FP-TEST-PACKET",
                        "io.fawxzzy.role": role,
                    }
                },
                "HostConfig": {
                    "Tmpfs": {
                        "/var/lib/postgresql/data": f"rw,nosuid,nodev,noexec,size={size}"
                    },
                    "NetworkMode": private_netns_probe.NETWORK_NAME,
                    "Privileged": False,
                    "PublishAllPorts": False,
                    "PidMode": "",
                    "IpcMode": "private",
                    "Binds": None,
                    "Mounts": [],
                    "CapAdd": None,
                    "Devices": [],
                    "PortBindings": {},
                    "SecurityOpt": ["no-new-privileges"],
                },
                "NetworkSettings": {
                    "Networks": {private_netns_probe.NETWORK_NAME: {}},
                    "Ports": {"5432/tcp": None},
                },
                "Mounts": [],
            }

        containers = [
            container("private-netns-service", "512m"),
            container("private-netns-client", "64m"),
        ]
        network = [{
            "Driver": "bridge",
            "Internal": True,
            "EnableIPv6": False,
            "Options": {
                "com.docker.network.bridge.name": private_netns_probe.BRIDGE_NAME
            },
            "IPAM": {"Config": [{
                "Subnet": private_netns_probe.PRIVATE_SUBNET,
                "Gateway": private_netns_probe.PRIVATE_GATEWAY,
            }]},
            "Containers": {service_id: {}, client_id: {}},
        }]
        return containers, network

    def test_container_contract_accepts_only_exact_private_attachment_and_security(self) -> None:
        args = mock.Mock(
            runtime=Path("/packet/private-netns"),
            workspace_root=Path("/packet"),
            packet="FP-TEST-PACKET",
        )
        probe = private_netns_probe.Probe(args)
        probe.service_id = "a" * 64
        probe.client_id = "b" * 64
        containers, network = self.private_container_fixture()
        responses = [
            subprocess.CompletedProcess([], 0, json.dumps(containers).encode(), b""),
            subprocess.CompletedProcess([], 0, json.dumps(network).encode(), b""),
        ]
        with mock.patch.object(private_netns_probe, "run_command", side_effect=responses):
            probe.verify_container_contract()
        self.assertIs(
            probe.receipt["diagnostic.private_netns.network.exact_attachment"], True
        )
        self.assertIs(
            probe.receipt["diagnostic.private_netns.network.container_security"], True
        )

    def test_container_contract_rejects_network_publication_mount_and_privilege_drift(self) -> None:
        for mutation in ("extra_network", "binding", "bind", "privileged", "volume"):
            with self.subTest(mutation=mutation):
                args = mock.Mock(
                    runtime=Path("/packet/private-netns"),
                    workspace_root=Path("/packet"),
                    packet="FP-TEST-PACKET",
                )
                probe = private_netns_probe.Probe(args)
                probe.service_id = "a" * 64
                probe.client_id = "b" * 64
                containers, network = self.private_container_fixture()
                target = containers[0]
                if mutation == "extra_network":
                    target["NetworkSettings"]["Networks"]["foreign"] = {}
                elif mutation == "binding":
                    target["NetworkSettings"]["Ports"]["5432/tcp"] = [
                        {"HostIp": "127.0.0.1", "HostPort": "56422"}
                    ]
                elif mutation == "bind":
                    target["HostConfig"]["Binds"] = ["/host:/container"]
                elif mutation == "privileged":
                    target["HostConfig"]["Privileged"] = True
                else:
                    target["Mounts"] = [{"Type": "volume"}]
                responses = [
                    subprocess.CompletedProcess([], 0, json.dumps(containers).encode(), b""),
                    subprocess.CompletedProcess([], 0, json.dumps(network).encode(), b""),
                ]
                with mock.patch.object(private_netns_probe, "run_command", side_effect=responses):
                    with self.assertRaises(private_netns_probe.ProbeFailure) as raised:
                        probe.verify_container_contract()
                self.assertEqual(raised.exception.code, "PRIVATE_CONTAINER_CONTRACT_INVALID")

    def probe_fixture(self, runtime: Path | None = None) -> object:
        args = mock.Mock(
            runtime=runtime or Path("/packet/private-netns"),
            workspace_root=Path("/packet"),
            packet="FP-TEST-PACKET",
            listen_port=59422,
            image="postgres@sha256:" + "d" * 64,
            expected_image_id="sha256:" + "c" * 64,
        )
        probe = private_netns_probe.Probe(args)
        probe.service_id = "a" * 64
        probe.client_id = "b" * 64
        return probe

    def test_network_denial_requires_exact_attempt_and_denied_result(self) -> None:
        probe = self.probe_fixture()
        denied = subprocess.CompletedProcess(
            [], 0, b"FP_CANARY_ATTEMPTED\nFP_CANARY_RESULT:1\n", b""
        )
        with mock.patch.object(private_netns_probe, "run_command", return_value=denied):
            probe.exec_network_denial("fixed-command", frozenset({1, 124}), "PRIVATE_LITERAL_IP_EGRESS_SUCCEEDED")
        reachable = subprocess.CompletedProcess(
            [], 0, b"FP_CANARY_ATTEMPTED\nFP_CANARY_RESULT:0\n", b""
        )
        with mock.patch.object(private_netns_probe, "run_command", return_value=reachable):
            with self.assertRaises(private_netns_probe.ProbeFailure) as raised:
                probe.exec_network_denial("fixed-command", frozenset({1, 124}), "PRIVATE_LITERAL_IP_EGRESS_SUCCEEDED")
        self.assertEqual(raised.exception.code, "PRIVATE_LITERAL_IP_EGRESS_SUCCEEDED")

    def test_network_denial_rejects_missing_tool_runtime_timeout_and_malformed_evidence(self) -> None:
        probe = self.probe_fixture()
        missing = subprocess.CompletedProcess([], 127, b"", b"")
        with mock.patch.object(private_netns_probe, "run_command", return_value=missing):
            with self.assertRaises(private_netns_probe.ProbeFailure) as raised:
                probe.preflight_canary_tools()
        self.assertEqual(raised.exception.code, "PRIVATE_CANARY_TOOL_MISSING")

        cases = (
            (
                "runtime",
                subprocess.CompletedProcess([], 125, b"", b""),
                "PRIVATE_CANARY_RUNTIME_FAILED",
            ),
            (
                "unexpected-result",
                subprocess.CompletedProcess([], 0, b"FP_CANARY_ATTEMPTED\nFP_CANARY_RESULT:125\n", b""),
                "PRIVATE_CANARY_RUNTIME_FAILED",
            ),
            (
                "malformed",
                subprocess.CompletedProcess([], 0, b"FP_CANARY_RESULT:1\n", b""),
                "PRIVATE_CANARY_EVIDENCE_INVALID",
            ),
        )
        for name, result, expected in cases:
            with self.subTest(name=name):
                with mock.patch.object(private_netns_probe, "run_command", return_value=result):
                    with self.assertRaises(private_netns_probe.ProbeFailure) as raised:
                        probe.exec_network_denial("fixed-command", frozenset({1, 124}), "PRIVATE_LITERAL_IP_EGRESS_SUCCEEDED")
                self.assertEqual(raised.exception.code, expected)
        with mock.patch.object(
            private_netns_probe,
            "run_command",
            side_effect=subprocess.TimeoutExpired(["docker", "exec"], 10),
        ):
            with self.assertRaises(private_netns_probe.ProbeFailure) as raised:
                probe.exec_network_denial("fixed-command", frozenset({1, 124}), "PRIVATE_LITERAL_IP_EGRESS_SUCCEEDED")
        self.assertEqual(raised.exception.code, "PRIVATE_CANARY_RUNTIME_FAILED")

    def test_canary_preflight_proves_the_same_internal_dns_tcp_timeout_and_ping_paths(self) -> None:
        probe = self.probe_fixture()
        success = subprocess.CompletedProcess([], 0, b"", b"")
        with mock.patch.object(
            private_netns_probe, "run_command", side_effect=[success, success]
        ) as runner:
            probe.preflight_canary_tools()
        rendered = "\n".join(" ".join(call.args[0]) for call in runner.call_args_list)
        for fragment in ("command -v", "getent hosts", "/dev/tcp/", "timeout 3", "ping -c 1"):
            self.assertIn(fragment, rendered)
        failed_resolution = subprocess.CompletedProcess([], 2, b"", b"")
        with mock.patch.object(
            private_netns_probe,
            "run_command",
            side_effect=[success, failed_resolution],
        ):
            with self.assertRaises(private_netns_probe.ProbeFailure) as raised:
                probe.preflight_canary_tools()
        self.assertEqual(raised.exception.code, "PRIVATE_INTERCONTAINER_FAILED")

    def test_every_private_cleanup_command_failure_continues_later_teardown(self) -> None:
        actions = (
            "REMOVE_CLIENT",
            "REMOVE_SERVICE",
            "REMOVE_NETWORK",
            "REMOVE_IMAGE",
            "QUERY_CONTAINERS",
            "QUERY_VOLUMES",
            "QUERY_NETWORKS",
            "QUERY_IMAGES",
            "DELETE_NETNS",
            "QUERY_NETNS",
        )
        for failure_kind in ("timeout", "error"):
            for failure_index, expected_action in enumerate(actions):
                with self.subTest(kind=failure_kind, action=expected_action):
                    with tempfile.TemporaryDirectory() as temporary:
                        runtime = Path(temporary) / "private-netns"
                        runtime.mkdir()
                        probe = self.probe_fixture(runtime)
                        probe.private_image_id = "c" * 64
                        probe.netns_created = True
                        probe.host_firewall_pre = ("d" * 64, "e" * 64, {"table": 1})
                        probe.host_link_pre = "f" * 64
                        calls: list[list[str]] = []

                        def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
                            index = len(calls)
                            calls.append(command)
                            if index == failure_index:
                                if failure_kind == "timeout":
                                    raise subprocess.TimeoutExpired(command, 10)
                                return subprocess.CompletedProcess(command, 1, b"", b"")
                            return subprocess.CompletedProcess(command, 0, b"", b"")

                        with mock.patch.object(Path, "is_socket", lambda path: path.name == "docker.sock"):
                            with mock.patch.object(probe, "private_docker_target_present", return_value=True):
                                with mock.patch.object(private_netns_probe, "run_command", side_effect=fake_run):
                                    with mock.patch.object(
                                        probe,
                                        "host_firewall_snapshot",
                                        return_value=probe.host_firewall_pre,
                                    ):
                                        with mock.patch.object(probe, "host_links", return_value=probe.host_link_pre):
                                            cleanup_ok = probe.cleanup()
                        self.assertFalse(cleanup_ok)
                        self.assertEqual(len(calls), len(actions))
                        self.assertEqual(probe.cleanup_failures, [expected_action])
                        self.assertEqual(
                            probe.receipt["diagnostic.private_netns.cleanup.command_failure_count"], 1
                        )
                        self.assertTrue(
                            probe.receipt[
                                "diagnostic.private_netns.cleanup.completeness_finalized"
                            ]
                        )
                        self.assertFalse(
                            probe.receipt["diagnostic.private_netns.cleanup.proof_complete"]
                        )
                        self.assertEqual(
                            probe.receipt[
                                "diagnostic.private_netns.cleanup.query_failure_count"
                            ]
                            + probe.receipt[
                                "diagnostic.private_netns.cleanup.action_failure_count"
                            ],
                            1,
                        )
                        self.assertEqual(
                            probe.receipt["diagnostic.private_netns.cleanup.namespaces_remaining"],
                            1 if expected_action == "QUERY_NETNS" else 0,
                        )
                        self.assertFalse(runtime.exists())
                        self.assertEqual(
                            probe.receipt["diagnostic.private_netns.host_links.final_sha256"],
                            probe.host_link_pre,
                        )

    def test_resource_creation_ambiguity_prelatches_exact_cleanup_targets(self) -> None:
        cases = (
            ("image", "REMOVE_IMAGE", "PRIVATE_IMAGE_LOAD_FAILED"),
            ("network", "REMOVE_NETWORK", "PRIVATE_NETWORK_CREATE_FAILED"),
            ("service", "REMOVE_SERVICE", "PRIVATE_CONTAINER_CREATE_FAILED"),
            ("client", "REMOVE_CLIENT", "PRIVATE_CONTAINER_CREATE_FAILED"),
        )
        expected_targets = {
            "REMOVE_IMAGE": "sha256:" + "c" * 64,
            "REMOVE_NETWORK": private_netns_probe.NETWORK_NAME,
            "REMOVE_SERVICE": private_netns_probe.SERVICE_NAME,
            "REMOVE_CLIENT": private_netns_probe.CLIENT_NAME,
        }
        for failure_kind in ("timeout", "error"):
            for operation, action, expected_code in cases:
                with self.subTest(kind=failure_kind, operation=operation):
                    probe = self.probe_fixture()
                    failed = (
                        subprocess.TimeoutExpired(["docker"], 45)
                        if failure_kind == "timeout"
                        else subprocess.CompletedProcess([], 1, b"", b"")
                    )
                    responses: list[object]
                    if operation == "client":
                        responses = [
                            subprocess.CompletedProcess([], 0, ("a" * 64).encode(), b""),
                            failed,
                        ]
                    else:
                        responses = [failed]
                    with mock.patch.object(
                        private_netns_probe, "run_command", side_effect=responses
                    ):
                        if failure_kind == "timeout":
                            with self.assertRaises(subprocess.TimeoutExpired):
                                if operation == "image":
                                    probe.load_image()
                                elif operation == "network":
                                    probe.create_private_network()
                                else:
                                    probe.start_containers()
                        else:
                            with self.assertRaises(private_netns_probe.ProbeFailure) as raised:
                                if operation == "image":
                                    probe.load_image()
                                elif operation == "network":
                                    probe.create_private_network()
                                else:
                                    probe.start_containers()
                            self.assertEqual(raised.exception.code, expected_code)
                    self.assertIn(action, probe.private_docker_action_obligations)
                    self.assertEqual(
                        probe.private_docker_action_target(action),
                        expected_targets[action],
                    )
                    with mock.patch.object(
                        probe, "private_docker_target_present", return_value=True
                    ):
                        with mock.patch.object(
                            private_netns_probe,
                            "run_command",
                            return_value=subprocess.CompletedProcess([], 0, b"", b""),
                        ) as remover:
                            self.assertTrue(probe.cleanup_private_docker_action(action))
                    remove_command = remover.call_args.args[0]
                    self.assertEqual(remove_command, probe.private_docker_action_command(action))
                    self.assertEqual(probe.cleanup_action_required, [action])
                    self.assertEqual(probe.cleanup_action_attempted, [action])
                    self.assertEqual(probe.cleanup_action_succeeded, [action])
                    probe.receipt["diagnostic.private_netns.cleanup.attempted"] = True
                    probe.finalize_cleanup_failures()
                    probe.finalize_cleanup_completeness()
                    probe.receipt["diagnostic.private_netns.failure_code"] = expected_code
                    private_netns_probe.finalize_receipt(probe.receipt)
                    first = private_netns_probe.format_receipt(probe.receipt)
                    second = private_netns_probe.format_receipt(probe.receipt)
                    self.assertEqual(first, second)

    def test_prelatched_cleanup_is_idempotent_when_target_is_absent(self) -> None:
        for action in private_netns_probe.DOCKER_CLEANUP_ACTION_ORDER:
            with self.subTest(action=action):
                probe = self.probe_fixture()
                probe.latch_private_docker_action(action)
                with mock.patch.object(
                    probe, "private_docker_target_present", return_value=False
                ):
                    with mock.patch.object(private_netns_probe, "run_command") as runner:
                        self.assertTrue(probe.cleanup_private_docker_action(action))
                runner.assert_not_called()
                self.assertEqual(probe.cleanup_failures, [])
                self.assertEqual(probe.cleanup_action_required, [action])
                self.assertEqual(probe.cleanup_action_attempted, [action])
                self.assertEqual(probe.cleanup_action_succeeded, [action])

    def test_cleanup_target_presence_is_closed_and_fail_closed(self) -> None:
        probe = self.probe_fixture()
        present_outputs = {
            "REMOVE_CLIENT": (private_netns_probe.CLIENT_NAME + "\n").encode(),
            "REMOVE_SERVICE": (private_netns_probe.SERVICE_NAME + "\n").encode(),
            "REMOVE_NETWORK": ("bridge\n" + private_netns_probe.NETWORK_NAME + "\n").encode(),
            "REMOVE_IMAGE": ("sha256:" + "c" * 64 + "\n").encode(),
        }
        for action, output in present_outputs.items():
            with self.subTest(action=action, state="present"):
                with mock.patch.object(
                    private_netns_probe,
                    "run_command",
                    return_value=subprocess.CompletedProcess([], 0, output, b""),
                ):
                    self.assertIs(probe.private_docker_target_present(action), True)
            with self.subTest(action=action, state="absent"):
                with mock.patch.object(
                    private_netns_probe,
                    "run_command",
                    return_value=subprocess.CompletedProcess([], 0, b"", b""),
                ):
                    self.assertIs(probe.private_docker_target_present(action), False)
        for result in (
            subprocess.CompletedProcess([], 1, b"", b""),
            subprocess.CompletedProcess([], 0, b"invalid value\n", b""),
        ):
            with mock.patch.object(private_netns_probe, "run_command", return_value=result):
                self.assertIs(
                    probe.private_docker_target_present("REMOVE_NETWORK"), None
                )
        with mock.patch.object(
            private_netns_probe,
            "run_command",
            side_effect=subprocess.TimeoutExpired(["docker"], 10),
        ):
            self.assertIs(probe.private_docker_target_present("REMOVE_IMAGE"), None)

    def test_successful_cleanup_proves_every_query_action_and_zero_residue(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "private-netns"
            runtime.mkdir()
            probe = self.probe_fixture(runtime)
            probe.netns_created = True
            probe.host_firewall_pre = ("d" * 64, "e" * 64, {"table": 1})
            probe.host_link_pre = "f" * 64
            success = subprocess.CompletedProcess([], 0, b"", b"")
            with mock.patch.object(Path, "is_socket", lambda path: path.name == "docker.sock"):
                with mock.patch.object(private_netns_probe, "run_command", return_value=success):
                    with mock.patch.object(
                        probe, "host_firewall_snapshot", return_value=probe.host_firewall_pre
                    ):
                        with mock.patch.object(probe, "host_links", return_value=probe.host_link_pre):
                            self.assertTrue(probe.cleanup())
        cleanup = "diagnostic.private_netns.cleanup."
        self.assertTrue(probe.receipt[f"{cleanup}completeness_finalized"])
        self.assertTrue(probe.receipt[f"{cleanup}query_complete"])
        self.assertTrue(probe.receipt[f"{cleanup}action_complete"])
        self.assertTrue(probe.receipt[f"{cleanup}proof_complete"])
        self.assertGreater(probe.receipt[f"{cleanup}query_required_count"], 0)
        self.assertGreater(probe.receipt[f"{cleanup}action_required_count"], 0)
        for category in ("query", "action"):
            self.assertEqual(
                probe.receipt[f"{cleanup}{category}_required_count"],
                probe.receipt[f"{cleanup}{category}_attempted_count"],
            )
            self.assertEqual(
                probe.receipt[f"{cleanup}{category}_attempted_count"],
                probe.receipt[f"{cleanup}{category}_succeeded_count"],
            )
            self.assertEqual(probe.receipt[f"{cleanup}{category}_failure_count"], 0)
        private_netns_probe.finalize_receipt(probe.receipt)
        first = private_netns_probe.format_receipt(probe.receipt)
        second = private_netns_probe.format_receipt(probe.receipt)
        self.assertEqual(first, second)

    def test_host_cleanup_query_failure_is_counted_and_never_hidden_by_zero_residue(self) -> None:
        for failing_method, expected_failure in (
            ("host_firewall_snapshot", "QUERY_HOST_FIREWALL"),
            ("host_links", "QUERY_HOST_LINKS"),
        ):
            with self.subTest(query=failing_method):
                probe = self.probe_fixture()
                probe.service_id = ""
                probe.client_id = ""
                probe.host_firewall_pre = ("d" * 64, "e" * 64, {"table": 1})
                probe.host_link_pre = "f" * 64
                success = subprocess.CompletedProcess([], 0, b"", b"")
                with mock.patch.object(private_netns_probe, "run_command", return_value=success):
                    with mock.patch.object(
                        probe,
                        "host_firewall_snapshot",
                        side_effect=(
                            OSError("withheld")
                            if failing_method == "host_firewall_snapshot"
                            else None
                        ),
                        return_value=probe.host_firewall_pre,
                    ):
                        with mock.patch.object(
                            probe,
                            "host_links",
                            side_effect=(
                                OSError("withheld") if failing_method == "host_links" else None
                            ),
                            return_value=probe.host_link_pre,
                        ):
                            self.assertFalse(probe.cleanup())
                cleanup = "diagnostic.private_netns.cleanup."
                self.assertEqual(probe.cleanup_failures, [expected_failure])
                self.assertEqual(probe.receipt[f"{cleanup}query_failure_count"], 1)
                self.assertFalse(probe.receipt[f"{cleanup}query_complete"])
                self.assertFalse(probe.receipt[f"{cleanup}proof_complete"])
                self.assertTrue(probe.receipt[f"{cleanup}action_complete"])

    def test_latched_docker_cleanup_obligations_survive_missing_or_wrong_socket(self) -> None:
        class CleanupProcess:
            def __init__(self) -> None:
                self.stopped = False

            def poll(self) -> int | None:
                return 0 if self.stopped else None

            def send_signal(self, _signal: int) -> None:
                return None

            def wait(self, timeout: int) -> int:
                self.stopped = True
                return 0

        unavailable_actions = list(private_netns_probe.DOCKER_CLEANUP_ACTION_ORDER)
        unavailable_queries = [item[0] for item in private_netns_probe.DOCKER_CLEANUP_QUERY_SPECS]
        for socket_state in ("missing", "wrong_type"):
            with self.subTest(socket_state=socket_state):
                with tempfile.TemporaryDirectory() as temporary:
                    runtime = Path(temporary) / "private-netns"
                    runtime.mkdir()
                    if socket_state == "wrong_type":
                        (runtime / "docker.sock").write_bytes(b"not-a-socket")
                    probe = self.probe_fixture(runtime)
                    probe.receipt[
                        "diagnostic.private_netns.isolation.private_dockerd_socket"
                    ] = True
                    probe.receipt[
                        "diagnostic.private_netns.network.private_network_count"
                    ] = 1
                    probe.private_image_id = "c" * 64
                    probe.service_id = "a" * 64
                    probe.client_id = "b" * 64
                    dockerd_process = CleanupProcess()
                    containerd_process = CleanupProcess()
                    probe.dockerd_process = dockerd_process
                    probe.containerd_process = containerd_process
                    probe.processes = [dockerd_process, containerd_process]
                    probe.netns_created = True
                    probe.host_firewall_pre = ("d" * 64, "e" * 64, {"table": 1})
                    probe.host_link_pre = "f" * 64
                    calls: list[list[str]] = []

                    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
                        calls.append(command)
                        return subprocess.CompletedProcess(command, 0, b"", b"")

                    with mock.patch.object(private_netns_probe, "run_command", side_effect=fake_run):
                        with mock.patch.object(
                            probe, "host_firewall_snapshot", return_value=probe.host_firewall_pre
                        ):
                            with mock.patch.object(probe, "host_links", return_value=probe.host_link_pre):
                                self.assertFalse(probe.cleanup())

                cleanup = "diagnostic.private_netns.cleanup."
                self.assertEqual(
                    probe.cleanup_failures,
                    [*unavailable_actions, *unavailable_queries],
                )
                self.assertEqual(
                    probe.receipt[f"{cleanup}query_required_count"],
                    len(unavailable_queries) + 4,
                )
                self.assertEqual(probe.receipt[f"{cleanup}query_attempted_count"], 4)
                self.assertEqual(probe.receipt[f"{cleanup}query_succeeded_count"], 4)
                self.assertFalse(probe.receipt[f"{cleanup}query_complete"])
                self.assertEqual(
                    probe.receipt[f"{cleanup}action_required_count"],
                    len(unavailable_actions) + 4,
                )
                self.assertEqual(probe.receipt[f"{cleanup}action_attempted_count"], 4)
                self.assertEqual(probe.receipt[f"{cleanup}action_succeeded_count"], 4)
                self.assertFalse(probe.receipt[f"{cleanup}action_complete"])
                self.assertEqual(
                    probe.receipt[f"{cleanup}command_failure_count"],
                    len(unavailable_actions) + len(unavailable_queries),
                )
                self.assertFalse(probe.receipt[f"{cleanup}proof_complete"])
                self.assertFalse(probe.receipt[f"{cleanup}succeeded"])
                self.assertEqual(
                    [
                        probe.receipt[f"{cleanup}{receipt_name}"]
                        for _, receipt_name, _ in private_netns_probe.DOCKER_CLEANUP_QUERY_SPECS
                    ],
                    [0, 0, 0, 0],
                )
                self.assertFalse(runtime.exists())
                self.assertTrue(dockerd_process.stopped)
                self.assertTrue(containerd_process.stopped)
                self.assertTrue(
                    any(
                        command[:4]
                        == ["ip", "netns", "delete", private_netns_probe.NS_NAME]
                        for command in calls
                    )
                )
                self.assertFalse(any(command and command[0] == "docker" for command in calls))
                probe.receipt["diagnostic.private_netns.failure_code"] = "PRIVATE_CLEANUP_FAILED"
                private_netns_probe.finalize_receipt(probe.receipt)
                first = private_netns_probe.format_receipt(probe.receipt)
                second = private_netns_probe.format_receipt(probe.receipt)
                self.assertEqual(first, second)

    def test_startup_and_cleanup_public_vocabulary_is_closed_and_documented(self) -> None:
        contract = (ROOT / "docs/CONTAINMENT_CONTRACT.md").read_text(encoding="utf-8")
        for substage in sorted(private_netns_probe.STARTUP_SUBSTAGES):
            self.assertIn(substage, self.source)
            self.assertIn(substage, self.runner)
            self.assertIn(substage, contract)
        for field in (
            "startup.terminal_substage",
            "cleanup.query_required_count",
            "cleanup.query_attempted_count",
            "cleanup.query_succeeded_count",
            "cleanup.query_failure_count",
            "cleanup.query_complete",
            "cleanup.action_required_count",
            "cleanup.action_attempted_count",
            "cleanup.action_succeeded_count",
            "cleanup.action_failure_count",
            "cleanup.action_complete",
            "cleanup.completeness_finalized",
            "cleanup.proof_complete",
        ):
            self.assertIn(field, self.source)
        self.assertIn("required, attempted, succeeded, and failed cleanup queries", contract)
        self.assertIn("Containerd stdout and stderr remain discarded", contract)

    def test_unexpected_cleanup_timeout_still_publishes_blocked_receipt(self) -> None:
        class TimeoutCleanupProbe(private_netns_probe.Probe):
            def execute(self) -> None:
                return None

            def cleanup(self) -> bool:
                self.receipt["diagnostic.private_netns.cleanup.attempted"] = True
                raise subprocess.TimeoutExpired(["docker", "rm"], 20)

        args = mock.Mock(
            runtime=Path("/packet/private-netns"),
            workspace_root=Path("/packet"),
            packet="FP-TEST-PACKET",
            listen_port=59422,
        )
        with mock.patch.object(private_netns_probe, "Probe", TimeoutCleanupProbe):
            with mock.patch("sys.stdout", new_callable=io.StringIO) as stdout:
                rc = private_netns_probe.run_probe(args)
        self.assertEqual(rc, 1)
        receipt = private_netns_probe.parse_receipt(stdout.getvalue().encode())
        self.assertEqual(
            receipt["diagnostic.private_netns.classification"],
            private_netns_probe.REJECT_CLASS,
        )
        self.assertEqual(
            receipt["diagnostic.private_netns.failure_code"], "PRIVATE_CLEANUP_FAILED"
        )
        self.assertEqual(
            receipt["diagnostic.private_netns.cleanup.command_failure_count"], 1
        )

    def test_daemon_stop_timeout_is_recorded_even_when_kill_completes(self) -> None:
        class TimeoutProcess:
            def __init__(self) -> None:
                self.wait_count = 0
                self.killed = False

            def poll(self) -> None:
                return None

            def send_signal(self, _signal: int) -> None:
                return None

            def wait(self, timeout: int) -> int:
                self.wait_count += 1
                if self.wait_count == 1:
                    raise subprocess.TimeoutExpired(["dockerd"], timeout)
                return 0

            def kill(self) -> None:
                self.killed = True

        probe = self.probe_fixture()
        process = TimeoutProcess()
        self.assertFalse(probe.stop_process("STOP_DOCKERD", process))
        self.assertTrue(process.killed)
        self.assertEqual(probe.cleanup_failures, ["STOP_DOCKERD"])

    def test_firewall_digests_ignore_only_admitted_volatile_fields(self) -> None:
        first = {
            "nftables": [
                {"metainfo": {"json_schema_version": 1}},
                {"table": {"family": "inet", "name": "foreign", "handle": 1}},
                {"chain": {"family": "inet", "table": "foreign", "name": "input", "handle": 2}},
                {
                    "rule": {
                        "family": "inet",
                        "table": "foreign",
                        "chain": "input",
                        "expr": [{"counter": {"packets": 1, "bytes": 2}}, {"accept": None}],
                        "handle": 3,
                    }
                },
            ]
        }
        volatile = copy.deepcopy(first)
        volatile["nftables"][1]["table"]["handle"] = 91
        volatile["nftables"][3]["rule"]["expr"][0]["counter"]["packets"] = 99
        a = private_netns_probe.firewall_snapshot_from_json(json.dumps(first).encode())
        b = private_netns_probe.firewall_snapshot_from_json(json.dumps(volatile).encode())
        self.assertEqual(a, b)
        reordered = {"nftables": [first["nftables"][0], first["nftables"][2], first["nftables"][1], first["nftables"][3]]}
        c = private_netns_probe.firewall_snapshot_from_json(json.dumps(reordered).encode())
        self.assertNotEqual(a[0], c[0])
        self.assertEqual(a[1], c[1])
        semantic_drift = copy.deepcopy(first)
        semantic_drift["nftables"][3]["rule"]["expr"][-1] = {"drop": None}
        d = private_netns_probe.firewall_snapshot_from_json(json.dumps(semantic_drift).encode())
        self.assertNotEqual(a[1], d[1])

    def test_host_link_digest_ignores_index_but_not_topology(self) -> None:
        first = [{"ifindex": 2, "ifname": "eth0", "flags": ["UP"], "link_type": "ether", "address": "00:11"}]
        second = [{"ifindex": 90, "ifname": "eth0", "flags": ["UP"], "link_type": "ether", "address": "aa:bb"}]
        changed = [{"ifindex": 2, "ifname": "veth-owned", "flags": ["UP"], "link_type": "ether", "address": "00:11"}]
        self.assertEqual(
            private_netns_probe.host_link_digest(json.dumps(first).encode()),
            private_netns_probe.host_link_digest(json.dumps(second).encode()),
        )
        self.assertNotEqual(
            private_netns_probe.host_link_digest(json.dumps(first).encode()),
            private_netns_probe.host_link_digest(json.dumps(changed).encode()),
        )

    def test_probe_source_forbids_install_and_host_configuration_mutation(self) -> None:
        for forbidden in (
            "apt-get",
            "apt install",
            "dnf install",
            "sysctl -w",
            "systemctl",
            "service docker",
            "--privileged",
            "tcp://",
            "/etc/docker",
            "docker context",
            "buildkit",
            "supabase",
        ):
            self.assertNotIn(forbidden, self.source.lower())
        self.assertNotIn("shell=True", self.source)
        self.assertIn('subprocess.DEVNULL', self.source)

    def test_runner_invokes_probe_before_host_network_creation_and_never_cli(self) -> None:
        function = self.runner[
            self.runner.index("run_private_docker_netns_probe() {") : self.runner.index(
                "firewall_counter_value() {"
            )
        ]
        self.assertIn('sudo -n env -i', function)
        self.assertIn('private_docker_netns_probe.py', function)
        self.assertIn('validate --input "$PRIVATE_NETNS_STATE_FILE"', function)
        self.assertIn('rm -f -- "$probe_stderr"', function)
        self.assertNotIn("supabase", function.lower())
        self.assertNotIn("gotrue", function.lower())
        dispatch = self.runner.index(
            'if [[ "$MODE" == "private-netns-probe" ]]; then\n  run_private_docker_netns_probe'
        )
        self.assertLess(dispatch, self.runner.index("mapfile -t existing_prefixes"))

    def test_namespace_process_cgroup_canary_and_cleanup_gates_are_mandatory(self) -> None:
        for fragment in (
            "namespace_identity",
            "containerd-shim",
            "cgroup.procs",
            "PRIVATE_INTERCONTAINER_FAILED",
            "PRIVATE_DEFAULT_ROUTE_PRESENT",
            "PRIVATE_EXTERNAL_DNS_SUCCEEDED",
            "PRIVATE_LITERAL_IP_EGRESS_SUCCEEDED",
            "PRIVATE_METADATA_EGRESS_SUCCEEDED",
            "PRIVATE_GATEWAY_REACHABLE",
            "PRIVATE_REGISTRY_ACCESS_SUCCEEDED",
            "127.0.0.1",
            "cleanup.containers_remaining",
            "cleanup.images_remaining",
            "cleanup.volumes_remaining",
            "cleanup.networks_remaining",
            "cleanup.listeners_remaining",
            "cleanup.processes_remaining",
            "cleanup.namespaces_remaining",
            "cleanup.veths_remaining",
            "cleanup.cgroups_remaining",
            "cleanup.scratch_remaining",
        ):
            self.assertIn(fragment, self.source)
        self.assertIn("links_restored and namespace_count == 0", self.source)
        self.assertNotIn('cleanup.veths_remaining\"] = 0\n', self.source)

    def test_missing_required_pass_evidence_becomes_stable_rejection(self) -> None:
        class IncompleteProbe:
            def __init__(self, _args: object):
                self.receipt = private_netns_probe.default_receipt()

            def execute(self) -> None:
                return None

            def cleanup(self) -> bool:
                self.receipt["diagnostic.private_netns.cleanup.succeeded"] = True
                return True

        with mock.patch.object(private_netns_probe, "Probe", IncompleteProbe):
            with mock.patch("sys.stdout", new_callable=io.StringIO) as stdout:
                rc = private_netns_probe.run_probe(object())
        self.assertEqual(rc, 1)
        receipt = private_netns_probe.parse_receipt(stdout.getvalue().encode())
        self.assertEqual(
            receipt["diagnostic.private_netns.classification"],
            private_netns_probe.REJECT_CLASS,
        )
        self.assertEqual(
            receipt["diagnostic.private_netns.failure_code"], "PRIVATE_CLEANUP_FAILED"
        )
        self.assertFalse(
            receipt["diagnostic.private_netns.cleanup.completeness_finalized"]
        )
        self.assertFalse(receipt["diagnostic.private_netns.cleanup.proof_complete"])

    def test_runner_cleanup_contract_includes_private_packet_and_scratch(self) -> None:
        self.assertIn('"label=io.fawxzzy.packet=${PRIVATE_NETNS_PACKET}"', self.runner)
        self.assertIn('run|direct-port|private-netns-probe', self.runner)
        self.assertIn('"private-netns/",', self.runner)
        self.assertIn('"private-netns-probe.tsv",', self.runner)
        self.assertIn(
            'mode$\'\\t\'str$\'\\t\'(run|direct-port|firewall-rehearsal|private-netns-probe)',
            self.runner,
        )


class FirewallBoundaryTests(unittest.TestCase):
    @staticmethod
    def _marker_diagnostic(entries: list[dict]) -> dict[str, object]:
        return firewall_boundary.diagnose_marker_rule_expressions(
            entries,
            firewall_boundary.TABLE,
            "br-fpro001",
            "172.31.253.0/24",
            "172.31.253.10",
            "172.31.253.11",
            "172.17.0.4",
            "172.31.253.1",
            18080,
        )

    @staticmethod
    def _marker_rules(entries: list[dict]) -> list[dict]:
        return [
            entry["rule"]
            for entry in entries
            if isinstance(entry.get("rule"), dict)
            and entry["rule"].get("chain") in firewall_boundary.MARKER_CHAINS
        ]

    @staticmethod
    def _prepared_ledger_payload(foreign: list[dict]) -> dict[str, object]:
        pre_sha, pre_counts = firewall_boundary.canonical_snapshot(foreign)
        return {
            "schema": firewall_boundary.SCHEMA,
            "table": firewall_boundary.TABLE,
            "interface": "br-fpro001",
            "subnet": "172.31.253.0/24",
            "preimage_sha256": pre_sha,
            "preimage_semantic_sha256": firewall_boundary.semantic_snapshot(foreign),
            "preimage_counts": pre_counts,
            "installation_sha256": "",
            "installation_semantic_sha256": "",
            "installation_counts": {},
            "installed": False,
            "owned_sha256": "",
            "markers_installed": False,
            "marker_sha256": "",
            "combined_sha256": "",
        }

    @staticmethod
    def _restoration_ledger_payload(
        foreign: list[dict], *, markers_installed: bool = True,
        installation_foreign: list[dict] | None = None,
    ) -> dict[str, object]:
        pre_sha, pre_counts = firewall_boundary.canonical_snapshot(foreign)
        installation = foreign if installation_foreign is None else installation_foreign
        installation_sha, installation_counts = firewall_boundary.canonical_snapshot(
            installation
        )
        owned = (
            owned_firewall_entries_with_markers()
            if markers_installed
            else owned_firewall_entries()
        )
        owned_sha, _ = firewall_boundary.validate_owned(
            owned, firewall_boundary.TABLE, markers_installed=markers_installed
        )
        marker_sha = ""
        combined_sha = ""
        if markers_installed:
            marker_sha, _ = firewall_boundary.canonical_snapshot(
                firewall_boundary.marker_entries(owned, firewall_boundary.TABLE)
            )
            combined_sha = owned_sha
            owned_sha, _ = firewall_boundary.validate_owned(
                owned_firewall_entries(), firewall_boundary.TABLE
            )
        return {
            "schema": firewall_boundary.SCHEMA,
            "table": firewall_boundary.TABLE,
            "interface": "br-fpro001",
            "subnet": "172.31.253.0/24",
            "preimage_sha256": pre_sha,
            "preimage_semantic_sha256": firewall_boundary.semantic_snapshot(foreign),
            "preimage_counts": pre_counts,
            "installation_sha256": installation_sha,
            "installation_semantic_sha256": firewall_boundary.semantic_snapshot(
                installation
            ),
            "installation_counts": installation_counts,
            "installed": True,
            "owned_sha256": owned_sha,
            "markers_installed": markers_installed,
            "marker_sha256": marker_sha,
            "combined_sha256": combined_sha,
        }

    @classmethod
    def _write_marker_state(
        cls, ledger_path: Path, marked: list[dict]
    ) -> tuple[dict[str, object], dict[str, object]]:
        ledger = firewall_boundary.read_ledger(ledger_path)
        batch = firewall_boundary.build_marker_batch(
            firewall_boundary.TABLE,
            "br-fpro001",
            "172.31.253.0/24",
            "172.31.253.10",
            "172.31.253.11",
            "172.17.0.4",
            "172.31.253.1",
            18080,
        )
        intent = firewall_boundary.build_marker_intent(
            ledger,
            "172.31.253.10",
            "172.31.253.11",
            "172.17.0.4",
            "172.31.253.1",
            18080,
            batch,
        )
        firewall_boundary.write_marker_intent(
            firewall_boundary.marker_intent_path(ledger_path), intent
        )
        marker_sha, _ = firewall_boundary.canonical_snapshot(
            firewall_boundary.marker_entries(marked, firewall_boundary.TABLE)
        )
        combined_sha, _ = firewall_boundary.validate_owned(
            marked, firewall_boundary.TABLE, markers_installed=True
        )
        installed = firewall_boundary.build_marker_installed(
            ledger,
            intent,
            marker_sha,
            combined_sha,
            cls._marker_diagnostic(marked),
        )
        firewall_boundary.write_marker_installed(
            firewall_boundary.marker_installed_path(ledger_path), installed
        )
        return intent, installed

    @staticmethod
    def _phase_contract_functions() -> str:
        runner = (ROOT / "scripts/run-containment-smoke.sh").read_text(encoding="utf-8")
        start = runner.index("firewall_phase_finish() {")
        end = runner.index("\nexpect_firewall_block() {", start)
        return runner[start:end]

    def _run_phase_contract(
        self,
        snapshots: list[tuple[str, int, int, int]],
        *,
        complete: bool = False,
        defer_finish: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            calls = "\n".join(
                f"CURRENT_INPUT={input_count}; CURRENT_FORWARD={forward_count}; "
                f"CURRENT_OUTPUT={output_count}; firewall_phase_snapshot {shlex.quote(phase)}"
                for phase, input_count, forward_count, output_count in snapshots
            )
            override = ""
            if defer_finish:
                override = "firewall_phase_finish() { printf 'FINISH:%s\\n' \"$1\"; }"
            finish = "firewall_phase_finish PRECANARY_SETUP_QUIESCENT" if complete else ""
            script = f"""set -Eeuo pipefail
FIREWALL_PHASE_MANIFEST={shlex.quote(str(Path(directory) / 'manifest.tsv'))}
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
SMOKE_PASSED=0
CURRENT_INPUT=0
CURRENT_FORWARD=0
CURRENT_OUTPUT=0
firewall_counter_value() {{
  case "$1" in
    input_deny) printf '%s\\n' "$CURRENT_INPUT" ;;
    forward_deny) printf '%s\\n' "$CURRENT_FORWARD" ;;
    output_deny) printf '%s\\n' "$CURRENT_OUTPUT" ;;
  esac
}}
record() {{ printf 'RECORD:%s:%s:%s\\n' "$1" "$2" "$3"; }}
block() {{ printf 'BLOCK:%s\\n' "$1"; exit 91; }}
{self._phase_contract_functions()}
{override}
{calls}
{finish}
printf 'FIRST:%s:%s\\n' "$FIREWALL_FIRST_HIT_CLASS" "$FIREWALL_FIRST_HIT_FROZEN"
printf 'SETUP:%s:%s\\n' "$FIREWALL_SETUP_OUTPUT_TOTAL" "$SMOKE_PASSED"
"""
            return subprocess.run(
                [bash_executable()],
                input=script,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )

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
        self.assertIn(
            "packet_output meta skuid 0 udp dport 53 counter name packet_output_deny drop",
            batch,
        )
        self.assertIn(
            "packet_output meta skuid 0 tcp dport 53 counter name packet_output_deny drop",
            batch,
        )
        self.assertLess(batch.index("meta skuid 0 udp"), batch.index("meta skuid 0 tcp"))
        for forbidden in ("flush ruleset", "flush table", "policy drop", "delete chain", "delete rule"):
            self.assertNotIn(forbidden, batch)
        self.assertEqual(batch.count(" iifname "), 5)
        self.assertEqual(batch.count("172.31.253.0/24"), 6)
        self.assertEqual(batch.count("meta skuid 0"), 2)
        self.assertEqual(batch.count("packet_output_deny"), 3)

    def test_marker_batch_is_atomic_flow_specific_and_has_no_verdict_or_broad_dns_marker(self) -> None:
        batch = firewall_boundary.build_marker_batch(
            firewall_boundary.TABLE,
            "br-fpro001",
            "172.31.253.0/24",
            "172.31.253.10",
            "172.31.253.11",
            "172.17.0.4",
            "172.31.253.1",
            18080,
        )
        self.assertEqual(batch.count("add counter inet"), 7)
        self.assertEqual(batch.count("add chain inet"), 3)
        self.assertEqual(batch.count("add rule inet"), 7)
        self.assertIn("priority -20; policy accept", batch)
        self.assertIn(
            'iifname "br-fpro001" oifname "br-fpro001" ip saddr 172.31.253.10 ip daddr 172.31.253.11 tcp dport 5432 counter name marker_same_network',
            batch,
        )
        self.assertIn(
            f"udp dport 53 @th,160,104 0x{firewall_boundary.DNS_QUESTION_HEX} counter name marker_external_dns",
            batch,
        )
        self.assertNotIn("marker_external_dns drop", batch)
        self.assertNotIn("meta skuid 0 udp dport 53 counter name marker_external_dns", batch)
        self.assertNotIn("flush", batch)
        self.assertNotIn("delete", batch)
        for invalid in (
            ("172.31.253.1", "172.31.253.11", "172.17.0.4", "172.31.253.1", 18080),
            ("172.31.253.10", "172.31.253.11", "172.31.253.12", "172.31.253.1", 18080),
            ("172.31.253.10", "172.31.253.11", "172.17.0.4", "172.31.253.0", 18080),
            ("172.31.253.10", "172.31.253.11", "172.17.0.4", "172.31.253.1", 0),
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(
                    firewall_boundary.BoundaryError,
                    "FIREWALL_MARKER_IDENTITY_INVALID",
                ):
                    firewall_boundary.build_marker_batch(
                        firewall_boundary.TABLE,
                        "br-fpro001",
                        "172.31.253.0/24",
                        *invalid,
                    )

    def test_marker_readback_requires_exact_ordered_libnftables_expressions(self) -> None:
        marked = owned_firewall_entries_with_markers()
        expression_sha = firewall_boundary.validate_marker_rule_expressions(
            marked,
            firewall_boundary.TABLE,
            "br-fpro001",
            "172.31.253.0/24",
            "172.31.253.10",
            "172.31.253.11",
            "172.17.0.4",
            "172.31.253.1",
            18080,
        )
        self.assertRegex(expression_sha, r"^[0-9a-f]{64}$")
        expected = firewall_boundary.expected_marker_rule_expressions(
            firewall_boundary.TABLE,
            "br-fpro001",
            "172.31.253.0/24",
            "172.31.253.10",
            "172.31.253.11",
            "172.17.0.4",
            "172.31.253.1",
            18080,
        )
        self.assertEqual(
            expected[firewall_boundary.MARKER_INPUT_CHAIN][0][-1],
            {"counter": firewall_boundary.MARKER_COUNTERS["gateway"]},
        )
        self.assertEqual(
            expected[firewall_boundary.MARKER_FORWARD_CHAIN][0][0],
            {
                "match": {
                    "op": "==",
                    "left": {"meta": {"key": "iifname"}},
                    "right": "br-fpro001",
                }
            },
        )
        self.assertEqual(
            expected[firewall_boundary.MARKER_OUTPUT_CHAIN][0][2],
            {
                "match": {
                    "op": "==",
                    "left": {"payload": {"base": "th", "offset": 160, "len": 104}},
                    "right": f"0x{firewall_boundary.DNS_QUESTION_HEX}",
                }
            },
        )

        marker_indices = [
            index
            for index, entry in enumerate(marked)
            if isinstance(entry.get("rule"), dict)
            and entry["rule"].get("chain") in firewall_boundary.MARKER_CHAINS
        ]
        cases: list[list[dict]] = []
        reordered_rules = copy.deepcopy(marked)
        reordered_rules[marker_indices[0]], reordered_rules[marker_indices[1]] = (
            reordered_rules[marker_indices[1]],
            reordered_rules[marker_indices[0]],
        )
        cases.append(reordered_rules)
        wrong_tuple = copy.deepcopy(marked)
        wrong_tuple[marker_indices[2]]["rule"]["expr"][3]["match"]["right"] = "172.31.253.12"
        cases.append(wrong_tuple)
        wrong_counter = copy.deepcopy(marked)
        wrong_counter[marker_indices[3]]["rule"]["expr"][-1] = {"counter": "marker_metadata"}
        cases.append(wrong_counter)
        broad_dns = copy.deepcopy(marked)
        broad_dns[marker_indices[-1]]["rule"]["expr"].pop(2)
        cases.append(broad_dns)
        unknown_expression = copy.deepcopy(marked)
        unknown_expression[marker_indices[4]]["rule"]["expr"].insert(0, {"accept": None})
        cases.append(unknown_expression)
        anonymous_counter = copy.deepcopy(marked)
        anonymous_counter[marker_indices[5]]["rule"]["expr"][-1] = {
            "counter": {"packets": 0, "bytes": 0}
        }
        cases.append(anonymous_counter)
        for entries in cases:
            with self.subTest(entries=entries):
                with self.assertRaisesRegex(
                    firewall_boundary.BoundaryError,
                    "FIREWALL_MARKER_INSTALLATION_MISMATCH",
                ):
                    firewall_boundary.validate_marker_rule_expressions(
                        entries,
                        firewall_boundary.TABLE,
                        "br-fpro001",
                        "172.31.253.0/24",
                        "172.31.253.10",
                        "172.31.253.11",
                        "172.17.0.4",
                        "172.31.253.1",
                        18080,
                    )

    def test_marker_diagnostic_inventory_is_closed_redacted_and_deterministic(self) -> None:
        base = owned_firewall_entries_with_markers()

        def changed() -> tuple[list[dict], list[dict]]:
            entries = copy.deepcopy(base)
            return entries, self._marker_rules(entries)

        cases: dict[str, list[dict]] = {"MATCHED_SHAPE": copy.deepcopy(base)}

        entries, rules = changed()
        rules[0]["expr"][0]["match"]["right"] = b"unsupported"
        cases["UNSUPPORTED_STRUCTURE"] = entries

        entries = copy.deepcopy(base)
        entries.append({"rule": "not-an-object"})
        cases["RULE_TYPE"] = entries

        entries, rules = changed()
        target = rules[-1]
        entries.remove(next(entry for entry in entries if entry.get("rule") is target))
        cases["RULE_COUNT"] = entries

        entries, rules = changed()
        marker_entries = [entry for entry in entries if entry.get("rule") in rules]
        marker_entries[0]["rule"], marker_entries[1]["rule"] = (
            marker_entries[1]["rule"],
            marker_entries[0]["rule"],
        )
        cases["RULE_ORDER"] = entries

        entries, rules = changed()
        rules[0]["unknown"] = True
        cases["RULE_KEYS"] = entries

        entries, rules = changed()
        rules[0]["family"] = "other-family"
        cases["RULE_IDENTITY"] = entries

        entries, rules = changed()
        rules[0]["expr"] = {"not": "a-list"}
        cases["EXPRESSION_COLLECTION_TYPE"] = entries

        entries, rules = changed()
        rules[0]["expr"].pop()
        cases["EXPRESSION_COUNT"] = entries

        entries, rules = changed()
        rules[0]["expr"][0], rules[0]["expr"][1] = (
            rules[0]["expr"][1],
            rules[0]["expr"][0],
        )
        cases["EXPRESSION_ORDER"] = entries

        entries, rules = changed()
        rules[0]["expr"][0] = "not-an-object"
        cases["EXPRESSION_TYPE"] = entries

        entries, rules = changed()
        rules[0]["expr"][0]["unknown"] = None
        cases["EXPRESSION_KEYS"] = entries

        entries, rules = changed()
        rules[0]["expr"][0] = {"counter": "different-kind"}
        cases["EXPRESSION_KIND_OR_ORDER"] = entries

        entries, rules = changed()
        rules[0]["expr"][0] = {"accept": None}
        cases["UNEXPECTED_VERDICT_OR_ACTION"] = entries

        entries, rules = changed()
        rules[0]["expr"][0]["match"].pop("right")
        cases["MATCH_KEYS"] = entries

        entries, rules = changed()
        rules[0]["expr"][0]["match"]["op"] = "!="
        cases["MATCH_OPERATOR"] = entries

        entries, rules = changed()
        rules[0]["expr"][0]["match"]["left"] = "not-an-object"
        cases["SELECTOR_TYPE"] = entries

        entries, rules = changed()
        selector = rules[0]["expr"][0]["match"]["left"]
        selector[next(iter(selector))]["unknown"] = True
        cases["SELECTOR_KIND_OR_KEYS"] = entries

        entries, rules = changed()
        selector = rules[0]["expr"][0]["match"]["left"]
        selector[next(iter(selector))]["key"] = "different-selector"
        cases["SELECTOR_IDENTITY"] = entries

        entries, rules = changed()
        rules[0]["expr"][0]["match"]["right"] = 7
        cases["RIGHT_VALUE_TYPE"] = entries

        entries, rules = changed()
        rules[0]["expr"][0]["match"]["right"] = "different-literal"
        cases["RIGHT_VALUE_IDENTITY"] = entries

        entries, rules = changed()
        rules[0]["expr"][-1]["counter"] = {"name": "different-counter"}
        cases["COUNTER_REFERENCE_SHAPE"] = entries

        entries, rules = changed()
        rules[0]["expr"][-1]["counter"] = {"reference": "different-counter"}
        cases["COUNTER_REFERENCE_KEYS"] = entries

        entries, rules = changed()
        rules[0]["expr"][-1]["counter"] = {"packets": 0, "bytes": 0}
        cases["COUNTER_DYNAMIC_FIELDS"] = entries

        entries, rules = changed()
        rules[0]["expr"][-1]["counter"] = "different-counter"
        cases["COUNTER_REFERENCE_IDENTITY"] = entries

        self.assertEqual(set(cases), firewall_boundary.MARKER_MISMATCH_CLASSES)
        observed_classes: set[str] = set()
        for expected_class, entries in cases.items():
            with self.subTest(expected_class=expected_class):
                first = self._marker_diagnostic(entries)
                second = self._marker_diagnostic(copy.deepcopy(entries))
                self.assertEqual(first, second)
                self.assertEqual(first["mismatch_class"], expected_class)
                self.assertEqual(first["schema"], firewall_boundary.MARKER_DIAGNOSTIC_SCHEMA)
                self.assertRegex(str(first["expected_shape_sha256"]), r"^[0-9a-f]{64}$")
                self.assertRegex(str(first["observed_shape_sha256"]), r"^[0-9a-f]{64}$")
                self.assertLessEqual(int(first["expected_rule_count"]), 64)
                self.assertLessEqual(int(first["observed_rule_count"]), 64)
                serialized = json.dumps(first, sort_keys=True)
                for raw in (
                    "br-fpro001",
                    "172.31.253.10",
                    "172.31.253.11",
                    "172.17.0.4",
                    "172.31.253.1",
                    "different-literal",
                    "different-counter",
                    firewall_boundary.MARKER_COUNTERS["gateway"],
                ):
                    self.assertNotIn(raw, serialized)
                observed_classes.add(str(first["mismatch_class"]))
        self.assertEqual(observed_classes, firewall_boundary.MARKER_MISMATCH_CLASSES)

        matched = self._marker_diagnostic(base)
        self.assertEqual(matched["disposition"], "DIAGNOSTIC_STOP_MATCHED_SHAPE")
        self.assertTrue(matched["shape_digests_equal"])
        self.assertTrue(matched["matched_shape"])

        literal_change = self._marker_diagnostic(cases["RIGHT_VALUE_IDENTITY"])
        self.assertTrue(literal_change["shape_digests_equal"])
        structural_change = self._marker_diagnostic(cases["MATCH_KEYS"])
        self.assertFalse(structural_change["shape_digests_equal"])

        numeric_type_drift = copy.deepcopy(base)
        output_rule = next(
            rule
            for rule in self._marker_rules(numeric_type_drift)
            if rule["chain"] == firewall_boundary.MARKER_OUTPUT_CHAIN
        )
        payload_selector = next(
            expression["match"]["left"]["payload"]
            for expression in output_rule["expr"]
            if "offset"
            in expression.get("match", {}).get("left", {}).get("payload", {})
        )
        payload_selector["offset"] = float(payload_selector["offset"])
        self.assertEqual(
            self._marker_diagnostic(numeric_type_drift)["mismatch_class"],
            "SELECTOR_IDENTITY",
        )

    def test_marker_shape_digest_redacts_literals_but_preserves_structure(self) -> None:
        first = {
            "match": {
                "op": "==",
                "left": {"meta": {"key": "first-selector"}},
                "right": "first-sensitive-literal",
            }
        }
        second = {
            "match": {
                "op": "==",
                "left": {"meta": {"key": "second-selector"}},
                "right": "second-sensitive-literal",
            }
        }
        first_sha, first_supported = firewall_boundary._redacted_shape_digest(first)
        second_sha, second_supported = firewall_boundary._redacted_shape_digest(second)
        self.assertTrue(first_supported and second_supported)
        self.assertEqual(first_sha, second_sha)

        structural = copy.deepcopy(second)
        structural["match"].pop("right")
        structural_sha, structural_supported = firewall_boundary._redacted_shape_digest(
            structural
        )
        self.assertTrue(structural_supported)
        self.assertNotEqual(first_sha, structural_sha)

    def test_marker_diagnostic_state_publication_is_closed_private_and_one_shot(self) -> None:
        diagnostic = self._marker_diagnostic(owned_firewall_entries_with_markers())
        rows = firewall_boundary.marker_diagnostic_state_rows(diagnostic)
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.tsv"
            state.write_text("existing\tbool\ttrue\n", encoding="utf-8")
            if os.name != "nt":
                state.chmod(0o600)
            firewall_boundary.publish_marker_diagnostic_state(rows, state)
            payload = state.read_text(encoding="utf-8")
            self.assertEqual(payload.count(firewall_boundary.MARKER_DIAGNOSTIC_PREFIX), len(rows))
            self.assertIn(
                "firewall.markers.diagnostic.canaries_reachable\tbool\tfalse",
                payload,
            )
            self.assertIn("DIAGNOSTIC_STOP_MATCHED_SHAPE", payload)
            for raw in (
                "br-fpro001",
                "172.31.253.10",
                "172.31.253.11",
                "172.17.0.4",
                "172.31.253.1",
                firewall_boundary.MARKER_COUNTERS["gateway"],
            ):
                self.assertNotIn(raw, payload)
            with self.assertRaisesRegex(
                firewall_boundary.BoundaryError,
                "FIREWALL_DIAGNOSTIC_STATE_PUBLICATION_FAILED",
            ):
                firewall_boundary.publish_marker_diagnostic_state(rows, state)

            missing = Path(directory) / "missing.tsv"
            with self.assertRaisesRegex(
                firewall_boundary.BoundaryError,
                "FIREWALL_DIAGNOSTIC_STATE_PUBLICATION_FAILED",
            ):
                firewall_boundary.publish_marker_diagnostic_state(rows, missing)

            malformed = list(rows)
            malformed[0] = (malformed[0][0], "str", "raw value with spaces")
            clean = Path(directory) / "clean.tsv"
            clean.write_text("", encoding="utf-8")
            if os.name != "nt":
                clean.chmod(0o600)
            with self.assertRaisesRegex(
                firewall_boundary.BoundaryError,
                "FIREWALL_MARKER_DIAGNOSTIC_INVALID",
            ):
                firewall_boundary.publish_marker_diagnostic_state(malformed, clean)

            for invalid_diagnostic in (
                {**diagnostic, "raw": "not-admitted"},
                {**diagnostic, "mismatch_class": "UNKNOWN_CLASS"},
                {**diagnostic, "observed_expression_kind": "UNKNOWN_KIND"},
                {**diagnostic, "matched_shape": False},
                {**diagnostic, "expected_rule_count": 8},
            ):
                with self.subTest(invalid_diagnostic=invalid_diagnostic):
                    with self.assertRaisesRegex(
                        firewall_boundary.BoundaryError,
                        "FIREWALL_MARKER_DIAGNOSTIC_INVALID",
                    ):
                        firewall_boundary.marker_diagnostic_state_rows(
                            invalid_diagnostic
                        )

    def test_marker_diagnostic_always_stops_before_canary_reachability(self) -> None:
        source = inspect.getsource(firewall_boundary.install_markers)
        intent_write = source.index("write_marker_intent(intent_path, intent)")
        installed_write = source.index("write_marker_installed(installed_path, installed)")
        foreign_comparison = source.index("post_foreign_sha != foreign_sha")
        publication = source.index("publish_marker_diagnostic_state(rows)")
        matched_stop = source.index(
            'raise BoundaryError("FIREWALL_DIAGNOSTIC_STOP_MATCHED_SHAPE")'
        )
        mismatch_stop = source.index(
            'raise BoundaryError("FIREWALL_MARKER_INSTALLATION_MISMATCH")',
            matched_stop,
        )
        self.assertLess(intent_write, installed_write)
        self.assertLess(installed_write, foreign_comparison)
        self.assertLess(foreign_comparison, publication)
        self.assertLess(publication, matched_stop)
        self.assertLess(matched_stop, mismatch_stop)
        self.assertNotIn("return", source[publication:])
        self.assertNotIn("marker_counters", source)

        contract = (ROOT / "docs/CONTAINMENT_CONTRACT.md").read_text(encoding="utf-8")
        self.assertIn("canaries_reachable=false", contract)
        self.assertIn("FIREWALL_DIAGNOSTIC_STOP_MATCHED_SHAPE", contract)
        for mismatch_class in firewall_boundary.MARKER_MISMATCH_CLASSES:
            self.assertIn(f"`{mismatch_class}`", contract)

    def test_marker_diagnostic_bounds_oversized_unknown_readback(self) -> None:
        entries = owned_firewall_entries_with_markers()
        entries.extend(
            nft_entry(
                "rule",
                chain=firewall_boundary.MARKER_INPUT_CHAIN,
                expr=[{"unknown": index}],
            )
            for index in range(80)
        )
        diagnostic = self._marker_diagnostic(entries)
        self.assertEqual(diagnostic["mismatch_class"], "RULE_COUNT")
        self.assertEqual(diagnostic["observed_rule_count"], 64)
        self.assertTrue(diagnostic["count_truncated"])

    def test_process_identity_preflight_is_closed_and_sanitized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            daemon = proc / "101"
            daemon.mkdir()
            (daemon / "comm").write_text("dockerd\n", encoding="utf-8")
            (daemon / "status").write_text("Name:\tdockerd\nUid:\t0\t0\t0\t0\n", encoding="utf-8")
            other = proc / "202"
            other.mkdir()
            (other / "comm").write_text("Runner.Worker\n", encoding="utf-8")
            observed = firewall_boundary.process_ownership_preflight(proc, runner_euid=1001)
            self.assertEqual(observed, ("single-root-owned-dockerd", True, True))
            with self.assertRaisesRegex(
                firewall_boundary.BoundaryError, "FIREWALL_RUNNER_IDENTITY_UNAVAILABLE"
            ):
                firewall_boundary.process_ownership_preflight(proc, runner_euid=-1)
            with self.assertRaisesRegex(firewall_boundary.BoundaryError, "FIREWALL_RUNNER_ROOT"):
                firewall_boundary.process_ownership_preflight(proc, runner_euid=0)
            (daemon / "status").write_text("Name:\tdockerd\nUid:\t1001\t1001\t1001\t1001\n", encoding="utf-8")
            with self.assertRaisesRegex(
                firewall_boundary.BoundaryError, "FIREWALL_DOCKER_DAEMON_NOT_ROOT"
            ):
                firewall_boundary.process_ownership_preflight(proc, runner_euid=1001)
            (daemon / "status").unlink()
            with self.assertRaisesRegex(
                firewall_boundary.BoundaryError,
                "FIREWALL_DOCKER_DAEMON_IDENTITY_UNAVAILABLE",
            ):
                firewall_boundary.process_ownership_preflight(proc, runner_euid=1001)

    def test_process_identity_preflight_rejects_missing_and_ambiguous_daemon(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            with self.assertRaisesRegex(
                firewall_boundary.BoundaryError, "FIREWALL_DOCKER_DAEMON_MISSING"
            ):
                firewall_boundary.process_ownership_preflight(proc, runner_euid=1001)
            for pid in ("101", "202"):
                daemon = proc / pid
                daemon.mkdir()
                (daemon / "comm").write_text("dockerd\n", encoding="utf-8")
                (daemon / "status").write_text(
                    "Name:\tdockerd\nUid:\t0\t0\t0\t0\n", encoding="utf-8"
                )
            with self.assertRaisesRegex(
                firewall_boundary.BoundaryError, "FIREWALL_DOCKER_DAEMON_AMBIGUOUS"
            ):
                firewall_boundary.process_ownership_preflight(proc, runner_euid=1001)

    def test_owned_table_shape_is_exact_and_digest_is_deterministic(self) -> None:
        entries = owned_firewall_entries()
        first = firewall_boundary.validate_owned(entries, firewall_boundary.TABLE)
        second = firewall_boundary.validate_owned(copy.deepcopy(entries), firewall_boundary.TABLE)
        self.assertEqual(first, second)
        self.assertEqual(first[1], {"chain": 3, "counter": 3, "rule": 7, "table": 1})
        self.assertEqual(first[0], "22d68c21dec10ab4828727fb601006e31a1da6bfc96b7e6505a6aa570c013944")

        marked = owned_firewall_entries_with_markers()
        marked_first = firewall_boundary.validate_owned(
            marked, firewall_boundary.TABLE, markers_installed=True
        )
        marked_second = firewall_boundary.validate_owned(
            copy.deepcopy(marked), firewall_boundary.TABLE, markers_installed=True
        )
        self.assertEqual(marked_first, marked_second)
        self.assertEqual(
            marked_first[1], {"chain": 6, "counter": 10, "rule": 14, "table": 1}
        )
        marker_sha, marker_counts = firewall_boundary.canonical_snapshot(
            firewall_boundary.marker_entries(marked, firewall_boundary.TABLE)
        )
        self.assertRegex(marker_sha, r"^[0-9a-f]{64}$")
        self.assertEqual(marker_counts, {"chain": 3, "counter": 7, "rule": 7})

    def test_owned_table_rejects_unknown_duplicate_and_malformed_objects(self) -> None:
        cases = []
        duplicate_counter = owned_firewall_entries()
        duplicate_counter[3]["counter"]["name"] = firewall_boundary.INPUT_COUNTER
        cases.append(duplicate_counter)
        duplicate_rule = owned_firewall_entries()
        duplicate_rule[-1]["rule"]["expr"] = copy.deepcopy(duplicate_rule[-2]["rule"]["expr"])
        cases.append(duplicate_rule)
        unknown_chain = owned_firewall_entries()
        unknown_chain[6]["chain"]["name"] = "packet_unknown"
        cases.append(unknown_chain)
        unknown_field = owned_firewall_entries()
        unknown_field[4]["chain"]["unexpected"] = True
        cases.append(unknown_field)
        unknown_object = owned_firewall_entries()
        unknown_object.append(
            {"flowtable": {"family": "inet", "table": firewall_boundary.TABLE, "name": "unexpected"}}
        )
        cases.append(unknown_object)
        missing_rule = owned_firewall_entries()[:-1]
        cases.append(missing_rule)
        malformed_rule = owned_firewall_entries()
        malformed_rule[-1]["rule"]["expr"] = []
        cases.append(malformed_rule)
        for entries in cases:
            with self.subTest(entries=entries):
                with self.assertRaisesRegex(
                    firewall_boundary.BoundaryError, "FIREWALL_INSTALLATION_MISMATCH"
                ):
                    firewall_boundary.validate_owned(entries, firewall_boundary.TABLE)

        marked_duplicate = owned_firewall_entries_with_markers()
        marked_duplicate[-2]["rule"]["expr"] = copy.deepcopy(
            marked_duplicate[-3]["rule"]["expr"]
        )
        with self.assertRaisesRegex(
            firewall_boundary.BoundaryError, "FIREWALL_INSTALLATION_MISMATCH"
        ):
            firewall_boundary.validate_owned(
                marked_duplicate, firewall_boundary.TABLE, markers_installed=True
            )

    def test_runner_correlates_embedded_dns_to_specific_marker_and_output_enforcement(self) -> None:
        runner = (ROOT / "scripts/run-containment-smoke.sh").read_text(encoding="utf-8")
        self.assertIn("EXPECTED_OUTPUT_DENIES=0", runner)
        self.assertIn('[[ "$(wc -l <"$counter_file" | tr -d \' \')" == "3" ]]', runner)
        self.assertIn(
            "expect_firewall_block external_dns output_deny external_dns EXTERNAL_DNS_SUCCEEDED EXTERNAL_DNS_NOT_FIREWALL_CORRELATED",
            runner,
        )
        self.assertIn("expect_same_network_positive same_network_resolution none", runner)
        self.assertIn("expect_same_network_positive same_network_connect same_network", runner)
        self.assertIn('output_absolute="$(firewall_counter_value output_deny)"', runner)
        self.assertIn(
            'before_output="$(firewall_counter_value output_deny)"', runner
        )
        self.assertIn('record firewall.final_output_deny_count int "$output_final"', runner)
        self.assertNotIn('expect_firewall_block external_dns forward_deny', runner)
        self.assertNotIn('cat "$RAW/canary-', runner)

    def test_every_canary_has_one_closed_marker_and_enforcement_mapping(self) -> None:
        runner = (ROOT / "scripts/run-containment-smoke.sh").read_text(encoding="utf-8")
        rehearsal = runner[
            runner.index("run_firewall_publication_rehearsal() {") : runner.index(
                "packet_object_counts() {"
            )
        ]
        for expected in (
            "expect_same_network_positive same_network_resolution none",
            "expect_same_network_positive same_network_connect same_network",
            "expect_firewall_block external_dns output_deny external_dns",
            "expect_firewall_block literal_ip forward_deny literal_ip",
            "expect_firewall_block metadata forward_deny metadata",
            "expect_firewall_block gateway input_deny gateway",
            "expect_firewall_block host_listener input_deny host_listener",
            "expect_firewall_block foreign_network forward_deny foreign_network",
        ):
            with self.subTest(expected=expected):
                self.assertEqual(rehearsal.count(expected), 1)
        self.assertIn('[[ "$manifest_count" == "8"', runner)
        self.assertIn("canaries.firewall.marker_manifest_sha256", runner)
        self.assertIn("diagnostic.precanary.enforcement_manifest_sha256", runner)
        self.assertIn("FIREWALL_MARKER_EXPECTED_TOTAL", runner)
        self.assertNotIn("reset counters", runner.lower())

    def test_cleanup_listener_failure_omits_count_and_fails_without_negative_sentinel(self) -> None:
        runner = (ROOT / "scripts/run-containment-smoke.sh").read_text(encoding="utf-8")
        cleanup = runner[
            runner.index("cleanup_exact() {") : runner.index("\nfinalize() {")
        ]
        self.assertIn('record cleanup.listeners_remaining int "$listener_count"', cleanup)
        self.assertIn('listener_count=""', cleanup)
        self.assertIn("record cleanup.listener_failure_code", cleanup)
        self.assertIn('[[ "$listener_count" == "0" ]] || return 1', cleanup)
        self.assertNotIn('listener_count="-1"', cleanup)
        self.assertNotIn("cleanup.listeners_remaining int -1", cleanup)

    def test_precanary_phase_order_is_complete_and_advances_only_after_quiescence(self) -> None:
        runner = (ROOT / "scripts/run-containment-smoke.sh").read_text(encoding="utf-8")
        rehearsal = runner[
            runner.index("run_firewall_publication_rehearsal() {") : runner.index(
                "packet_object_counts() {"
            )
        ]
        phases = (
            "post_install",
            "host_listener_ready",
            "foreign_container_started",
            "published_service_started",
            "packet_client_started",
            "shape_network_health_validated",
            "publication_probes_complete",
            "client_tool_preflight_complete",
            "quiescence_first",
            "quiescence_second",
        )
        positions = [rehearsal.index(f"firewall_phase_snapshot {phase}") for phase in phases]
        self.assertEqual(positions, sorted(positions))
        identity = rehearsal.index('client_ip="$(docker inspect', positions[7])
        finish = rehearsal.index("firewall_phase_finish PRECANARY_SETUP_QUIESCENT")
        markers = rehearsal.index("firewall_install_marker_boundary", finish)
        same_network = rehearsal.index("expect_same_network_positive", markers)
        self.assertLess(identity, positions[8])
        self.assertLess(positions[-1], finish)
        self.assertLess(finish, markers)
        self.assertLess(markers, same_network)
        self.assertIn("sleep 2\n  firewall_phase_snapshot quiescence_second", rehearsal)
        marker_function = runner[
            runner.index("firewall_install_marker_boundary() {") : runner.index(
                "\nfirewall_record_canary_evidence() {"
            )
        ]
        self.assertIn("input_before - FIREWALL_PHASE_PREV_INPUT", marker_function)
        self.assertIn("forward_before - FIREWALL_PHASE_PREV_FORWARD", marker_function)
        self.assertIn("output_before - FIREWALL_PHASE_PREV_OUTPUT", marker_function)
        self.assertLess(
            marker_function.index("FIREWALL_QUIESCENCE_LOST_BEFORE_MARKER_INSTALL"),
            marker_function.index("install-markers"),
        )
        self.assertNotIn("PRECANARY_PHASE_DIAGNOSTIC_PASS", runner)
        self.assertNotIn("FIREWALL_PHASE_DIAGNOSTIC_MODE=", runner)

    def test_precanary_phase_classifier_covers_every_phase_and_chain(self) -> None:
        phases = (
            "post_install",
            "host_listener_ready",
            "foreign_container_started",
            "published_service_started",
            "packet_client_started",
            "shape_network_health_validated",
            "publication_probes_complete",
            "client_tool_preflight_complete",
            "quiescence_first",
            "quiescence_second",
        )
        chain_counts = {
            "INPUT": (1, 0, 0),
            "FORWARD": (0, 1, 0),
            "OUTPUT": (0, 0, 1),
            "MULTIPLE": (1, 1, 0),
        }
        for phase_index, phase in enumerate(phases):
            for chain, counts in chain_counts.items():
                with self.subTest(phase=phase, chain=chain):
                    snapshots = [(name, 0, 0, 0) for name in phases[:phase_index]]
                    snapshots.append((phase, *counts))
                    result = self._run_phase_contract(snapshots)
                    output_is_admitted = (
                        chain == "OUTPUT"
                        and phase not in {"post_install", "quiescence_second"}
                    )
                    if output_is_admitted:
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertIn(
                            "FIRST:ROOT_DNS_OUTPUT_SETUP_OR_AMBIENT_HIT:1",
                            result.stdout,
                        )
                        continue
                    self.assertEqual(result.returncode, 91, result.stderr)
                    expected = {
                        "post_install": "INSTALL_WINDOW_HIT",
                        "quiescence_second": "QUIESCENCE_HIT",
                    }.get(
                        phase,
                        {
                            "INPUT": "PACKET_INPUT_SETUP_HIT",
                            "FORWARD": "PACKET_FORWARD_SETUP_HIT",
                            "OUTPUT": "ROOT_DNS_OUTPUT_SETUP_OR_AMBIENT_HIT",
                            "MULTIPLE": "MULTICHAIN_SETUP_HIT",
                        }[chain],
                    )
                    lines = result.stdout.splitlines()
                    self.assertEqual(lines[-1], f"BLOCK:{expected}")
                    self.assertIn(
                        f"RECORD:diagnostic.precanary.first_hit_phase:str:{phase}", lines
                    )
                    self.assertIn(
                        f"RECORD:diagnostic.precanary.first_hit_chain:str:{chain}", lines
                    )
                    terminal_index = lines.index(
                        f"RECORD:diagnostic.precanary.terminal_class:str:{expected}"
                    )
                    self.assertLess(terminal_index, len(lines) - 1)
                    self.assertTrue(
                        any(
                            line.startswith(
                                "RECORD:diagnostic.precanary.phase_manifest_sha256:str:"
                            )
                            for line in lines[:terminal_index]
                        )
                    )

    def test_precanary_phase_classifier_rejects_negative_delta_and_freezes_first_hit(self) -> None:
        snapshots = [
            ("post_install", 0, 0, 0),
            ("host_listener_ready", 1, 0, 0),
            ("foreign_container_started", 1, 0, 1),
            ("published_service_started", 0, 0, 1),
        ]
        result = self._run_phase_contract(snapshots, defer_finish=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.count(
                "RECORD:diagnostic.precanary.first_hit_phase:str:host_listener_ready"
            ),
            1,
        )
        self.assertNotIn(
            "RECORD:diagnostic.precanary.first_hit_phase:str:foreign_container_started",
            result.stdout,
        )
        self.assertIn("FINISH:FIREWALL_COUNTER_NONMONOTONIC", result.stdout)
        self.assertIn("FIRST:PACKET_INPUT_SETUP_HIT:1", result.stdout)

    def test_precanary_phase_classifier_accepts_zero_or_ambiguous_output_only_after_stable_quiescence(self) -> None:
        phases = (
            "post_install",
            "host_listener_ready",
            "foreign_container_started",
            "published_service_started",
            "packet_client_started",
            "shape_network_health_validated",
            "publication_probes_complete",
            "client_tool_preflight_complete",
            "quiescence_first",
            "quiescence_second",
        )
        zero_snapshots = [(phase, 0, 0, 0) for phase in phases]
        output_snapshots = [
            (phase, 0, 0, 16 if index >= 5 else 0)
            for index, phase in enumerate(phases)
        ]
        first = self._run_phase_contract(zero_snapshots, complete=True)
        second = self._run_phase_contract(zero_snapshots, complete=True)
        output = self._run_phase_contract(output_snapshots, complete=True)
        for result in (first, second, output):
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(
                "RECORD:diagnostic.precanary.terminal_class:str:PRECANARY_SETUP_QUIESCENT",
                result.stdout,
            )
            self.assertIn("RECORD:diagnostic.precanary.phase_manifest_count:int:10", result.stdout)
            self.assertIn("RECORD:diagnostic.precanary.delta_sum_matches_final:bool:true", result.stdout)
            self.assertIn("RECORD:diagnostic.precanary.quiescent:bool:true", result.stdout)
        self.assertIn(
            "RECORD:diagnostic.precanary.setup_class:str:NO_SETUP_ENFORCEMENT_HIT",
            first.stdout,
        )
        self.assertIn(
            "RECORD:diagnostic.precanary.setup_class:str:ROOT_DNS_OUTPUT_SETUP_OR_AMBIENT_HIT",
            output.stdout,
        )
        self.assertIn("RECORD:diagnostic.precanary.setup_output_total:int:16", output.stdout)
        digest_pattern = re.compile(
            r"RECORD:diagnostic\.precanary\.phase_manifest_sha256:str:([0-9a-f]{64})"
        )
        self.assertEqual(
            digest_pattern.search(first.stdout).group(1),
            digest_pattern.search(second.stdout).group(1),
        )
        missing = self._run_phase_contract(zero_snapshots[:-1], complete=True)
        self.assertEqual(missing.returncode, 91, missing.stderr)
        self.assertIn("BLOCK:FIREWALL_PHASE_MANIFEST_INVALID", missing.stdout)

    def test_precanary_phase_receipt_is_closed_and_never_resets_counters(self) -> None:
        runner = (ROOT / "scripts/run-containment-smoke.sh").read_text(encoding="utf-8")
        contract = (ROOT / "docs/CONTAINMENT_CONTRACT.md").read_text(encoding="utf-8")
        functions = self._phase_contract_functions()
        for field in (
            "input_absolute",
            "forward_absolute",
            "output_absolute",
            "input_delta",
            "forward_delta",
            "output_delta",
            "monotonic",
        ):
            self.assertIn(f".${{phase}}.{field}", functions)
        self.assertNotIn("reset counters", functions.lower())
        self.assertNotIn("nft reset", functions.lower())
        self.assertNotIn("cat \"$RAW", functions)
        for forbidden in (
            "POSTGRES_PASSWORD",
            "docker inspect",
            "nft-rule",
            "environment",
            "connection string",
        ):
            self.assertNotIn(forbidden, functions)
        self.assertIn("cleanup_exact", runner)
        self.assertIn('firewall_boundary.py" remove', runner)
        for signed_field in (
            "input_delta",
            "forward_delta",
            "output_delta",
            "first_hit_input_delta",
            "first_hit_forward_delta",
            "first_hit_output_delta",
            "gateway_input_deny_delta",
            "gateway_forward_deny_delta",
            "gateway_output_deny_delta",
            "preinstall_gap_input_delta",
            "preinstall_gap_forward_delta",
            "preinstall_gap_output_delta",
            "install_enforcement_input_delta",
            "install_enforcement_forward_delta",
            "install_enforcement_output_delta",
            "enforcement_input_delta",
            "enforcement_forward_delta",
            "enforcement_output_delta",
            "<marker>_delta",
        ):
            self.assertIn(f"`{signed_field}`", contract)
        self.assertIn("Those fields alone admit signed base-10 integers", contract)
        self.assertIn("every other integer remain nonnegative", contract)

    def test_gateway_canary_records_complete_sanitized_evidence_before_classification(self) -> None:
        runner = (ROOT / "scripts/run-containment-smoke.sh").read_text(encoding="utf-8")
        start = runner.index("firewall_validate_marker_deltas() {")
        end = runner.index("\nexpect_same_network_positive() {", start)
        function = runner[start:end]

        def execute(
            command_rc: int,
            before: tuple[int, int, int],
            after: tuple[int, int, int],
        ) -> subprocess.CompletedProcess[str]:
            with tempfile.TemporaryDirectory() as directory:
                script = f"""set -Eeuo pipefail
RAW={shlex.quote(directory)}
PHASE_FILE="$RAW/after"
EXPECTED_INPUT_DENIES=0
EXPECTED_FORWARD_DENIES=0
EXPECTED_OUTPUT_DENIES=0
COMMAND_RC={command_rc}
BEFORE_INPUT={before[0]}
BEFORE_FORWARD={before[1]}
BEFORE_OUTPUT={before[2]}
AFTER_INPUT={after[0]}
AFTER_FORWARD={after[1]}
AFTER_OUTPUT={after[2]}
AFTER_GATEWAY=$(( AFTER_INPUT >= BEFORE_INPUT ? AFTER_INPUT - BEFORE_INPUT : 0 ))
declare -A FIREWALL_MARKER_EXPECTED_TOTAL=(
  [same_network]=0 [external_dns]=0 [literal_ip]=0 [metadata]=0
  [gateway]=0 [host_listener]=0 [foreign_network]=0
)
firewall_counter_value() {{
  local name="$1" prefix=BEFORE variable
  [[ ! -e "$PHASE_FILE" ]] || prefix=AFTER
  case "$name" in
    input_deny) variable="${{prefix}}_INPUT" ;;
    forward_deny) variable="${{prefix}}_FORWARD" ;;
    output_deny) variable="${{prefix}}_OUTPUT" ;;
  esac
  printf '%s\\n' "${{!variable}}"
}}
firewall_marker_snapshot() {{
  local -n target="$1"
  target=(
    [same_network]=0 [external_dns]=0 [literal_ip]=0 [metadata]=0
    [gateway]=0 [host_listener]=0 [foreign_network]=0
  )
  [[ ! -e "$PHASE_FILE" ]] || target[gateway]="$AFTER_GATEWAY"
}}
firewall_record_canary_evidence() {{
  record "canaries.firewall.$1.enforcement_input_delta" int "$4"
}}
record() {{ printf 'RECORD:%s:%s:%s\\n' "$1" "$2" "$3"; }}
block() {{ printf 'BLOCK:%s\\n' "$1"; exit 91; }}
trigger() {{
  : >"$PHASE_FILE"
  printf 'raw-secret-token 172.31.253.1 nft-rule-text\\n'
  return "$COMMAND_RC"
}}
{function}
expect_firewall_block gateway input_deny gateway PACKET_GATEWAY_REACHABLE GATEWAY_NOT_FIREWALL_CORRELATED trigger
printf 'expected-input=%s\\n' "$EXPECTED_INPUT_DENIES"
"""
                return subprocess.run(
                    [bash_executable()],
                    input=script,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )

        evidence_keys = (
            "gateway_command_exit_code",
            "gateway_command_exit_class",
            "gateway_input_deny_delta",
            "gateway_forward_deny_delta",
            "gateway_output_deny_delta",
        )

        accepted = execute(1, (0, 0, 0), (2, 0, 0))
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertIn("expected-input=2", accepted.stdout)
        self.assertIn("gateway_command_exit_class:str:NO_REPLY", accepted.stdout)

        failures = (
            (0, (1, 1, 1), (0, 1, 1), "PACKET_GATEWAY_REACHABLE"),
            (1, (0, 0, 0), (0, 0, 0), "GATEWAY_INPUT_COUNTER_DELTA_MISSING"),
            (1, (0, 0, 0), (1, 1, 0), "GATEWAY_UNEXPECTED_COUNTER_DELTA"),
            (1, (0, 0, 0), (0, 1, 1), "GATEWAY_UNEXPECTED_COUNTER_DELTA"),
            (1, (1, 0, 0), (0, 0, 0), "FIREWALL_COUNTER_NONMONOTONIC"),
            (1, (0, 1, 0), (0, 0, 0), "FIREWALL_COUNTER_NONMONOTONIC"),
            (1, (0, 0, 1), (0, 0, 0), "FIREWALL_COUNTER_NONMONOTONIC"),
            (2, (0, 0, 0), (0, 0, 0), "GATEWAY_COMMAND_RUNTIME_FAILED"),
            (125, (0, 0, 0), (0, 0, 0), "GATEWAY_COMMAND_RUNTIME_FAILED"),
            (126, (0, 0, 0), (0, 0, 0), "GATEWAY_COMMAND_RUNTIME_FAILED"),
            (127, (0, 0, 0), (0, 0, 0), "GATEWAY_COMMAND_RUNTIME_FAILED"),
            (42, (0, 0, 0), (0, 0, 0), "GATEWAY_COMMAND_RUNTIME_FAILED"),
        )
        for command_rc, before, after, expected in failures:
            with self.subTest(command_rc=command_rc, before=before, after=after):
                result = execute(command_rc, before, after)
                self.assertEqual(result.returncode, 91, result.stderr)
                lines = result.stdout.splitlines()
                self.assertEqual(lines[-1], f"BLOCK:{expected}")
                for key in evidence_keys:
                    self.assertTrue(
                        any(line.startswith(f"RECORD:canaries.firewall.{key}:") for line in lines[:-1]),
                        (key, lines),
                    )
                self.assertNotIn("raw-secret-token", result.stdout)
                self.assertNotIn("172.31.253.1", result.stdout)
                self.assertNotIn("nft-rule-text", result.stdout)

    def test_gateway_diagnostic_preserves_following_tcp_host_listener_proof(self) -> None:
        runner = (ROOT / "scripts/run-containment-smoke.sh").read_text(encoding="utf-8")
        gateway = (
            "expect_firewall_block gateway input_deny gateway PACKET_GATEWAY_REACHABLE "
            "GATEWAY_NOT_FIREWALL_CORRELATED"
        )
        host_listener = (
            "expect_firewall_block host_listener input_deny host_listener HOST_TEST_LISTENER_REACHABLE "
            "HOST_TEST_LISTENER_NOT_FIREWALL_CORRELATED"
        )
        self.assertLess(runner.index(gateway), runner.index(host_listener))
        self.assertIn(
            'docker exec "$client_id" timeout 3 bash -ceu "</dev/tcp/${SUBNET_GATEWAY}/${HOST_TEST_PORT}"',
            runner,
        )

    def test_output_canary_rejects_any_simultaneous_unrelated_counter_hit(self) -> None:
        runner = (ROOT / "scripts/run-containment-smoke.sh").read_text(encoding="utf-8")
        start = runner.index("firewall_validate_marker_deltas() {")
        end = runner.index("\nexpect_same_network_positive() {", start)
        function = runner[start:end]

        def execute(after_input: int, after_forward: int, after_output: int) -> subprocess.CompletedProcess[str]:
            with tempfile.TemporaryDirectory() as directory:
                script = f"""set -Eeuo pipefail
RAW={shlex.quote(directory)}
PHASE_FILE="$RAW/after"
EXPECTED_INPUT_DENIES=0
EXPECTED_FORWARD_DENIES=0
EXPECTED_OUTPUT_DENIES=0
BEFORE_INPUT=0
BEFORE_FORWARD=0
BEFORE_OUTPUT=0
AFTER_INPUT={after_input}
AFTER_FORWARD={after_forward}
AFTER_OUTPUT={after_output}
declare -A FIREWALL_MARKER_EXPECTED_TOTAL=(
  [same_network]=0 [external_dns]=0 [literal_ip]=0 [metadata]=0
  [gateway]=0 [host_listener]=0 [foreign_network]=0
)
firewall_counter_value() {{
  local name="$1" prefix=BEFORE variable
  [[ ! -e "$PHASE_FILE" ]] || prefix=AFTER
  case "$name" in
    input_deny) variable="${{prefix}}_INPUT" ;;
    forward_deny) variable="${{prefix}}_FORWARD" ;;
    output_deny) variable="${{prefix}}_OUTPUT" ;;
  esac
  printf '%s\\n' "${{!variable}}"
}}
firewall_marker_snapshot() {{
  local -n target="$1"
  target=(
    [same_network]=0 [external_dns]=0 [literal_ip]=0 [metadata]=0
    [gateway]=0 [host_listener]=0 [foreign_network]=0
  )
  [[ ! -e "$PHASE_FILE" ]] || target[external_dns]="$AFTER_OUTPUT"
}}
firewall_record_canary_evidence() {{ :; }}
record() {{ :; }}
block() {{ printf '%s\\n' "$1"; exit 91; }}
trigger() {{ : >"$PHASE_FILE"; return 1; }}
{function}
expect_firewall_block external_dns output_deny external_dns EXTERNAL_DNS_SUCCEEDED EXTERNAL_DNS_NOT_FIREWALL_CORRELATED trigger
printf 'expected-output=%s\\n' "$EXPECTED_OUTPUT_DENIES"
"""
                return subprocess.run(
                    [bash_executable()],
                    input=script,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )

        accepted = execute(0, 0, 2)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertIn("expected-output=2", accepted.stdout)
        rejected = execute(1, 0, 2)
        self.assertEqual(rejected.returncode, 91, rejected.stderr)
        self.assertEqual(rejected.stdout.strip(), "EXTERNAL_DNS_NOT_FIREWALL_CORRELATED")

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
        baseline = [{"table": {"family": "ip", "name": "baseline"}}]
        network_foreign = baseline + [{"chain": {"family": "ip", "table": "docker", "name": "packet"}}]
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            with mock.patch.object(firewall_boundary, "process_ownership_preflight", return_value=("single-root-owned-dockerd", True, True)), mock.patch.object(firewall_boundary, "privileged_prefix", return_value=(["nft"], "nftables-v1")), mock.patch.object(
                firewall_boundary, "read_ruleset", return_value=owned_firewall_entries()
            ):
                with self.assertRaisesRegex(firewall_boundary.BoundaryError, "FIREWALL_TABLE_COLLISION"):
                    firewall_boundary.prepare(ledger, "br-fpro001", "172.31.253.0/24")
            firewall_boundary.write_ledger(ledger, self._prepared_ledger_payload(baseline))
            completion = firewall_boundary.restoration_completion_path(ledger)
            completion.write_text("collision\n", encoding="utf-8")
            with self.assertRaisesRegex(
                firewall_boundary.BoundaryError, "FIREWALL_LEDGER_COLLISION"
            ):
                firewall_boundary.install(ledger, "br-fpro001", "172.31.253.0/24")
            completion.unlink()
            failed = subprocess.CompletedProcess([], 1, stdout="", stderr="invalid")
            with mock.patch.object(firewall_boundary, "process_ownership_preflight", return_value=("single-root-owned-dockerd", True, True)), mock.patch.object(firewall_boundary, "privileged_prefix", return_value=(["nft"], "nftables-v1")), mock.patch.object(
                firewall_boundary, "read_ruleset", return_value=network_foreign
            ), mock.patch.object(firewall_boundary, "_run", return_value=failed):
                with self.assertRaisesRegex(firewall_boundary.BoundaryError, "FIREWALL_ATOMIC_CHECK_FAILED"):
                    firewall_boundary.install(ledger, "br-fpro001", "172.31.253.0/24")
            self.assertTrue(ledger.exists())
            self.assertFalse(firewall_boundary.read_ledger(ledger)["installed"])

    def test_atomic_install_and_exact_foreign_preservation(self) -> None:
        baseline = [{"table": {"family": "ip", "name": "baseline"}}]
        network_foreign = baseline + [{"chain": {"family": "ip", "table": "docker", "name": "packet"}}]
        success = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            sanitized = io.StringIO()
            with mock.patch.object(firewall_boundary, "process_ownership_preflight", return_value=("single-root-owned-dockerd", True, True)), mock.patch.object(firewall_boundary, "privileged_prefix", return_value=(["nft"], "nftables-v1")), mock.patch.object(
                firewall_boundary, "read_ruleset", return_value=baseline
            ), contextlib.redirect_stdout(sanitized):
                firewall_boundary.prepare(ledger, "br-fpro001", "172.31.253.0/24")
            with mock.patch.object(firewall_boundary, "process_ownership_preflight", return_value=("single-root-owned-dockerd", True, True)), mock.patch.object(firewall_boundary, "privileged_prefix", return_value=(["nft"], "nftables-v1")), mock.patch.object(
                firewall_boundary, "read_ruleset", side_effect=[network_foreign, network_foreign + owned_firewall_entries()]
            ), mock.patch.object(firewall_boundary, "_run", return_value=success), contextlib.redirect_stdout(sanitized):
                firewall_boundary.install(ledger, "br-fpro001", "172.31.253.0/24")
            saved = firewall_boundary.read_ledger(ledger)
            baseline_sha, baseline_counts = firewall_boundary.canonical_snapshot(baseline)
            self.assertEqual(saved["preimage_sha256"], baseline_sha)
            self.assertEqual(saved["preimage_counts"], baseline_counts)
            self.assertTrue(saved["installed"])
            self.assertFalse(saved["markers_installed"])
            self.assertEqual(saved["marker_sha256"], "")
            self.assertEqual(saved["combined_sha256"], "")
            self.assertRegex(saved["owned_sha256"], r"^[0-9a-f]{64}$")
            state = sanitized.getvalue()
            self.assertIn("firewall.daemon_class\tstr\tsingle-root-owned-dockerd", state)
            self.assertIn("firewall.docker_daemon_root_owned\tbool\ttrue", state)
            self.assertIn("firewall.runner_nonroot\tbool\ttrue", state)
            self.assertIn("firewall.prepared_before_network\tbool\ttrue", state)
            self.assertIn("firewall.install_foreign_unchanged\tbool\ttrue", state)
            self.assertIn("firewall.owned_counter_count\tint\t3", state)
            self.assertNotIn("dockerd\nUid:", state)
            expected_mode = "0o666" if os.name == "nt" else "0o600"
            self.assertEqual(oct(ledger.stat().st_mode & 0o777), expected_mode)

    def test_apply_failure_and_foreign_drift_retain_cleanup_ledger(self) -> None:
        baseline = [{"table": {"family": "ip", "name": "baseline"}}]
        network_foreign = baseline + [{"chain": {"family": "ip", "table": "docker", "name": "packet"}}]
        changed = network_foreign + [{"chain": {"family": "ip", "table": "foreign", "name": "changed"}}]
        success = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        failed = subprocess.CompletedProcess([], 1, stdout="", stderr="rejected")
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            firewall_boundary.write_ledger(ledger, self._prepared_ledger_payload(baseline))
            with mock.patch.object(firewall_boundary, "process_ownership_preflight", return_value=("single-root-owned-dockerd", True, True)), mock.patch.object(firewall_boundary, "privileged_prefix", return_value=(["nft"], "nftables-v1")), mock.patch.object(
                firewall_boundary, "read_ruleset", return_value=network_foreign
            ), mock.patch.object(firewall_boundary, "_run", side_effect=[success, failed]):
                with self.assertRaisesRegex(firewall_boundary.BoundaryError, "FIREWALL_ATOMIC_INSTALL_FAILED"):
                    firewall_boundary.install(ledger, "br-fpro001", "172.31.253.0/24")
            self.assertTrue(ledger.exists())
            self.assertFalse(firewall_boundary.read_ledger(ledger)["installed"])
            with mock.patch.object(firewall_boundary, "process_ownership_preflight", return_value=("single-root-owned-dockerd", True, True)), mock.patch.object(firewall_boundary, "privileged_prefix", return_value=(["nft"], "nftables-v1")), mock.patch.object(
                firewall_boundary, "read_ruleset", side_effect=[network_foreign, changed + owned_firewall_entries()]
            ), mock.patch.object(firewall_boundary, "_run", return_value=success):
                with self.assertRaisesRegex(firewall_boundary.BoundaryError, "FIREWALL_FOREIGN_STATE_DRIFT"):
                    firewall_boundary.install(ledger, "br-fpro001", "172.31.253.0/24")
            self.assertTrue(ledger.exists())

    def test_marker_install_is_atomic_one_shot_and_sanitized(self) -> None:
        foreign = [{"table": {"family": "ip", "name": "foreign"}}]
        pre_sha, pre_counts = firewall_boundary.canonical_snapshot(foreign)
        owned_sha, _ = firewall_boundary.validate_owned(
            owned_firewall_entries(), firewall_boundary.TABLE
        )
        success = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            diagnostic_state = Path(directory) / "state.tsv"
            diagnostic_state.write_text("existing\tbool\ttrue\n", encoding="utf-8")
            if os.name != "nt":
                diagnostic_state.chmod(0o600)
            firewall_boundary.write_ledger(
                ledger,
                {
                    "schema": firewall_boundary.SCHEMA,
                    "table": firewall_boundary.TABLE,
                    "interface": "br-fpro001",
                    "subnet": "172.31.253.0/24",
                    "preimage_sha256": pre_sha,
                    "preimage_semantic_sha256": firewall_boundary.semantic_snapshot(foreign),
                    "preimage_counts": pre_counts,
                    "installation_sha256": pre_sha,
                    "installation_semantic_sha256": firewall_boundary.semantic_snapshot(foreign),
                    "installation_counts": pre_counts,
                    "installed": True,
                    "owned_sha256": owned_sha,
                    "markers_installed": False,
                    "marker_sha256": "",
                    "combined_sha256": "",
                },
            )
            state = io.StringIO()
            with mock.patch.object(
                firewall_boundary,
                "privileged_prefix",
                return_value=(["nft"], "nftables-v1"),
            ), mock.patch.object(
                firewall_boundary,
                "read_ruleset",
                side_effect=[
                    foreign + owned_firewall_entries(),
                    foreign + owned_firewall_entries_with_markers(),
                ],
            ), mock.patch.object(
                firewall_boundary, "_run", return_value=success
            ), mock.patch.object(
                firewall_boundary,
                "MARKER_DIAGNOSTIC_STATE_FILE",
                diagnostic_state,
            ), contextlib.redirect_stdout(state):
                with self.assertRaisesRegex(
                    firewall_boundary.BoundaryError,
                    "FIREWALL_DIAGNOSTIC_STOP_MATCHED_SHAPE",
                ):
                    firewall_boundary.install_markers(
                        ledger,
                        "172.31.253.10",
                        "172.31.253.11",
                        "172.17.0.4",
                        "172.31.253.1",
                        18080,
                    )
            saved = firewall_boundary.read_ledger(ledger)
            effective = firewall_boundary.read_effective_ledger(ledger)
            self.assertFalse(saved["markers_installed"])
            self.assertEqual(saved["marker_sha256"], "")
            self.assertEqual(saved["combined_sha256"], "")
            self.assertTrue(effective["markers_installed"])
            self.assertRegex(effective["marker_sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(effective["combined_sha256"], r"^[0-9a-f]{64}$")
            sanitized = state.getvalue()
            persisted = diagnostic_state.read_text(encoding="utf-8")
            self.assertEqual(sanitized, "")
            self.assertIn(
                "firewall.markers.diagnostic.disposition\tstr\tDIAGNOSTIC_STOP_MATCHED_SHAPE",
                persisted,
            )
            self.assertIn(
                "firewall.markers.diagnostic.canaries_reachable\tbool\tfalse",
                persisted,
            )
            for raw in ("172.31.253.10", "172.31.253.11", "172.17.0.4"):
                self.assertNotIn(raw, sanitized)
                self.assertNotIn(raw, persisted)
            with self.assertRaisesRegex(
                firewall_boundary.BoundaryError, "FIREWALL_MARKER_STATE_COLLISION"
            ):
                firewall_boundary.install_markers(
                    ledger,
                    "172.31.253.10",
                    "172.31.253.11",
                    "172.17.0.4",
                    "172.31.253.1",
                    18080,
                )

    def test_marker_transaction_accepts_stable_setup_era_foreign_change_only(self) -> None:
        original = [{"table": {"family": "ip", "name": "foreign-original"}}]
        setup = original + [
            {"chain": {"family": "ip", "table": "foreign-original", "name": "docker-setup"}}
        ]
        original_sha, original_counts = firewall_boundary.canonical_snapshot(original)
        setup_sha, setup_counts = firewall_boundary.canonical_snapshot(setup)
        owned_sha, _ = firewall_boundary.validate_owned(
            owned_firewall_entries(), firewall_boundary.TABLE
        )
        success = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            diagnostic_state = Path(directory) / "state.tsv"
            diagnostic_state.write_text("existing\tbool\ttrue\n", encoding="utf-8")
            if os.name != "nt":
                diagnostic_state.chmod(0o600)
            firewall_boundary.write_ledger(
                ledger,
                {
                    "schema": firewall_boundary.SCHEMA,
                    "table": firewall_boundary.TABLE,
                    "interface": "br-fpro001",
                    "subnet": "172.31.253.0/24",
                    "preimage_sha256": original_sha,
                    "preimage_semantic_sha256": firewall_boundary.semantic_snapshot(original),
                    "preimage_counts": original_counts,
                    "installation_sha256": setup_sha,
                    "installation_semantic_sha256": firewall_boundary.semantic_snapshot(setup),
                    "installation_counts": setup_counts,
                    "installed": True,
                    "owned_sha256": owned_sha,
                    "markers_installed": False,
                    "marker_sha256": "",
                    "combined_sha256": "",
                },
            )
            state = io.StringIO()
            with mock.patch.object(
                firewall_boundary,
                "privileged_prefix",
                return_value=(["nft"], "nftables-v1"),
            ), mock.patch.object(
                firewall_boundary,
                "read_ruleset",
                side_effect=[
                    setup + owned_firewall_entries(),
                    setup + owned_firewall_entries_with_markers(),
                ],
            ), mock.patch.object(
                firewall_boundary, "_run", return_value=success
            ), mock.patch.object(
                firewall_boundary,
                "MARKER_DIAGNOSTIC_STATE_FILE",
                diagnostic_state,
            ), contextlib.redirect_stdout(state):
                with self.assertRaisesRegex(
                    firewall_boundary.BoundaryError,
                    "FIREWALL_DIAGNOSTIC_STOP_MATCHED_SHAPE",
                ):
                    firewall_boundary.install_markers(
                        ledger,
                        "172.31.253.10",
                        "172.31.253.11",
                        "172.17.0.4",
                        "172.31.253.1",
                        18080,
                    )
            saved = firewall_boundary.read_ledger(ledger)
            self.assertEqual(saved["preimage_sha256"], original_sha)
            self.assertEqual(saved["preimage_counts"], original_counts)
            sanitized = state.getvalue()
            persisted = diagnostic_state.read_text(encoding="utf-8")
            self.assertIn(
                "firewall.markers.diagnostic.foreign_transaction_unchanged\tbool\ttrue",
                persisted,
            )
            self.assertNotIn(original_sha, persisted)
            self.assertNotIn(setup_sha, persisted)
            self.assertNotIn("foreign-original", sanitized)
            self.assertNotIn("docker-setup", sanitized)
            self.assertNotIn("foreign-original", persisted)
            self.assertNotIn("docker-setup", persisted)

    def test_marker_diagnostic_exit_retains_exact_idempotent_cleanup_for_match_and_mismatch(self) -> None:
        foreign = [{"table": {"family": "ip", "name": "foreign"}}]
        pre_sha, pre_counts = firewall_boundary.canonical_snapshot(foreign)
        owned_sha, _ = firewall_boundary.validate_owned(
            owned_firewall_entries(), firewall_boundary.TABLE
        )
        success = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        for matched in (True, False):
            with self.subTest(matched=matched), tempfile.TemporaryDirectory() as directory:
                marked = owned_firewall_entries_with_markers()
                if not matched:
                    self._marker_rules(marked)[0]["expr"][0]["match"][
                        "right"
                    ] = "different-literal"
                ledger = Path(directory) / "ledger.json"
                completion = firewall_boundary.restoration_completion_path(ledger)
                diagnostic_state = Path(directory) / "state.tsv"
                diagnostic_state.write_text("existing\tbool\ttrue\n", encoding="utf-8")
                if os.name != "nt":
                    diagnostic_state.chmod(0o600)
                firewall_boundary.write_ledger(
                    ledger,
                    {
                        "schema": firewall_boundary.SCHEMA,
                        "table": firewall_boundary.TABLE,
                        "interface": "br-fpro001",
                        "subnet": "172.31.253.0/24",
                        "preimage_sha256": pre_sha,
                        "preimage_semantic_sha256": firewall_boundary.semantic_snapshot(foreign),
                        "preimage_counts": pre_counts,
                        "installation_sha256": pre_sha,
                        "installation_semantic_sha256": firewall_boundary.semantic_snapshot(foreign),
                        "installation_counts": pre_counts,
                        "installed": True,
                        "owned_sha256": owned_sha,
                        "markers_installed": False,
                        "marker_sha256": "",
                        "combined_sha256": "",
                    },
                )
                expected_code = (
                    "FIREWALL_DIAGNOSTIC_STOP_MATCHED_SHAPE"
                    if matched
                    else "FIREWALL_MARKER_INSTALLATION_MISMATCH"
                )
                with mock.patch.object(
                    firewall_boundary,
                    "privileged_prefix",
                    return_value=(["nft"], "nftables-v1"),
                ), mock.patch.object(
                    firewall_boundary,
                    "read_ruleset",
                    side_effect=[foreign + owned_firewall_entries(), foreign + marked],
                ), mock.patch.object(
                    firewall_boundary, "_run", return_value=success
                ), mock.patch.object(
                    firewall_boundary,
                    "MARKER_DIAGNOSTIC_STATE_FILE",
                    diagnostic_state,
                ), contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(
                        firewall_boundary.BoundaryError, expected_code
                    ):
                        firewall_boundary.install_markers(
                            ledger,
                            "172.31.253.10",
                            "172.31.253.11",
                            "172.17.0.4",
                            "172.31.253.1",
                            18080,
                        )
                saved = firewall_boundary.read_ledger(ledger)
                effective = firewall_boundary.read_effective_ledger(ledger)
                self.assertFalse(saved["markers_installed"])
                self.assertEqual(saved["marker_sha256"], "")
                self.assertEqual(saved["combined_sha256"], "")
                self.assertTrue(effective["markers_installed"])
                self.assertRegex(effective["marker_sha256"], r"^[0-9a-f]{64}$")
                self.assertRegex(effective["combined_sha256"], r"^[0-9a-f]{64}$")

                with mock.patch.object(
                    firewall_boundary,
                    "privileged_prefix",
                    return_value=(["nft"], "nftables-v1"),
                ), mock.patch.object(
                    firewall_boundary,
                    "read_ruleset",
                    side_effect=[foreign + marked, foreign],
                ), mock.patch.object(
                    firewall_boundary, "_run", return_value=success
                ), contextlib.redirect_stdout(io.StringIO()):
                    firewall_boundary.remove(ledger)
                self.assertFalse(ledger.exists())
                self.assertTrue(completion.exists())

                with mock.patch.object(
                    firewall_boundary,
                    "privileged_prefix",
                    return_value=(["nft"], "nftables-v1"),
                ), mock.patch.object(
                    firewall_boundary, "read_ruleset", return_value=foreign
                ), contextlib.redirect_stdout(io.StringIO()):
                    firewall_boundary.remove(ledger)
                self.assertFalse(ledger.exists())
                self.assertFalse(completion.exists())

    def test_marker_transaction_rejects_window_drift_snapshot_failure_and_collision(self) -> None:
        original = [{"table": {"family": "ip", "name": "foreign"}}]
        setup = original + [
            {"chain": {"family": "ip", "table": "foreign", "name": "setup"}}
        ]
        during = setup + [
            {"chain": {"family": "ip", "table": "foreign", "name": "during-marker"}}
        ]
        original_sha, original_counts = firewall_boundary.canonical_snapshot(original)
        setup_sha, setup_counts = firewall_boundary.canonical_snapshot(setup)
        owned_sha, _ = firewall_boundary.validate_owned(
            owned_firewall_entries(), firewall_boundary.TABLE
        )
        success = subprocess.CompletedProcess([], 0, stdout="", stderr="")

        def ledger_payload() -> dict[str, object]:
            return {
                "schema": firewall_boundary.SCHEMA,
                "table": firewall_boundary.TABLE,
                "interface": "br-fpro001",
                "subnet": "172.31.253.0/24",
                "preimage_sha256": original_sha,
                "preimage_semantic_sha256": firewall_boundary.semantic_snapshot(original),
                "preimage_counts": original_counts,
                "installation_sha256": setup_sha,
                "installation_semantic_sha256": firewall_boundary.semantic_snapshot(setup),
                "installation_counts": setup_counts,
                "installed": True,
                "owned_sha256": owned_sha,
                "markers_installed": False,
                "marker_sha256": "",
                "combined_sha256": "",
            }

        with self.subTest(boundary="post-persist-foreign-drift"), tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            firewall_boundary.write_ledger(ledger, ledger_payload())
            with mock.patch.object(
                firewall_boundary,
                "privileged_prefix",
                return_value=(["nft"], "nftables-v1"),
            ), mock.patch.object(
                firewall_boundary,
                "read_ruleset",
                side_effect=[
                    setup + owned_firewall_entries(),
                    during + owned_firewall_entries_with_markers(),
                ],
            ), mock.patch.object(firewall_boundary, "_run", return_value=success):
                with self.assertRaisesRegex(
                    firewall_boundary.BoundaryError, "FIREWALL_FOREIGN_STATE_DRIFT"
                ):
                    firewall_boundary.install_markers(
                        ledger,
                        "172.31.253.10",
                        "172.31.253.11",
                        "172.17.0.4",
                        "172.31.253.1",
                        18080,
                    )
            saved = firewall_boundary.read_ledger(ledger)
            effective = firewall_boundary.read_effective_ledger(ledger)
            self.assertFalse(saved["markers_installed"])
            self.assertTrue(effective["markers_installed"])
            self.assertEqual(saved["preimage_sha256"], original_sha)
            self.assertTrue(firewall_boundary.marker_intent_path(ledger).exists())
            self.assertTrue(firewall_boundary.marker_installed_path(ledger).exists())

        with self.subTest(boundary="pre-apply-snapshot-failure"), tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            firewall_boundary.write_ledger(ledger, ledger_payload())
            with mock.patch.object(
                firewall_boundary,
                "privileged_prefix",
                return_value=(["nft"], "nftables-v1"),
            ), mock.patch.object(
                firewall_boundary,
                "read_ruleset",
                side_effect=firewall_boundary.BoundaryError("FIREWALL_INSPECTION_FAILED"),
            ), mock.patch.object(firewall_boundary, "_run", return_value=success):
                with self.assertRaisesRegex(
                    firewall_boundary.BoundaryError, "FIREWALL_INSPECTION_FAILED"
                ):
                    firewall_boundary.install_markers(
                        ledger,
                        "172.31.253.10",
                        "172.31.253.11",
                        "172.17.0.4",
                        "172.31.253.1",
                        18080,
                    )
            self.assertFalse(firewall_boundary.marker_intent_path(ledger).exists())
            self.assertFalse(firewall_boundary.marker_installed_path(ledger).exists())

        with self.subTest(boundary="owned-shape-collision"), tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            firewall_boundary.write_ledger(ledger, ledger_payload())
            collision = setup + owned_firewall_entries()
            collision.append(
                nft_entry(
                    "counter",
                    name="marker_collision",
                    packets=0,
                    bytes=0,
                )
            )
            with mock.patch.object(
                firewall_boundary,
                "privileged_prefix",
                return_value=(["nft"], "nftables-v1"),
            ), mock.patch.object(
                firewall_boundary, "read_ruleset", return_value=collision
            ), mock.patch.object(firewall_boundary, "_run", return_value=success):
                with self.assertRaisesRegex(
                    firewall_boundary.BoundaryError, "FIREWALL_INSTALLATION_MISMATCH"
                ):
                    firewall_boundary.install_markers(
                        ledger,
                        "172.31.253.10",
                        "172.31.253.11",
                        "172.17.0.4",
                        "172.31.253.1",
                        18080,
                    )
            self.assertFalse(firewall_boundary.marker_intent_path(ledger).exists())

    def test_marker_apply_failure_preserves_base_ledger_for_exact_cleanup(self) -> None:
        foreign = [{"table": {"family": "ip", "name": "foreign"}}]
        pre_sha, pre_counts = firewall_boundary.canonical_snapshot(foreign)
        owned_sha, _ = firewall_boundary.validate_owned(
            owned_firewall_entries(), firewall_boundary.TABLE
        )
        checked = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        rejected = subprocess.CompletedProcess([], 1, stdout="", stderr="rejected")
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
                    "preimage_semantic_sha256": firewall_boundary.semantic_snapshot(foreign),
                    "preimage_counts": pre_counts,
                    "installation_sha256": pre_sha,
                    "installation_semantic_sha256": firewall_boundary.semantic_snapshot(foreign),
                    "installation_counts": pre_counts,
                    "installed": True,
                    "owned_sha256": owned_sha,
                    "markers_installed": False,
                    "marker_sha256": "",
                    "combined_sha256": "",
                },
            )
            with mock.patch.object(
                firewall_boundary,
                "privileged_prefix",
                return_value=(["nft"], "nftables-v1"),
            ), mock.patch.object(
                firewall_boundary,
                "read_ruleset",
                return_value=foreign + owned_firewall_entries(),
            ), mock.patch.object(
                firewall_boundary, "_run", side_effect=[checked, rejected]
            ):
                with self.assertRaisesRegex(
                    firewall_boundary.BoundaryError,
                    "FIREWALL_MARKER_ATOMIC_INSTALL_FAILED",
                ):
                    firewall_boundary.install_markers(
                        ledger,
                        "172.31.253.10",
                        "172.31.253.11",
                        "172.17.0.4",
                        "172.31.253.1",
                        18080,
                    )
            saved = firewall_boundary.read_ledger(ledger)
            self.assertFalse(saved["markers_installed"])
            self.assertEqual(saved["marker_sha256"], "")
            self.assertEqual(saved["combined_sha256"], "")
            intent = firewall_boundary.marker_intent_path(ledger)
            installed = firewall_boundary.marker_installed_path(ledger)
            self.assertTrue(intent.exists())
            self.assertFalse(installed.exists())
            with mock.patch.object(
                firewall_boundary,
                "privileged_prefix",
                return_value=(["nft"], "nftables-v1"),
            ), mock.patch.object(
                firewall_boundary,
                "read_ruleset",
                side_effect=[
                    foreign + owned_firewall_entries(),
                    foreign,
                ],
            ), mock.patch.object(
                firewall_boundary, "_run", return_value=checked
            ), contextlib.redirect_stdout(io.StringIO()):
                firewall_boundary.remove(ledger)
            self.assertFalse(ledger.exists())
            self.assertFalse(intent.exists())
            self.assertFalse(installed.exists())

    def test_marker_post_apply_interruptions_recover_exact_state_for_cleanup(self) -> None:
        foreign = [{"table": {"family": "ip", "name": "foreign-private"}}]
        marked = owned_firewall_entries_with_markers()
        success = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        for boundary, expected_code in (
            ("readback", "FIREWALL_INSPECTION_FAILED"),
            ("installed-persistence", "FIREWALL_MARKER_STATE_PERSISTENCE_FAILED"),
        ):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as directory:
                ledger = Path(directory) / "ledger.json"
                completion = firewall_boundary.restoration_completion_path(ledger)
                intent_path = firewall_boundary.marker_intent_path(ledger)
                installed_path = firewall_boundary.marker_installed_path(ledger)
                firewall_boundary.write_ledger(
                    ledger,
                    self._restoration_ledger_payload(
                        foreign, markers_installed=False
                    ),
                )
                readback = [
                    foreign + owned_firewall_entries(),
                    (
                        firewall_boundary.BoundaryError(
                            "FIREWALL_INSPECTION_FAILED"
                        )
                        if boundary == "readback"
                        else foreign + marked
                    ),
                ]
                persistence_patch = (
                    mock.patch.object(
                        firewall_boundary,
                        "write_marker_installed",
                        side_effect=firewall_boundary.BoundaryError(
                            "FIREWALL_MARKER_STATE_PERSISTENCE_FAILED"
                        ),
                    )
                    if boundary == "installed-persistence"
                    else contextlib.nullcontext()
                )
                with mock.patch.object(
                    firewall_boundary,
                    "privileged_prefix",
                    return_value=(["nft"], "nftables-v1"),
                ), mock.patch.object(
                    firewall_boundary, "read_ruleset", side_effect=readback
                ), mock.patch.object(
                    firewall_boundary, "_run", return_value=success
                ), persistence_patch:
                    with self.assertRaisesRegex(
                        firewall_boundary.BoundaryError, expected_code
                    ):
                        firewall_boundary.install_markers(
                            ledger,
                            "172.31.253.10",
                            "172.31.253.11",
                            "172.17.0.4",
                            "172.31.253.1",
                            18080,
                        )
                self.assertTrue(intent_path.exists())
                self.assertFalse(installed_path.exists())
                self.assertFalse(
                    firewall_boundary.read_ledger(ledger)["markers_installed"]
                )

                with mock.patch.object(
                    firewall_boundary,
                    "privileged_prefix",
                    return_value=(["nft"], "nftables-v1"),
                ), mock.patch.object(
                    firewall_boundary,
                    "read_ruleset",
                    side_effect=[foreign + marked, foreign],
                ), mock.patch.object(
                    firewall_boundary, "_run", return_value=success
                ), contextlib.redirect_stdout(io.StringIO()):
                    firewall_boundary.remove(ledger)
                self.assertFalse(ledger.exists())
                self.assertFalse(intent_path.exists())
                self.assertFalse(installed_path.exists())
                self.assertTrue(completion.exists())

                with mock.patch.object(
                    firewall_boundary,
                    "privileged_prefix",
                    return_value=(["nft"], "nftables-v1"),
                ), mock.patch.object(
                    firewall_boundary, "read_ruleset", return_value=foreign
                ), contextlib.redirect_stdout(io.StringIO()):
                    firewall_boundary.remove(ledger)
                self.assertFalse(completion.exists())

    def test_marker_cleanup_retirement_is_retryable_at_each_sidecar_boundary(self) -> None:
        foreign = [{"table": {"family": "ip", "name": "foreign-private"}}]
        marked = owned_firewall_entries_with_markers()
        success = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        original_retire = firewall_boundary._retire_private_path
        for failure_target in ("intent", "installed"):
            with self.subTest(failure_target=failure_target), tempfile.TemporaryDirectory() as directory:
                ledger = Path(directory) / "ledger.json"
                completion = firewall_boundary.restoration_completion_path(ledger)
                intent_path = firewall_boundary.marker_intent_path(ledger)
                installed_path = firewall_boundary.marker_installed_path(ledger)
                firewall_boundary.write_ledger(
                    ledger,
                    self._restoration_ledger_payload(
                        foreign, markers_installed=False
                    ),
                )
                self._write_marker_state(ledger, marked)
                target = intent_path if failure_target == "intent" else installed_path
                failed_once = False

                def retire(path: Path, failure_code: str) -> None:
                    nonlocal failed_once
                    if path == target and not failed_once:
                        failed_once = True
                        raise firewall_boundary.BoundaryError(
                            "FIREWALL_MARKER_STATE_RETIREMENT_FAILED"
                        )
                    original_retire(path, failure_code)

                with mock.patch.object(
                    firewall_boundary,
                    "privileged_prefix",
                    return_value=(["nft"], "nftables-v1"),
                ), mock.patch.object(
                    firewall_boundary,
                    "read_ruleset",
                    side_effect=[foreign + marked, foreign],
                ), mock.patch.object(
                    firewall_boundary, "_run", return_value=success
                ), mock.patch.object(
                    firewall_boundary, "_retire_private_path", side_effect=retire
                ):
                    with self.assertRaisesRegex(
                        firewall_boundary.BoundaryError,
                        "FIREWALL_MARKER_STATE_RETIREMENT_FAILED",
                    ):
                        firewall_boundary.remove(ledger)
                self.assertFalse(ledger.exists())
                self.assertTrue(completion.exists())
                self.assertTrue(target.exists())

                with mock.patch.object(
                    firewall_boundary,
                    "privileged_prefix",
                    return_value=(["nft"], "nftables-v1"),
                ), mock.patch.object(
                    firewall_boundary, "read_ruleset", return_value=foreign
                ), contextlib.redirect_stdout(io.StringIO()):
                    firewall_boundary.remove(ledger)
                self.assertFalse(intent_path.exists())
                self.assertFalse(installed_path.exists())
                self.assertFalse(completion.exists())

    def test_marker_state_is_private_self_digested_and_tamper_evident(self) -> None:
        foreign = [{"table": {"family": "ip", "name": "raw-foreign-name"}}]
        marked = owned_firewall_entries_with_markers()
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            firewall_boundary.write_ledger(
                ledger,
                self._restoration_ledger_payload(foreign, markers_installed=False),
            )
            intent, installed = self._write_marker_state(ledger, marked)
            intent_path = firewall_boundary.marker_intent_path(ledger)
            installed_path = firewall_boundary.marker_installed_path(ledger)
            self.assertEqual(
                intent["evidence_sha256"],
                firewall_boundary.marker_evidence_sha256(intent),
            )
            self.assertEqual(
                installed["evidence_sha256"],
                firewall_boundary.marker_evidence_sha256(installed),
            )
            expected_mode = "0o666" if os.name == "nt" else "0o600"
            self.assertEqual(oct(intent_path.stat().st_mode & 0o777), expected_mode)
            self.assertEqual(oct(installed_path.stat().st_mode & 0o777), expected_mode)

            forged = dict(installed)
            forged["base_ledger_sha256"] = "0" * 64
            installed_path.write_text(
                json.dumps(forged, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                firewall_boundary.BoundaryError, "FIREWALL_MARKER_STATE_INVALID"
            ):
                firewall_boundary.read_effective_ledger(ledger)

            installed_path.write_text(
                '{"schema":"x","schema":"y"}\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(
                firewall_boundary.BoundaryError, "FIREWALL_MARKER_STATE_INVALID"
            ):
                firewall_boundary.read_marker_installed(installed_path)

    def test_marker_counters_require_the_persisted_effective_state(self) -> None:
        foreign = [{"table": {"family": "ip", "name": "foreign-private"}}]
        marked = owned_firewall_entries_with_markers()
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            firewall_boundary.write_ledger(
                ledger,
                self._restoration_ledger_payload(foreign, markers_installed=False),
            )
            self._write_marker_state(ledger, marked)
            output = io.StringIO()
            with mock.patch.object(
                firewall_boundary,
                "privileged_prefix",
                return_value=(["nft"], "nftables-v1"),
            ), mock.patch.object(
                firewall_boundary, "read_ruleset", return_value=foreign + marked
            ), contextlib.redirect_stdout(output):
                firewall_boundary.marker_counters(ledger)
            self.assertEqual(output.getvalue().count("firewall.markers.counters."), 7)
            for raw in (
                "172.31.253.10",
                "172.31.253.11",
                "raw-foreign-name",
            ):
                self.assertNotIn(raw, output.getvalue())

    def test_marker_cleanup_rejects_drift_from_the_persisted_owned_shape(self) -> None:
        foreign = [{"table": {"family": "ip", "name": "foreign-private"}}]
        marked = owned_firewall_entries_with_markers()
        drifted = copy.deepcopy(marked)
        self._marker_rules(drifted)[0]["expr"][0]["match"]["right"] = (
            "different-literal"
        )
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            firewall_boundary.write_ledger(
                ledger,
                self._restoration_ledger_payload(foreign, markers_installed=False),
            )
            self._write_marker_state(ledger, marked)
            command = mock.Mock()
            with mock.patch.object(
                firewall_boundary,
                "privileged_prefix",
                return_value=(["nft"], "nftables-v1"),
            ), mock.patch.object(
                firewall_boundary, "read_ruleset", return_value=foreign + drifted
            ), mock.patch.object(firewall_boundary, "_run", command):
                with self.assertRaisesRegex(
                    firewall_boundary.BoundaryError,
                    "FIREWALL_INSTALLATION_MISMATCH",
                ):
                    firewall_boundary.remove(ledger)
            command.assert_not_called()
            self.assertTrue(ledger.exists())
            self.assertTrue(firewall_boundary.marker_intent_path(ledger).exists())
            self.assertTrue(firewall_boundary.marker_installed_path(ledger).exists())

    def test_counter_schema_is_closed_and_exact(self) -> None:
        entries = owned_firewall_entries()
        entries[1]["counter"]["packets"] = 7
        entries[3]["counter"]["packets"] = 11
        self.assertEqual(
            firewall_boundary.counter_packets(entries, firewall_boundary.INPUT_COUNTER), 7
        )
        self.assertEqual(
            firewall_boundary.counter_packets(entries, firewall_boundary.OUTPUT_COUNTER), 11
        )
        entries.append(nft_entry("counter", name=firewall_boundary.INPUT_COUNTER, packets=8, bytes=0))
        with self.assertRaisesRegex(firewall_boundary.BoundaryError, "FIREWALL_COUNTER_INVALID"):
            firewall_boundary.counter_packets(entries, firewall_boundary.INPUT_COUNTER)

    def test_exact_atomic_rollback_requires_completion_for_idempotency(self) -> None:
        foreign = [{"table": {"family": "ip", "name": "foreign"}}]
        marked = owned_firewall_entries_with_markers()
        success = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            firewall_boundary.write_ledger(ledger, self._restoration_ledger_payload(foreign))
            completion = firewall_boundary.restoration_completion_path(ledger)
            first_state = io.StringIO()
            with mock.patch.object(firewall_boundary, "privileged_prefix", return_value=(["nft"], "nftables-v1")), mock.patch.object(
                firewall_boundary, "read_ruleset", side_effect=[foreign + marked, foreign]
            ), mock.patch.object(firewall_boundary, "_run", return_value=success), contextlib.redirect_stdout(first_state):
                firewall_boundary.remove(ledger)
            self.assertFalse(ledger.exists())
            self.assertTrue(completion.exists())
            self.assertIn("firewall.rollback_completion_published\tbool\ttrue", first_state.getvalue())
            for forbidden in (
                "br-fpro001",
                "172.31.253.0/24",
                firewall_boundary.INPUT_COUNTER,
            ):
                self.assertNotIn(forbidden, first_state.getvalue())
            second_state = io.StringIO()
            with mock.patch.object(firewall_boundary, "privileged_prefix", return_value=(["nft"], "nftables-v1")), mock.patch.object(
                firewall_boundary, "read_ruleset", return_value=foreign
            ), contextlib.redirect_stdout(second_state):
                firewall_boundary.remove(ledger)
            self.assertFalse(completion.exists())
            self.assertIn("firewall.rollback_idempotent\tbool\ttrue", second_state.getvalue())
            with mock.patch.object(firewall_boundary, "privileged_prefix", return_value=(["nft"], "nftables-v1")), mock.patch.object(
                firewall_boundary, "read_ruleset", return_value=foreign
            ):
                with self.assertRaisesRegex(
                    firewall_boundary.BoundaryError,
                    "FIREWALL_RESTORATION_EVIDENCE_MISSING",
                ):
                    firewall_boundary.remove(ledger)

    def test_completion_waits_for_network_teardown_and_then_is_idempotent(self) -> None:
        baseline = [{"table": {"family": "ip", "name": "foreign"}}]
        network_state = baseline + [
            {"chain": {"family": "ip", "table": "docker", "name": "packet-network"}}
        ]
        marked = owned_firewall_entries_with_markers()
        for entry in marked:
            if entry.get("counter", {}).get("name") == firewall_boundary.OUTPUT_COUNTER:
                entry["counter"]["packets"] = 24
        success = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            firewall_boundary.write_ledger(
                ledger,
                self._restoration_ledger_payload(baseline, markers_installed=False),
            )
            _, installed = self._write_marker_state(ledger, marked)
            installed_path = firewall_boundary.marker_installed_path(ledger)
            installed_path.unlink()
            installed["mismatch_class"] = "RIGHT_VALUE_IDENTITY"
            installed["evidence_sha256"] = firewall_boundary.marker_evidence_sha256(
                installed
            )
            firewall_boundary.write_marker_installed(installed_path, installed)
            completion = firewall_boundary.restoration_completion_path(ledger)
            remove_command = mock.Mock(return_value=success)
            pause = mock.Mock()
            with mock.patch.object(
                firewall_boundary,
                "privileged_prefix",
                return_value=(["nft"], "nftables-v1"),
            ), mock.patch.object(
                firewall_boundary,
                "read_ruleset",
                side_effect=[
                    network_state + marked,
                    network_state + marked,
                    baseline + marked,
                    baseline,
                ],
            ), mock.patch.object(
                firewall_boundary, "_run", remove_command
            ), mock.patch.object(
                firewall_boundary.time, "sleep", pause
            ), contextlib.redirect_stdout(io.StringIO()):
                firewall_boundary.remove(ledger)
            self.assertEqual(remove_command.call_count, 2)
            self.assertEqual(pause.call_count, 2)
            pause.assert_has_calls(
                [
                    mock.call(firewall_boundary.RESTORATION_POLL_INTERVAL_SECONDS),
                    mock.call(firewall_boundary.RESTORATION_POLL_INTERVAL_SECONDS),
                ]
            )
            self.assertFalse(ledger.exists())
            self.assertTrue(completion.exists())
            self.assertFalse(firewall_boundary.marker_intent_path(ledger).exists())
            self.assertFalse(firewall_boundary.marker_installed_path(ledger).exists())

            with mock.patch.object(
                firewall_boundary,
                "privileged_prefix",
                return_value=(["nft"], "nftables-v1"),
            ), mock.patch.object(
                firewall_boundary, "read_ruleset", return_value=baseline
            ), contextlib.redirect_stdout(io.StringIO()):
                firewall_boundary.remove(ledger)
            self.assertFalse(completion.exists())

    def test_semantic_snapshot_ignores_only_safe_top_level_order(self) -> None:
        first = [
            {"table": {"family": "ip", "name": "foreign"}},
            {"chain": {"family": "ip", "table": "foreign", "name": "input"}},
            {
                "rule": {
                    "family": "ip",
                    "table": "foreign",
                    "chain": "input",
                    "expr": [{"accept": None}],
                }
            },
            {
                "rule": {
                    "family": "ip",
                    "table": "foreign",
                    "chain": "input",
                    "expr": [{"drop": None}],
                }
            },
        ]
        reordered_objects = [first[1], first[0], first[2], first[3]]
        reordered_rules = [first[1], first[0], first[3], first[2]]
        strict_first, _ = firewall_boundary.canonical_snapshot(first)
        strict_reordered, _ = firewall_boundary.canonical_snapshot(reordered_objects)
        self.assertNotEqual(strict_first, strict_reordered)
        self.assertEqual(
            firewall_boundary.semantic_snapshot(first),
            firewall_boundary.semantic_snapshot(reordered_objects),
        )
        self.assertNotEqual(
            firewall_boundary.semantic_snapshot(first),
            firewall_boundary.semantic_snapshot(reordered_rules),
        )

    def test_restoration_observations_close_all_postimage_classes(self) -> None:
        baseline = [
            {"table": {"family": "ip", "name": "foreign"}},
            {"chain": {"family": "ip", "table": "foreign", "name": "input"}},
        ]
        installation = baseline + [
            {"chain": {"family": "ip", "table": "docker", "name": "packet"}}
        ]
        unrelated = baseline + [
            {"chain": {"family": "ip", "table": "foreign", "name": "concurrent"}}
        ]
        other = baseline + [
            {"chain": {"family": "ip", "table": "foreign", "name": "other"}}
        ]
        owned = owned_firewall_entries()
        ledger = self._restoration_ledger_payload(
            baseline,
            markers_installed=False,
            installation_foreign=installation,
        )

        cases = {
            "PERSISTENT_INSTALLATION_IDENTITY": [installation] * 20,
            "STABLE_UNRELATED_FOREIGN_DRIFT": [unrelated] * 20,
            "UNSTABLE_FOREIGN_DRIFT": [unrelated, other] * 10,
            "LIST_ORDER_SERIALIZATION_VARIANCE": [list(reversed(baseline))] * 20,
        }
        for expected, observations in cases.items():
            with self.subTest(expected=expected):
                state = io.StringIO()
                with mock.patch.object(
                    firewall_boundary,
                    "read_ruleset",
                    side_effect=[item + owned for item in observations[1:]],
                ), mock.patch.object(
                    firewall_boundary.time, "sleep"
                ), contextlib.redirect_stdout(state):
                    with self.assertRaisesRegex(
                        firewall_boundary.BoundaryError,
                        "FIREWALL_FOREIGN_STATE_DRIFT",
                    ):
                        firewall_boundary.wait_for_restoration_preimage(
                            ["nft"], ledger, observations[0] + owned
                        )
                sanitized = state.getvalue()
                self.assertIn(
                    f"firewall.restoration_classification\tstr\t{expected}",
                    sanitized,
                )
                self.assertIn(
                    "firewall.restoration_observation_count\tint\t20", sanitized
                )
                self.assertEqual(
                    sanitized.count(".query_succeeded\tbool\ttrue"), 20
                )
                self.assertEqual(
                    sanitized.count(".semantic_equals_prior\tbool\t"), 20
                )
                self.assertNotIn("concurrent", sanitized)
                self.assertNotIn("packet", sanitized)

        unrelated_reordered = [unrelated, list(reversed(unrelated))] * 10
        reordered_state = io.StringIO()
        with mock.patch.object(
            firewall_boundary,
            "read_ruleset",
            side_effect=[item + owned for item in unrelated_reordered[1:]],
        ), mock.patch.object(
            firewall_boundary.time, "sleep"
        ), contextlib.redirect_stdout(reordered_state):
            with self.assertRaisesRegex(
                firewall_boundary.BoundaryError,
                "FIREWALL_FOREIGN_STATE_DRIFT",
            ):
                firewall_boundary.wait_for_restoration_preimage(
                    ["nft"], ledger, unrelated_reordered[0] + owned
                )
        self.assertIn(
            "firewall.restoration_classification\tstr\tLIST_ORDER_SERIALIZATION_VARIANCE",
            reordered_state.getvalue(),
        )
        self.assertIn(
            ".semantic_equals_prior\tbool\ttrue", reordered_state.getvalue()
        )

        success_state = io.StringIO()
        with contextlib.redirect_stdout(success_state):
            current, selected = firewall_boundary.wait_for_restoration_preimage(
                ["nft"], ledger, baseline + owned
            )
        self.assertEqual(current, baseline + owned)
        self.assertEqual(selected, owned)
        self.assertIn(
            "firewall.restoration_classification\tstr\tPRE_NETWORK_IDENTITY",
            success_state.getvalue(),
        )

    def test_cleanup_never_adopts_persistent_foreign_drift(self) -> None:
        baseline = [{"table": {"family": "ip", "name": "foreign"}}]
        changed = baseline + [
            {"chain": {"family": "ip", "table": "foreign", "name": "concurrent"}}
        ]
        owned = owned_firewall_entries()
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            firewall_boundary.write_ledger(
                ledger,
                self._restoration_ledger_payload(baseline, markers_installed=False),
            )
            original = ledger.read_bytes()
            completion = firewall_boundary.restoration_completion_path(ledger)
            command = mock.Mock()
            pause = mock.Mock()
            ruleset = mock.Mock(return_value=changed + owned)
            with mock.patch.object(
                firewall_boundary,
                "privileged_prefix",
                return_value=(["nft"], "nftables-v1"),
            ), mock.patch.object(
                firewall_boundary, "read_ruleset", ruleset
            ), mock.patch.object(
                firewall_boundary, "_run", command
            ), mock.patch.object(
                firewall_boundary.time, "sleep", pause
            ):
                with self.assertRaisesRegex(
                    firewall_boundary.BoundaryError, "FIREWALL_FOREIGN_STATE_DRIFT"
                ):
                    firewall_boundary.remove(ledger)
            self.assertEqual(
                ruleset.call_count, firewall_boundary.RESTORATION_POLL_ATTEMPTS
            )
            self.assertEqual(
                pause.call_count, firewall_boundary.RESTORATION_POLL_ATTEMPTS - 1
            )
            command.assert_not_called()
            self.assertEqual(ledger.read_bytes(), original)
            self.assertFalse(completion.exists())

    def test_cleanup_revalidates_owned_shape_during_restoration_wait(self) -> None:
        baseline = [{"table": {"family": "ip", "name": "foreign"}}]
        changed = baseline + [
            {"chain": {"family": "ip", "table": "foreign", "name": "pending"}}
        ]
        marked = owned_firewall_entries_with_markers()
        drifted = copy.deepcopy(marked)
        self._marker_rules(drifted)[0]["expr"][0]["match"]["right"] = "changed"
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            firewall_boundary.write_ledger(
                ledger,
                self._restoration_ledger_payload(baseline, markers_installed=False),
            )
            self._write_marker_state(ledger, marked)
            command = mock.Mock()
            pause = mock.Mock()
            with mock.patch.object(
                firewall_boundary,
                "privileged_prefix",
                return_value=(["nft"], "nftables-v1"),
            ), mock.patch.object(
                firewall_boundary,
                "read_ruleset",
                side_effect=[changed + marked, changed + drifted],
            ), mock.patch.object(
                firewall_boundary, "_run", command
            ), mock.patch.object(
                firewall_boundary.time, "sleep", pause
            ):
                with self.assertRaisesRegex(
                    firewall_boundary.BoundaryError, "FIREWALL_INSTALLATION_MISMATCH"
                ):
                    firewall_boundary.remove(ledger)
            pause.assert_called_once_with(
                firewall_boundary.RESTORATION_POLL_INTERVAL_SECONDS
            )
            command.assert_not_called()
            self.assertTrue(ledger.exists())

    def test_cleanup_wait_inspection_failure_keeps_retry_evidence(self) -> None:
        baseline = [{"table": {"family": "ip", "name": "foreign"}}]
        changed = baseline + [
            {"chain": {"family": "ip", "table": "foreign", "name": "pending"}}
        ]
        owned = owned_firewall_entries()
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            firewall_boundary.write_ledger(
                ledger,
                self._restoration_ledger_payload(baseline, markers_installed=False),
            )
            original = ledger.read_bytes()
            completion = firewall_boundary.restoration_completion_path(ledger)
            command = mock.Mock()
            pause = mock.Mock()
            with mock.patch.object(
                firewall_boundary,
                "privileged_prefix",
                return_value=(["nft"], "nftables-v1"),
            ), mock.patch.object(
                firewall_boundary,
                "read_ruleset",
                side_effect=[
                    changed + owned,
                    firewall_boundary.BoundaryError("FIREWALL_INSPECTION_FAILED"),
                ],
            ), mock.patch.object(
                firewall_boundary, "_run", command
            ), mock.patch.object(
                firewall_boundary.time, "sleep", pause
            ):
                with self.assertRaisesRegex(
                    firewall_boundary.BoundaryError, "FIREWALL_INSPECTION_FAILED"
                ):
                    firewall_boundary.remove(ledger)
            pause.assert_called_once_with(
                firewall_boundary.RESTORATION_POLL_INTERVAL_SECONDS
            )
            command.assert_not_called()
            self.assertEqual(ledger.read_bytes(), original)
            self.assertFalse(completion.exists())

    def test_prepared_or_applied_install_interruption_remains_cleanup_retryable(self) -> None:
        baseline = [{"table": {"family": "ip", "name": "foreign"}}]
        owned = owned_firewall_entries()
        success = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        for boundary, rulesets, expected_remove_calls in (
            ("prepared-before-install", [baseline, baseline], 0),
            ("applied-before-ledger-update", [baseline + owned, baseline], 2),
        ):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as directory:
                ledger = Path(directory) / "ledger.json"
                firewall_boundary.write_ledger(
                    ledger, self._prepared_ledger_payload(baseline)
                )
                completion = firewall_boundary.restoration_completion_path(ledger)
                command = mock.Mock(return_value=success)
                with mock.patch.object(
                    firewall_boundary,
                    "privileged_prefix",
                    return_value=(["nft"], "nftables-v1"),
                ), mock.patch.object(
                    firewall_boundary, "read_ruleset", side_effect=rulesets
                ), mock.patch.object(
                    firewall_boundary, "_run", command
                ), contextlib.redirect_stdout(io.StringIO()):
                    firewall_boundary.remove(ledger)
                self.assertEqual(command.call_count, expected_remove_calls)
                self.assertFalse(ledger.exists())
                self.assertTrue(completion.exists())

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
                    "preimage_semantic_sha256": firewall_boundary.semantic_snapshot(foreign),
                    "preimage_counts": pre_counts,
                    "installation_sha256": pre_sha,
                    "installation_semantic_sha256": firewall_boundary.semantic_snapshot(foreign),
                    "installation_counts": pre_counts,
                    "installed": True,
                    "owned_sha256": "a" * 64,
                    "markers_installed": False,
                    "marker_sha256": "",
                    "combined_sha256": "",
                },
            )
            with mock.patch.object(firewall_boundary, "privileged_prefix", return_value=(["nft"], "nftables-v1")), mock.patch.object(
                firewall_boundary, "read_ruleset", return_value=foreign + owned_firewall_entries()
            ), mock.patch.object(firewall_boundary, "_run", return_value=failed):
                with self.assertRaisesRegex(firewall_boundary.BoundaryError, "FIREWALL_ATOMIC_ROLLBACK_CHECK_FAILED"):
                    firewall_boundary.remove(ledger)
            self.assertTrue(ledger.exists())

    def test_restore_and_verification_interruptions_preserve_exact_ledger(self) -> None:
        foreign = [{"table": {"family": "ip", "name": "foreign-private"}}]
        changed = foreign + [
            {"chain": {"family": "ip", "table": "foreign-private", "name": "drift"}}
        ]
        owned = owned_firewall_entries()
        success = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        failed = subprocess.CompletedProcess([], 1, stdout="", stderr="blocked")

        def exercise(
            expected_code: str,
            *,
            rulesets: object,
            commands: object,
        ) -> None:
            with tempfile.TemporaryDirectory() as directory:
                ledger = Path(directory) / "ledger.json"
                firewall_boundary.write_ledger(
                    ledger,
                    self._restoration_ledger_payload(foreign, markers_installed=False),
                )
                original = ledger.read_bytes()
                completion = firewall_boundary.restoration_completion_path(ledger)
                with mock.patch.object(
                    firewall_boundary,
                    "privileged_prefix",
                    return_value=(["nft"], "nftables-v1"),
                ), mock.patch.object(
                    firewall_boundary, "read_ruleset", side_effect=rulesets
                ), mock.patch.object(
                    firewall_boundary, "_run", side_effect=commands
                ):
                    with self.assertRaisesRegex(
                        firewall_boundary.BoundaryError, expected_code
                    ):
                        firewall_boundary.remove(ledger)
                self.assertEqual(ledger.read_bytes(), original)
                self.assertFalse(completion.exists())

        with self.subTest(boundary="before-restore"):
            exercise(
                "FIREWALL_ATOMIC_ROLLBACK_CHECK_FAILED",
                rulesets=[foreign + owned],
                commands=[failed],
            )
        with self.subTest(boundary="during-restore"):
            exercise(
                "FIREWALL_ATOMIC_ROLLBACK_FAILED",
                rulesets=[foreign + owned],
                commands=[success, failed],
            )
        with self.subTest(boundary="after-restore-before-verify"):
            exercise(
                "FIREWALL_INSPECTION_FAILED",
                rulesets=[
                    foreign + owned,
                    firewall_boundary.BoundaryError("FIREWALL_INSPECTION_FAILED"),
                ],
                commands=[success, success],
            )
        with self.subTest(boundary="verification-failure"):
            exercise(
                "FIREWALL_FOREIGN_STATE_DRIFT",
                rulesets=[foreign + owned, changed],
                commands=[success, success],
            )

    def test_completion_publication_and_ledger_retirement_are_retry_safe(self) -> None:
        foreign = [{"table": {"family": "ip", "name": "foreign-private"}}]
        owned = owned_firewall_entries()
        success = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            payload = self._restoration_ledger_payload(foreign, markers_installed=False)
            firewall_boundary.write_ledger(ledger, payload)
            original = ledger.read_bytes()
            completion = firewall_boundary.restoration_completion_path(ledger)
            stage = firewall_boundary.restoration_stage_path(completion)
            with mock.patch.object(
                firewall_boundary,
                "privileged_prefix",
                return_value=(["nft"], "nftables-v1"),
            ), mock.patch.object(
                firewall_boundary,
                "read_ruleset",
                side_effect=[foreign + owned, foreign],
            ), mock.patch.object(
                firewall_boundary, "_run", return_value=success
            ), mock.patch.object(
                firewall_boundary.os, "link", side_effect=OSError("publish blocked")
            ):
                with self.assertRaisesRegex(
                    firewall_boundary.BoundaryError,
                    "FIREWALL_RESTORATION_COMPLETION_FAILED",
                ):
                    firewall_boundary.remove(ledger)
            self.assertEqual(ledger.read_bytes(), original)
            self.assertFalse(completion.exists())
            self.assertFalse(stage.exists())

            with mock.patch.object(
                firewall_boundary,
                "privileged_prefix",
                return_value=(["nft"], "nftables-v1"),
            ), mock.patch.object(
                firewall_boundary,
                "read_ruleset",
                side_effect=[foreign, foreign],
            ), mock.patch.object(
                firewall_boundary,
                "_retire_private_path",
                side_effect=firewall_boundary.BoundaryError(
                    "FIREWALL_LEDGER_RETIREMENT_FAILED"
                ),
            ):
                with self.assertRaisesRegex(
                    firewall_boundary.BoundaryError,
                    "FIREWALL_LEDGER_RETIREMENT_FAILED",
                ):
                    firewall_boundary.remove(ledger)
            self.assertEqual(ledger.read_bytes(), original)
            self.assertTrue(completion.exists())
            completed = firewall_boundary.read_completion(completion)
            self.assertEqual(completed["ledger_sha256"], firewall_boundary.ledger_sha256(payload))

            with mock.patch.object(
                firewall_boundary,
                "privileged_prefix",
                return_value=(["nft"], "nftables-v1"),
            ), mock.patch.object(
                firewall_boundary, "read_ruleset", return_value=foreign
            ), contextlib.redirect_stdout(io.StringIO()):
                firewall_boundary.remove(ledger)
            self.assertFalse(ledger.exists())
            self.assertFalse(completion.exists())

    def test_cleanup_retry_matrix_is_closed_and_evidence_bound(self) -> None:
        foreign = [{"table": {"family": "ip", "name": "foreign-private"}}]
        changed = foreign + [
            {"chain": {"family": "ip", "table": "foreign-private", "name": "changed"}}
        ]
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            completion = firewall_boundary.restoration_completion_path(ledger)
            payload = self._restoration_ledger_payload(foreign, markers_installed=False)

            # Ledger only: re-verify restoration, publish completion, then retire the ledger.
            firewall_boundary.write_ledger(ledger, payload)
            state = io.StringIO()
            with mock.patch.object(
                firewall_boundary,
                "privileged_prefix",
                return_value=(["nft"], "nftables-v1"),
            ), mock.patch.object(
                firewall_boundary, "read_ruleset", side_effect=[foreign, foreign]
            ), contextlib.redirect_stdout(state):
                firewall_boundary.remove(ledger)
            self.assertFalse(ledger.exists())
            self.assertTrue(completion.exists())
            self.assertIn("firewall.rollback_idempotent\tbool\tfalse", state.getvalue())

            # Completion only: prove current restoration before consuming completion evidence.
            with mock.patch.object(
                firewall_boundary,
                "privileged_prefix",
                return_value=(["nft"], "nftables-v1"),
            ), mock.patch.object(
                firewall_boundary, "read_ruleset", return_value=foreign
            ), mock.patch.object(
                firewall_boundary,
                "_retire_private_path",
                side_effect=firewall_boundary.BoundaryError(
                    "FIREWALL_RESTORATION_COMPLETION_RETIREMENT_FAILED"
                ),
            ):
                with self.assertRaisesRegex(
                    firewall_boundary.BoundaryError,
                    "FIREWALL_RESTORATION_COMPLETION_RETIREMENT_FAILED",
                ):
                    firewall_boundary.remove(ledger)
            self.assertTrue(completion.exists())
            with mock.patch.object(
                firewall_boundary,
                "privileged_prefix",
                return_value=(["nft"], "nftables-v1"),
            ), mock.patch.object(
                firewall_boundary, "read_ruleset", return_value=foreign
            ), contextlib.redirect_stdout(io.StringIO()):
                firewall_boundary.remove(ledger)
            self.assertFalse(completion.exists())

            # Both: resume an interruption after completion publication and retire both.
            firewall_boundary.write_ledger(ledger, payload)
            valid = firewall_boundary.build_completion(
                payload, payload["preimage_sha256"], payload["preimage_counts"]
            )
            firewall_boundary.write_completion(completion, valid)
            with mock.patch.object(
                firewall_boundary,
                "privileged_prefix",
                return_value=(["nft"], "nftables-v1"),
            ), mock.patch.object(
                firewall_boundary, "read_ruleset", return_value=foreign
            ), contextlib.redirect_stdout(io.StringIO()):
                firewall_boundary.remove(ledger)
            self.assertFalse(ledger.exists())
            self.assertFalse(completion.exists())

            # Neither is never silently idempotent.
            with mock.patch.object(
                firewall_boundary,
                "privileged_prefix",
                return_value=(["nft"], "nftables-v1"),
            ), mock.patch.object(
                firewall_boundary, "read_ruleset", return_value=foreign
            ):
                with self.assertRaisesRegex(
                    firewall_boundary.BoundaryError,
                    "FIREWALL_RESTORATION_EVIDENCE_MISSING",
                ):
                    firewall_boundary.remove(ledger)

            # A valid completion cannot bless a different current foreign state.
            firewall_boundary.write_completion(completion, valid)
            with mock.patch.object(
                firewall_boundary,
                "privileged_prefix",
                return_value=(["nft"], "nftables-v1"),
            ), mock.patch.object(
                firewall_boundary, "read_ruleset", return_value=changed
            ):
                with self.assertRaisesRegex(
                    firewall_boundary.BoundaryError,
                    "FIREWALL_RESTORATION_EVIDENCE_INVALID",
                ):
                    firewall_boundary.remove(ledger)
            self.assertTrue(completion.exists())

            # A completion tied to a different valid ledger is rejected with both retained.
            mismatched_payload = dict(payload)
            mismatched_payload["owned_sha256"] = "b" * 64
            firewall_boundary.write_ledger(ledger, mismatched_payload)
            with mock.patch.object(
                firewall_boundary,
                "privileged_prefix",
                return_value=(["nft"], "nftables-v1"),
            ), mock.patch.object(
                firewall_boundary, "read_ruleset", return_value=foreign
            ):
                with self.assertRaisesRegex(
                    firewall_boundary.BoundaryError,
                    "FIREWALL_RESTORATION_EVIDENCE_INVALID",
                ):
                    firewall_boundary.remove(ledger)
            self.assertTrue(ledger.exists())
            self.assertTrue(completion.exists())

    def test_completion_evidence_rejects_forgery_and_suppresses_raw_state(self) -> None:
        foreign = [{"table": {"family": "ip", "name": "raw-foreign-name"}}]
        payload = self._restoration_ledger_payload(foreign, markers_installed=False)
        completion_value = firewall_boundary.build_completion(
            payload, payload["preimage_sha256"], payload["preimage_counts"]
        )
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "ledger.json"
            completion = firewall_boundary.restoration_completion_path(ledger)
            firewall_boundary.write_completion(completion, completion_value)
            raw = completion.read_text(encoding="utf-8")
            for forbidden in (
                "br-fpro001",
                "172.31.253.0/24",
                "raw-foreign-name",
                firewall_boundary.INPUT_COUNTER,
                '"packets"',
                '"bytes"',
            ):
                self.assertNotIn(forbidden, raw)
            expected_mode = "0o666" if os.name == "nt" else "0o600"
            self.assertEqual(oct(completion.stat().st_mode & 0o777), expected_mode)

            forged = dict(completion_value)
            forged["evidence_sha256"] = "0" * 64
            completion.write_text(
                json.dumps(forged, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                firewall_boundary.BoundaryError,
                "FIREWALL_RESTORATION_EVIDENCE_INVALID",
            ):
                firewall_boundary.read_completion(completion)

            completion.write_text(
                '{"schema":"x","schema":"y"}\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(
                firewall_boundary.BoundaryError,
                "FIREWALL_RESTORATION_EVIDENCE_INVALID",
            ):
                firewall_boundary.read_completion(completion)

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
