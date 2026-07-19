from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_adapter():
    spec = importlib.util.spec_from_file_location(
        "fitness_full_chain_replay", ROOT / "scripts/fitness_full_chain_replay.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


adapter = load_adapter()


class FitnessSourceManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = adapter.read_json(ROOT / "fitness/contract.v1.json")
        cls.manifest = adapter.read_json(ROOT / "fitness/source-manifest.v1.json")

    def test_exact_source_denominator(self) -> None:
        adapter.validate_manifest(self.manifest, self.contract)
        self.assertEqual(self.manifest["repository"], "fawxzzy/fawxzzy-fitness")
        self.assertEqual(self.manifest["base"]["commit"], "317568f9dcbc7d6c9dcf2ad30ef1cd80022ce8b3")
        self.assertEqual(self.manifest["base"]["tree"], "bd4b2809a2a613a4bc67a4cc8166bee56d64a30f")
        self.assertEqual(self.manifest["candidate"]["commit"], "4ff406c92c1d9b9e7ab23a4ebdaa01820b9b5c01")
        self.assertEqual(self.manifest["candidate"]["tree"], "e8314980790dd9c711f63f4b38ad61e59ec6f409")
        self.assertEqual(len(self.manifest["migrations"]), 102)

    def test_chain_digests_and_single_delta(self) -> None:
        rows = self.manifest["migrations"]
        self.assertEqual(adapter.chain_digest(rows[:101]), "236ded2d260b2787838219f6e54fa63cbed80a8581930f165ca6025bca91db3a")
        self.assertEqual(adapter.chain_digest(rows), "711445d03b3d98466c278c4dfcbaa7cda326f188427b6dbcd55065fae1a2bbb5")
        self.assertEqual(
            self.manifest["delta"],
            {
                "added_count": 1,
                "historical_edit_count": 0,
                "path": "supabase/migrations/20260718015422_retire_human_member_number_compaction.sql",
                "git_blob": "007eca9503dfd10a6910a27b02a46def30583d18",
                "bytes": 15431,
                "sha256": "ca502e3bcef4532ce4de336d33334c5620efaf3863286db51f6440bb9224662d",
            },
        )

    def test_manifest_rejects_missing_extra_reordered_and_substituted_source(self) -> None:
        mutations = []
        missing = copy.deepcopy(self.manifest); missing["migrations"].pop(); mutations.append(missing)
        extra = copy.deepcopy(self.manifest); extra["migrations"].append(copy.deepcopy(extra["migrations"][-1])); mutations.append(extra)
        reordered = copy.deepcopy(self.manifest); reordered["migrations"][0], reordered["migrations"][1] = reordered["migrations"][1], reordered["migrations"][0]; mutations.append(reordered)
        digest = copy.deepcopy(self.manifest); digest["migrations"][0]["sha256"] = "0" * 64; mutations.append(digest)
        path = copy.deepcopy(self.manifest); path["migrations"][0]["path"] = "supabase/migrations/../escape.sql"; mutations.append(path)
        null = copy.deepcopy(self.manifest); null["migrations"][0]["bytes"] = None; mutations.append(null)
        repository = copy.deepcopy(self.manifest); repository["repository"] = "example/substitution"; mutations.append(repository)
        for value in mutations:
            with self.subTest(value=value.get("repository")):
                with self.assertRaises(ValueError):
                    adapter.validate_manifest(value, self.contract)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            adapter.parse_json_bytes(b'{"schema":"a","schema":"b"}')


class FitnessFixtureContractTests(unittest.TestCase):
    def test_fixture_is_closed_and_synthetic_only(self) -> None:
        sql = (ROOT / "scripts/fitness_replay_fixture.sql").read_text(encoding="utf-8")
        self.assertEqual(sql.count("'f1000000-0000-4000-8000-"), 12)
        self.assertEqual(sql.count("'fa000000-0000-4000-8000-000000000000'"), 2)
        self.assertIn("account_kind", sql)
        self.assertIn("user_number, user_kind, user_number_assigned_at", sql)
        self.assertNotRegex(sql, r"(?i)@[a-z]|discord|phone|display_name")
        self.assertNotIn("service_role", sql)

    def test_mapping_digest_is_sorted_and_null_preserving(self) -> None:
        rows = [
            ("human-001", "human", 1, True),
            ("automation-000", "automation", None, False),
            ("human-000", "human", 0, True),
        ]
        self.assertEqual(adapter.mapping_digest(rows), adapter.mapping_digest(reversed(rows)))
        changed = copy.deepcopy(rows); changed[0] = ("human-001", "human", 2, True)
        self.assertNotEqual(adapter.mapping_digest(rows), adapter.mapping_digest(changed))

    def test_mapping_digest_rejects_unknown_or_identity_bearing_labels(self) -> None:
        for rows in [
            [("real-user", "human", 1, True)],
            [("human-000@example.com", "human", 1, True)],
            [("human-000", "unknown", 1, True)],
            [("human-000", "human", -1, True)],
            [("human-000", "human", 1, "yes")],
        ]:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                adapter.mapping_digest(rows)

    def test_concurrent_fixture_denominator_is_exact(self) -> None:
        statements = adapter.concurrent_insert_sql()
        self.assertEqual(len(statements), 8)
        self.assertEqual(len(set(statements)), 8)
        for index, sql in enumerate(statements):
            self.assertIn(f"f2000000-0000-4000-8000-{index:012d}", sql)
            self.assertIn("BEGIN;", sql)
            self.assertIn("COMMIT;", sql)
            self.assertNotRegex(sql, r"(?i)email|discord|password")


class FitnessReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = adapter.read_json(ROOT / "fitness/contract.v1.json")
        cls.manifest = adapter.read_json(ROOT / "fitness/source-manifest.v1.json")
        cls.valid_path = ROOT / "tests/fixtures/fitness_replay_receipt.valid.json"
        cls.valid = adapter.read_json(cls.valid_path)

    def validate(self, value) -> None:
        adapter.validate_receipt(value, self.manifest, self.contract)

    def resigned(self, value):
        value["receipt_sha256"] = adapter.self_digest(value, "receipt_sha256")
        return value

    def test_valid_receipt_and_wrapper(self) -> None:
        self.validate(self.valid)
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts/verify_fitness_replay_receipt.py"), "--input", str(self.valid_path)],
            capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")

    def test_published_schema_is_closed_at_every_receipt_object(self) -> None:
        schema = adapter.read_json(ROOT / "fitness/receipt.schema.v1.json")
        self.assertFalse(schema["additionalProperties"])
        for name in ("adapter", "source", "migration_record", "migrations", "fixtures", "security", "containment", "cleanup", "timings"):
            with self.subTest(name=name):
                definition = schema["$defs"][name]
                self.assertEqual(definition["type"], "object")
                self.assertFalse(definition["additionalProperties"])
                self.assertEqual(set(definition["required"]), set(definition["properties"]))

    def test_receipt_rejects_source_order_digest_and_cleanup_failures(self) -> None:
        mutations = []
        source = copy.deepcopy(self.valid); source["source"]["candidate_commit"] = "0" * 40; mutations.append(source)
        order = copy.deepcopy(self.valid); order["migrations"]["records"][0], order["migrations"]["records"][1] = order["migrations"]["records"][1], order["migrations"]["records"][0]; mutations.append(order)
        digest = copy.deepcopy(self.valid); digest["migrations"]["records"][0]["sha256"] = "0" * 64; mutations.append(digest)
        incomplete = copy.deepcopy(self.valid); incomplete["cleanup"]["containers_remaining"] = 1; mutations.append(incomplete)
        missing = copy.deepcopy(self.valid); del missing["cleanup"]["networks_remaining"]; mutations.append(missing)
        extra = copy.deepcopy(self.valid); extra["cleanup"]["unknown"] = 0; mutations.append(extra)
        extra_fixture = copy.deepcopy(self.valid); extra_fixture["fixtures"]["unknown"] = 0; mutations.append(extra_fixture)
        extra_security = copy.deepcopy(self.valid); extra_security["security"]["unknown"] = False; mutations.append(extra_security)
        extra_containment = copy.deepcopy(self.valid); extra_containment["containment"]["unknown"] = False; mutations.append(extra_containment)
        extra_timing = copy.deepcopy(self.valid); extra_timing["timings"]["unknown"] = 0; mutations.append(extra_timing)
        null = copy.deepcopy(self.valid); null["cleanup"]["volumes_remaining"] = None; mutations.append(null)
        for value in mutations:
            self.resigned(value)
            with self.subTest(keys=value["cleanup"].keys()), self.assertRaises(ValueError):
                self.validate(value)

    def test_pass_receipt_requires_boolean_true_applied_records(self) -> None:
        for applied in (False, "true", 1, None):
            receipt = copy.deepcopy(self.valid)
            receipt["migrations"]["records"][0]["applied"] = applied
            records = receipt["migrations"]["records"]
            payload = [
                {key: row[key] for key in ("ordinal", "path", "sha256", "applied")}
                for row in records
            ]
            receipt["migrations"]["records_digest"] = adapter.sha256_bytes(
                adapter.canonical_bytes(payload)
            )
            self.resigned(receipt)
            with self.subTest(applied=applied), self.assertRaises(ValueError):
                self.validate(receipt)

    def test_receipt_rejects_unsafe_fields_and_values(self) -> None:
        for key, value in [
            ("email", "synthetic" + "@" + "example.com"),
            ("jwt", "eyJabcdefghijk" + ".abcdefghijk" + ".abcdefghijk"),
            ("database_url", "postgres" + "ql://user:pass" + "@host/db"),
            ("raw_log", "redacted"),
            ("profile_id", "00000000-0000-0000-0000-000000000000"),
        ]:
            receipt = copy.deepcopy(self.valid)
            receipt["adapter"][key] = value
            self.resigned(receipt)
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate(receipt)

    def test_known_fingerprint_does_not_validate_tampered_receipt(self) -> None:
        receipt = copy.deepcopy(self.valid)
        receipt["fixtures"]["concurrent_succeeded"] = 7
        with self.assertRaises(ValueError):
            self.validate(receipt)

    def test_malformed_duplicate_and_non_object_receipts_fail_silently(self) -> None:
        payloads = [b"{", b"[]", b'{"schema":"a","schema":"b"}', b"\xff"]
        for payload in payloads:
            with tempfile.NamedTemporaryFile(delete=False) as handle:
                handle.write(payload)
                name = handle.name
            try:
                result = subprocess.run(
                    [sys.executable, "-B", str(ROOT / "scripts/verify_fitness_replay_receipt.py"), "--input", name],
                    capture_output=True, check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr, b"")
            finally:
                os.unlink(name)


class FitnessRuntimeSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (ROOT / "scripts/fitness_full_chain_replay.py").read_text(encoding="utf-8")
        cls.contract = adapter.read_json(ROOT / "fitness/contract.v1.json")

    def test_no_host_socket_or_tcp_fallback(self) -> None:
        self.assertIn('"unix:///run/fp-hosted-replay-jit-v1/docker.sock"', (ROOT / "fitness/contract.v1.json").read_text(encoding="utf-8"))
        self.assertIn('"unix:///run/fp-hosted-replay-jit-v1/observer.sock"', (ROOT / "fitness/contract.v1.json").read_text(encoding="utf-8"))
        self.assertIn('self.docker_host == "unix:///var/run/docker.sock"', self.source)
        self.assertNotRegex(self.source, r"docker\.tcp|tcp://|2375|2376")

    def test_attestation_requires_closed_exclusive_packet_runtime(self) -> None:
        for field in ("network_closed", "no_provider_credentials", "packet_vm", "exclusive_daemon", "images", "cli_observer_host", "observer_sha256", "observer_policy", "attestation_sha256"):
            self.assertIn(field, self.source)
        self.assertIn("PRIVATE_RUNTIME_ATTESTATION_REJECTED", self.source)

    def test_cli_receives_only_policy_observer_socket(self) -> None:
        start = self.source[self.source.index("def start_database(") : self.source.index("def apply_migration(")]
        self.assertIn('cli_env["DOCKER_HOST"] = self.cli_observer_host', start)
        self.assertNotIn('cli_env["DOCKER_HOST"] = self.docker_host', start)

    def test_private_database_publication_is_exact_loopback_only(self) -> None:
        expected = {
            "5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "56422"}],
        }
        adapter.validate_private_database_publication(expected)
        rejected = [
            {},
            {"5432/tcp": None},
            {"5432/tcp": []},
            {"5432/tcp": [{"HostIp": "", "HostPort": "56422"}]},
            {"5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": "56422"}]},
            {"5432/tcp": [{"HostIp": "::", "HostPort": "56422"}]},
            {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "5432"}]},
            {"5432/tcp": [
                {"HostIp": "127.0.0.1", "HostPort": "56422"},
                {"HostIp": "127.0.0.1", "HostPort": "56423"},
            ]},
            {
                "5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "56422"}],
                "5433/tcp": [{"HostIp": "127.0.0.1", "HostPort": "56423"}],
            },
            {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "56422", "extra": True}]},
        ]
        for ports in rejected:
            with self.subTest(ports=ports), self.assertRaises(ValueError):
                adapter.validate_private_database_publication(ports)

    def test_private_namespace_publication_does_not_relax_host_listener_gate(self) -> None:
        self.assertEqual(self.contract["foundation"]["observer_policy"], "foundation-db-start-v1")
        self.assertEqual(adapter.PRIVATE_DATABASE_PORT, "56422")
        config = (ROOT / "supabase/config.toml").read_text(encoding="utf-8")
        self.assertRegex(config, r"(?m)^\[db\]\nport = 56422$")
        receipt = adapter.default_receipt(self.contract, "a" * 40, "b" * 40)
        self.assertEqual(receipt["containment"]["host_publication_count"], 0)
        self.assertIn(
            'listener.bind(("127.0.0.1", int(PRIVATE_DATABASE_PORT)))',
            self.source,
        )

    def test_source_is_staged_before_runtime_attestation(self) -> None:
        execute = self.source[self.source.index("def execute(expected_head:") : self.source.index("def verify_receipt(path:")]
        self.assertLess(execute.index("stage_source(SOURCE_ROOT"), execute.index("runtime.attest()"))
        self.assertLess(execute.index("runtime.attest()"), execute.index("runtime.start_database(project)"))

    def test_replay_is_exactly_101_fixture_candidate_and_idempotency_probe(self) -> None:
        self.assertIn('manifest["migrations"][:101]', self.source)
        self.assertIn("runtime.run_proofs(project, manifest[\"migrations\"][-1])", self.source)
        self.assertIn("self.apply_migration(candidate, project)", self.source)
        self.assertIn('self.receipt["migrations"]["candidate_applied_count"] = 1', self.source)
        self.assertIn('self.receipt["migrations"]["idempotency_rerun"] = True', self.source)

    def test_cleanup_is_exact_labeled_and_no_broad_prune(self) -> None:
        self.assertIn("label=com.supabase.cli.project", self.source)
        self.assertIn("label=io.fawxzzy.packet", self.source)
        self.assertIn('["ls", "-aq"] if object_type == "container"', self.source)
        self.assertIn('listener.bind(("127.0.0.1", int(PRIVATE_DATABASE_PORT)))', self.source)
        self.assertIn('network_names - {"bridge", "host", "none"}', self.source)
        self.assertNotRegex(self.source, r"system\s+prune|volume\s+prune|network\s+prune|rm\s+-rf\s+/|container\s+prune")
        self.assertIn("cleanup_only(expected_head", self.source)

    def test_runtime_never_accepts_provider_or_remote_selectors(self) -> None:
        prohibited = ["--linked", "--db-url", "SUPABASE_ACCESS_TOKEN", "SUPABASE_PROJECT", "service_role_key"]
        for value in prohibited:
            self.assertNotIn(value, self.source)

    def test_subprocess_output_is_not_printed(self) -> None:
        self.assertNotRegex(self.source, r"print\([^\n]*(stdout|stderr)")
        self.assertNotIn("capture_output=False", self.source)
        self.assertNotIn("check_call", self.source)

    def test_runtime_reenumerates_both_exact_git_trees(self) -> None:
        self.assertIn("migration_tree_rows(bare, source[\"base_tree\"])", self.source)
        self.assertIn("migration_tree_rows(bare, source[\"candidate_tree\"])", self.source)
        self.assertIn('["ls-tree", "-r", "-l", "-z"', self.source)

    def test_adapter_identity_rejects_wrong_head(self) -> None:
        completed = subprocess.CompletedProcess([], 0, stdout=b"a" * 40 + b"\n", stderr=b"")
        tree = subprocess.CompletedProcess([], 0, stdout=b"b" * 40 + b"\n", stderr=b"")
        with mock.patch.object(adapter, "run_command", side_effect=[completed, tree]):
            with self.assertRaises(adapter.ReplayFailure) as error:
                adapter.adapter_identity("c" * 40)
        self.assertEqual(error.exception.code, "ADAPTER_IDENTITY_MISMATCH")

    def test_cleanup_failures_cannot_produce_pass(self) -> None:
        receipt = adapter.default_receipt(self.contract, "a" * 40, "b" * 40)
        self.assertEqual(receipt["status"], "BLOCKED")
        self.assertFalse(receipt["cleanup"]["succeeded"])
        self.assertGreater(receipt["cleanup"]["runtime_residue_count"], 0)


class FitnessWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = (ROOT / ".github/workflows/fitness-full-chain-replay.yml").read_text(encoding="utf-8")

    def test_manual_read_only_no_secrets(self) -> None:
        self.assertIn("workflow_dispatch:", self.workflow)
        self.assertNotRegex(self.workflow, r"(?m)^\s{2}(push|pull_request|schedule|workflow_call):")
        self.assertRegex(self.workflow, r"(?ms)^permissions:\s*\n\s{2}contents: read\s*$")
        self.assertNotIn("secrets:", self.workflow)
        self.assertNotIn("id-token:", self.workflow)
        self.assertNotRegex(self.workflow, r"\$\{\{\s*secrets\.")

    def test_unique_runner_concurrency_timeout_and_retention(self) -> None:
        self.assertIn("runs-on: [self-hosted, linux, x64, fp-hosted-replay-jit-v1]", self.workflow)
        self.assertIn("group: fp-hosted-replay-fitness-full-chain-v1", self.workflow)
        self.assertIn("cancel-in-progress: false", self.workflow)
        self.assertIn("timeout-minutes: 30", self.workflow)
        self.assertIn("retention-days: 7", self.workflow)

    def test_exact_actions_and_sha_binding(self) -> None:
        self.assertIn("actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8", self.workflow)
        self.assertIn("actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02", self.workflow)
        self.assertIn("persist-credentials: false", self.workflow)
        self.assertEqual(self.workflow.count("${GITHUB_SHA}"), 2)
        self.assertNotIn("github.ref_name", self.workflow)

    def test_always_cleanup_validation_and_sanitized_artifact_only(self) -> None:
        self.assertGreaterEqual(self.workflow.count("if: always()"), 3)
        self.assertIn("cleanup-only", self.workflow)
        self.assertIn("verify_fitness_replay_receipt.py", self.workflow)
        self.assertEqual(self.workflow.count("artifacts/fitness-full-chain-replay.json"), 2)
        self.assertNotRegex(self.workflow, r"(?i)upload.*(log|raw|environment)")


if __name__ == "__main__":
    unittest.main()
