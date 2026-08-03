import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from importlib import resources
from pathlib import Path

from agentsim.api import (
    community_pack_review,
    cross_runtime_conformance,
    lab_artifact_review,
    map_agent_telemetry,
    portable_mapping_catalog,
)
from agentsim.cli import main as cli_main
from agentsim.content import parse_community_trust_store, review_community_pack
from agentsim.lab import (
    artifact_reference_digest,
    parse_lab_artifact_reference,
    review_lab_artifact,
    review_lab_artifact_file,
    run_reference_fixture,
)
from agentsim.telemetry import (
    PORTABLE_PROFILES,
    agent_trace_from_portable_record,
    map_agent_trace,
    mapping_catalog,
    run_fixture_conformance,
)
from agentsim.telemetry.collectors import COLLECTOR_NAMES
from agentsim.telemetry.normalization import normalize_record
from scenarios import SCENARIOS, load_scenario_registry


class V17PortabilityAndTrustTests(unittest.TestCase):
    def setUp(self):
        self.event = run_reference_fixture("multi-agent-delegation-cascade").events[0]
        self.pack_path = Path("examples/community-ability-pack.signed.json")
        self.trust_path = Path("examples/community-trust-store.json")
        self.reference_path = Path(
            "labs/reference-agent/artifacts/synthetic-marker.reference.json"
        )

    def test_mapping_catalog_pins_versions_and_namespaces(self):
        catalog = mapping_catalog()
        self.assertFalse(catalog["content_values_recorded"])
        profiles = {item["profile"]: item for item in catalog["profiles"]}
        self.assertEqual(set(profiles), {"otel", "ecs", "ocsf"})
        self.assertEqual(profiles["otel"]["version"], "semantic-conventions-1.43.0")
        self.assertEqual(profiles["ecs"]["version"], "9.4.0")
        self.assertEqual(profiles["ocsf"]["version"], "1.8.0")
        self.assertEqual(profiles["otel"]["extension_namespace"], "attributes.agentsim")
        self.assertEqual(profiles["ocsf"]["extension_namespace"], "unmapped.agentsim")

    def test_each_mapping_round_trips_security_invariants_without_content(self):
        for profile in PORTABLE_PROFILES:
            with self.subTest(profile=profile):
                mapped = map_agent_trace(self.event, profile)
                value = mapped.to_dict()
                self.assertFalse(value["content_values_recorded"])
                self.assertGreater(value["mapping"]["native_coverage_percent"], 0)
                rendered = json.dumps(value).lower()
                self.assertNotIn("prompt_content", rendered)
                self.assertNotIn("response_content", rendered)
                restored = agent_trace_from_portable_record(
                    mapped.record, profile=profile, synthetic=self.event.synthetic
                )
                for field in (
                    "event_id",
                    "trace_id",
                    "agent_id",
                    "delegation_id",
                    "policy_decision",
                    "goal_integrity_valid",
                    "outcome",
                ):
                    self.assertEqual(getattr(restored, field), getattr(self.event, field))
                for key, expected in self.event.attributes.items():
                    self.assertEqual(restored.attributes[key], expected)

    def test_ecs_and_ocsf_collectors_retain_source_record_identity(self):
        self.assertIn("ecs", COLLECTOR_NAMES)
        self.assertIn("ocsf", COLLECTOR_NAMES)
        for profile in ("ecs", "ocsf"):
            with self.subTest(profile=profile):
                mapped = map_agent_trace(self.event, profile).record
                normalized = normalize_record(mapped, collector=profile, synthetic=True)
                self.assertEqual(normalized.source_record_id, self.event.event_id)
                self.assertEqual(normalized.fields["trace_id"], self.event.trace_id)
                self.assertTrue(normalized.synthetic)

    def test_cross_runtime_fixture_conformance_is_exact_and_bounded(self):
        report = run_fixture_conformance("multi-agent-delegation-cascade")
        self.assertTrue(report.passed)
        self.assertEqual(tuple(item.profile for item in report.profiles), PORTABLE_PROFILES)
        self.assertTrue(all(item.invariant_checks > item.event_count for item in report.profiles))
        self.assertTrue(all(not item.failures for item in report.profiles))
        self.assertFalse(report.to_dict()["safety"]["content_values_recorded"])

    def test_community_pack_requires_checksum_trust_signature_and_provenance(self):
        pack = json.loads(self.pack_path.read_text(encoding="utf-8"))
        trust_value = json.loads(self.trust_path.read_text(encoding="utf-8"))
        trust = parse_community_trust_store(trust_value)
        approved = review_community_pack(pack, trusted_keys=trust)
        self.assertEqual(approved.verdict, "approved")
        self.assertTrue(all(approved.checks.values()))
        self.assertFalse(approved.to_dict()["execution_performed"])

        missing_trust = review_community_pack(pack)
        self.assertEqual(missing_trust.verdict, "blocked")
        self.assertTrue(missing_trust.checks["checksum"])
        self.assertFalse(missing_trust.checks["signature"])

        substituted = copy.deepcopy(pack)
        substituted["provenance"]["source"]["revision"] = "a" * 40
        tampered = review_community_pack(substituted, trusted_keys=trust)
        self.assertEqual(tampered.verdict, "blocked")
        self.assertTrue(tampered.checks["checksum"])
        self.assertFalse(tampered.checks["signature"])

    def test_provenance_and_trust_store_validation_are_strict(self):
        trust = json.loads(self.trust_path.read_text(encoding="utf-8"))
        trust["keys"]["agentsim-community-example-1"]["modulus_hex"] = "aa" * 64
        with self.assertRaisesRegex(ValueError, "malformed"):
            parse_community_trust_store(trust)

        pack = json.loads(self.pack_path.read_text(encoding="utf-8"))
        pack["provenance"]["source"]["repository"] = "http://example.invalid/repo"
        review = review_community_pack(pack)
        self.assertEqual(review.verdict, "blocked")
        self.assertTrue(any(item.code == "provenance_invalid" for item in review.findings))

    def test_lab_artifact_reference_is_reviewed_without_returning_content(self):
        review = review_lab_artifact_file(self.reference_path)
        value = review.to_dict()
        self.assertEqual(review.verdict, "approved")
        self.assertEqual(value["observed_sha256"], value["expected_sha256"])
        self.assertFalse(value["controls"]["execution_allowed"])
        self.assertFalse(value["controls"]["artifact_content_returned"])
        self.assertNotIn("content", value)

        packaged_root = Path(str(resources.files("agentsim.lab.artifact_content")))
        packaged = review_lab_artifact_file(
            packaged_root / "synthetic-marker.reference.json",
            lab_root=packaged_root,
        )
        self.assertEqual(packaged.verdict, "approved")

        raw = json.loads(self.reference_path.read_text(encoding="utf-8"))
        parsed = parse_lab_artifact_reference(raw)
        self.assertEqual(
            parsed.to_dict()["integrity"]["digest"],
            artifact_reference_digest(parsed.to_dict()),
        )

    def test_lab_artifact_path_escape_and_digest_substitution_are_blocked(self):
        raw = json.loads(self.reference_path.read_text(encoding="utf-8"))
        escaped = copy.deepcopy(raw)
        escaped["local_path"] = "../synthetic-marker.txt"
        escaped["integrity"]["digest"] = artifact_reference_digest(escaped)
        escaped_review = review_lab_artifact(escaped, lab_root=self.reference_path.parent)
        self.assertEqual(escaped_review.verdict, "blocked")
        self.assertEqual(escaped_review.findings[0].code, "reference_invalid")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "synthetic-marker.txt").write_text("substituted", encoding="utf-8")
            digest_review = review_lab_artifact(raw, lab_root=root)
            self.assertEqual(digest_review.verdict, "blocked")
            self.assertTrue(
                {item.code for item in digest_review.findings}
                >= {"size_mismatch", "digest_mismatch"}
            )

    def test_python_api_exposes_v17_contracts(self):
        self.assertEqual(len(portable_mapping_catalog()["profiles"]), 3)
        self.assertEqual(map_agent_telemetry(self.event, output_profile="ecs")["profile"], "ecs")
        self.assertTrue(cross_runtime_conformance("multi-agent-delegation-cascade")["passed"])
        self.assertEqual(
            community_pack_review(self.pack_path, trust_store_paths=(self.trust_path,))[
                "verdict"
            ],
            "approved",
        )
        self.assertEqual(lab_artifact_review(self.reference_path)["verdict"], "approved")

    def test_cli_maps_reviews_and_checks_conformance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "event.json"
            mapped_path = root / "mapped.json"
            report_path = root / "conformance.json"
            review_path = root / "review.json"
            artifact_path = root / "artifact-review.json"
            source.write_text(json.dumps(self.event.to_dict()), encoding="utf-8")

            self.assertEqual(
                cli_main(
                    [
                        "telemetry",
                        "map",
                        str(source),
                        "--to-profile",
                        "ecs",
                        "--output",
                        str(mapped_path),
                    ]
                ),
                0,
            )
            self.assertEqual(json.loads(mapped_path.read_text())["record_count"], 1)
            self.assertEqual(
                cli_main(
                    [
                        "lab",
                        "conformance",
                        "multi-agent-delegation-cascade",
                        "--output",
                        str(report_path),
                        "--fail-on-error",
                    ]
                ),
                0,
            )
            self.assertTrue(json.loads(report_path.read_text())["passed"])
            self.assertEqual(
                cli_main(
                    [
                        "content",
                        "review",
                        str(self.pack_path),
                        "--trust-store",
                        str(self.trust_path),
                        "--output",
                        str(review_path),
                    ]
                ),
                0,
            )
            self.assertEqual(json.loads(review_path.read_text())["verdict"], "approved")
            self.assertEqual(
                cli_main(
                    [
                        "lab",
                        "artifact-review",
                        str(self.reference_path),
                        "--output",
                        str(artifact_path),
                    ]
                ),
                0,
            )
            self.assertEqual(json.loads(artifact_path.read_text())["verdict"], "approved")

        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(cli_main(["telemetry", "mappings"]), 0)
        self.assertIn("semantic-conventions-1.43.0", output.getvalue())

    def test_v17_scenarios_are_loaded_and_remain_non_executing(self):
        expected = {
            "portable-mapping-security-field-loss",
            "community-pack-provenance-substitution",
            "lab-artifact-reference-substitution",
        }
        self.assertTrue(expected.issubset(SCENARIOS))
        artifact = SCENARIOS["lab-artifact-reference-substitution"]
        self.assertEqual(
            artifact.lab_artifact_ref,
            "lab-artifact://agentsim.synthetic.marker",
        )
        for scenario_id in expected:
            for step in (
                *SCENARIOS[scenario_id].malicious_steps,
                *SCENARIOS[scenario_id].benign_steps,
            ):
                self.assertFalse(step.attributes.get("executed", True))

    def test_scenario_artifact_reference_rejects_suffix_injection(self):
        source = json.loads(
            Path("agentsim_scenarios/packs/v17_portability.json").read_text(
                encoding="utf-8"
            )
        )
        artifact_scenario = next(
            item
            for item in source["scenarios"]
            if item["scenario_id"] == "lab-artifact-reference-substitution"
        )
        artifact_scenario["lab_artifact_ref"] = (
            "lab-artifact://agentsim.synthetic.marker?execute=true"
        )
        with tempfile.TemporaryDirectory() as directory:
            pack_path = Path(directory) / "invalid-artifact-reference.json"
            pack_path.write_text(json.dumps(source), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid format"):
                load_scenario_registry([pack_path], include_builtin=False)

    def test_every_json_schema_is_valid_json(self):
        schemas = tuple(Path("schemas").glob("*.schema.json"))
        self.assertGreaterEqual(len(schemas), 20)
        for schema in schemas:
            with self.subTest(schema=schema.name):
                value = json.loads(schema.read_text(encoding="utf-8"))
                self.assertIsInstance(value, dict)
                self.assertIn("$schema", value)


if __name__ == "__main__":
    unittest.main()
