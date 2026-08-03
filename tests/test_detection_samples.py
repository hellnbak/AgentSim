import ast
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from agentsim.api import (
    detection_alert_samples,
    detection_samples,
    export_detection_samples,
)
from agentsim.cli import main as cli_main
from agentsim.defense import detection_alert_from_mapping
from agentsim.detection import (
    ALERT_SAMPLE_PROFILES,
    DETECTION_SAMPLE_FORMATS,
    alert_sample_records,
    detection_sample_catalog,
    evaluate_rule,
    export_detection_sample_library,
    load_detection_samples,
    render_detection_sample,
    sample_detection_pack,
    sample_telemetry,
)
from agentsim.detection.ast import parse_rule
from agentsim.telemetry.normalization import normalize_record
from scenarios import SCENARIOS


class DetectionSampleLibraryTests(unittest.TestCase):
    def test_catalog_covers_every_supported_format_and_connector(self):
        catalog = detection_sample_catalog()
        self.assertEqual(catalog["sample_count"], 6)
        self.assertEqual(tuple(catalog["detection_formats"]), DETECTION_SAMPLE_FORMATS)
        self.assertEqual(tuple(catalog["alert_profiles"]), ALERT_SAMPLE_PROFILES)
        self.assertEqual(catalog["detection_rule_variant_count"], 48)
        self.assertEqual(catalog["detection_file_count"], 54)
        self.assertEqual(catalog["alert_record_count"], 42)
        self.assertFalse(catalog["content_values_recorded"])
        self.assertFalse(catalog["execution_performed"])
        for sample in load_detection_samples():
            self.assertIn(sample.scenario_id, SCENARIOS)

    def test_generic_rules_match_malicious_and_reject_benign_controls(self):
        pack = sample_detection_pack()
        malicious = sample_telemetry("malicious")
        benign = sample_telemetry("benign")
        self.assertEqual(len(pack.rules), 6)
        for index, packed in enumerate(pack.rules):
            with self.subTest(rule=packed.rule.rule_id):
                self.assertTrue(evaluate_rule(packed.rule, (malicious[index],)).matched)
                self.assertFalse(evaluate_rule(packed.rule, (benign[index],)).matched)
                self.assertIn("trace_id", packed.required_fields)

    def test_each_detection_format_is_rendered_and_panther_python_parses(self):
        for sample in load_detection_samples():
            for format_name in DETECTION_SAMPLE_FORMATS:
                with self.subTest(sample=sample.sample_id, format=format_name):
                    rendered = render_detection_sample(sample, format_name)
                    self.assertTrue(rendered)
                    for filename, content in rendered.items():
                        self.assertTrue(filename.startswith(sample.sample_id))
                        self.assertNotIn("scenario_variant", content)
                        if format_name != "generic":
                            self.assertIn("TUNING", content.upper())
                    if format_name == "generic":
                        parse_rule(json.loads(next(iter(rendered.values()))))
                    if format_name == "panther":
                        ast.parse(rendered[f"{sample.sample_id}.py"])

    def test_alert_samples_are_content_safe_trace_linked_and_normalizable(self):
        prohibited = {
            "credential",
            "message",
            "password",
            "payload",
            "prompt",
            "response",
            "secret",
            "token",
            "tool_arguments",
            "tool_result",
        }
        for profile in ALERT_SAMPLE_PROFILES:
            records = alert_sample_records(profile)
            self.assertEqual(len(records), 6)
            for record in records:
                rendered = json.dumps(record).casefold()
                self.assertTrue(all(f'"{key}"' not in rendered for key in prohibited))
                if profile == "generic":
                    alert = detection_alert_from_mapping(record)
                    self.assertTrue(alert.trace_id)
                    self.assertTrue(alert.source_record_ids)
                    self.assertTrue(alert.synthetic)
                    self.assertFalse(alert.content_values_recorded)
                else:
                    event = normalize_record(record, collector=profile, synthetic=True)
                    self.assertTrue(event.source_record_id)
                    self.assertTrue(event.get("trace_id"))
                    self.assertTrue(event.synthetic)

    def test_export_is_deterministic_hashed_and_matches_repository_examples(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first"
            second = Path(directory) / "second"
            export_detection_sample_library(first)
            export_detection_samples(second)
            first_manifest = json.loads((first / "manifest.json").read_text())
            second_manifest = json.loads((second / "manifest.json").read_text())
            repository_manifest = json.loads(
                Path("examples/detection-samples/manifest.json").read_text()
            )
            self.assertEqual(first_manifest, second_manifest)
            self.assertEqual(first_manifest, repository_manifest)
            self.assertEqual(first_manifest["detection_file_count"], 54)
            self.assertEqual(first_manifest["alert_record_count"], 42)
            for item in first_manifest["files"]:
                data = (first / item["path"]).read_bytes()
                self.assertEqual(len(data), item["size"])
                self.assertEqual(hashlib.sha256(data).hexdigest(), item["sha256"])

    def test_cli_and_python_api_expose_sample_library(self):
        self.assertEqual(detection_samples()["alert_record_count"], 42)
        self.assertEqual(len(detection_alert_samples("sentinel")), 6)
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(cli_main(["detection", "samples"]), 0)
        self.assertEqual(json.loads(output.getvalue())["detection_file_count"], 54)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "samples"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    cli_main(
                        [
                            "detection",
                            "sample-export",
                            str(destination),
                            "--format",
                            "sigma",
                            "--alert-profile",
                            "splunk",
                        ]
                    ),
                    0,
                )
            manifest = json.loads((destination / "manifest.json").read_text())
            self.assertEqual(manifest["detection_formats"], ["sigma"])
            self.assertEqual(manifest["alert_profiles"], ["splunk"])
            self.assertEqual(manifest["detection_file_count"], 6)
            self.assertEqual(manifest["alert_record_count"], 6)

    def test_new_schemas_are_valid_json_and_registered_for_packaging(self):
        names = {
            "detection-sample-catalog.schema.json",
            "detection-alert-sample.schema.json",
            "detection-sample-export.schema.json",
        }
        for name in names:
            json.loads((Path("schemas") / name).read_text(encoding="utf-8"))
        pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
        setup = Path("setup.py").read_text(encoding="utf-8")
        for name in names:
            self.assertIn(name, pyproject)
            self.assertIn(name, setup)


if __name__ == "__main__":
    unittest.main()
