import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agentsim.api import detection_ci
from agentsim.cli import main as cli_main
from agentsim.content import load_ability_registry, load_campaign_registry
from agentsim.defense import compare_flight_bundles
from agentsim.detection import load_detection_pack
from agentsim.lab import run_reference_fixture
from agentsim.models.target import TargetProfile
from agentsim.orchestration.runner import CampaignRunner
from agentsim.safety.authorization import AuthorizationManifest
from agentsim.telemetry import (
    AgentSimTraceProcessor,
    FlightRecorder,
    FlightRecorderBundle,
    flight_bundle_from_mapping,
    otlp_records,
    serve_flight_recorder,
)


class _FakeTrace:
    trace_id = "trace-openai-1"
    group_id = "group-openai-1"
    name = "Synthetic support workflow"
    metadata = {"agent_id": "support-agent", "prompt": "must-not-survive"}


class _FakeFunctionData:
    type = "function"
    name = "synthetic.lookup"
    input = "secret function argument"
    output = "secret function result"
    metadata = {"tool_risk": "low", "message": "must-not-survive"}


class _FakeSpan:
    trace_id = "trace-openai-1"
    span_id = "span-openai-1"
    parent_id = None
    started_at = "2026-08-02T12:00:00Z"
    ended_at = "2026-08-02T12:00:01Z"
    span_data = _FakeFunctionData()
    error = None
    trace_metadata = {"group_id": "group-openai-1", "credential": "must-not-survive"}

    def export(self):
        raise AssertionError("content-bearing span export must never be called")


def _otlp_payload():
    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "checkout-agent"}},
                        {"key": "deployment.environment", "value": {"stringValue": "test"}},
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "openai-agents"},
                        "spans": [
                            {
                                "traceId": "trace-otlp-1",
                                "spanId": "span-otlp-1",
                                "name": "agent.tool.completed",
                                "startTimeUnixNano": "1785672000000000000",
                                "endTimeUnixNano": "1785672001000000000",
                                "attributes": [
                                    {
                                        "key": "gen_ai.tool.name",
                                        "value": {"stringValue": "synthetic.lookup"},
                                    },
                                    {
                                        "key": "gen_ai.prompt",
                                        "value": {"stringValue": "sensitive prompt"},
                                    },
                                    {
                                        "key": "gen_ai.usage.input_tokens",
                                        "value": {"intValue": "12"},
                                    },
                                ],
                                "status": {"code": "STATUS_CODE_OK"},
                            }
                        ],
                    }
                ],
            }
        ]
    }


def _bundle(events, recorder_id, classification="malicious"):
    return FlightRecorderBundle(
        recorder_id=recorder_id,
        source_runtime="reference-agent",
        classification=classification,
        started_at="2026-08-02T12:00:00Z",
        ended_at="2026-08-02T12:01:00Z",
        events=tuple(events),
    )


class FlightRecorderTests(unittest.TestCase):
    def test_openai_processor_never_exports_or_retains_content(self):
        recorder = FlightRecorder(
            source_runtime="openai-agents", recorder_id="flight-openai"
        )
        processor = AgentSimTraceProcessor(recorder)
        processor.on_trace_start(_FakeTrace())
        processor.on_span_end(_FakeSpan())
        processor.on_trace_end(_FakeTrace())
        bundle = recorder.snapshot()
        rendered = json.dumps(bundle.to_dict(), sort_keys=True)
        self.assertEqual(len(bundle.events), 3)
        self.assertNotIn("secret function", rendered)
        self.assertNotIn("must-not-survive", rendered)
        self.assertNotIn("sensitive prompt", rendered)
        self.assertFalse(bundle.to_dict()["content_values_recorded"])
        tool = next(event for event in bundle.events if event.event_type == "agent.tool.completed")
        self.assertEqual(tool.tool_name, "synthetic.lookup")
        self.assertFalse(tool.attributes["arguments_recorded"])
        self.assertFalse(tool.attributes["result_recorded"])

    def test_otlp_projection_and_synthetic_twin_are_content_safe(self):
        records = otlp_records(_otlp_payload())
        self.assertEqual(len(records), 1)
        self.assertNotIn("gen_ai.prompt", records[0]["attributes"])
        recorder = FlightRecorder(
            source_runtime="otlp", classification="malicious", recorder_id="flight-otlp"
        )
        self.assertEqual(recorder.ingest_otlp_export(_otlp_payload()), 1)
        bundle = recorder.snapshot()
        event = bundle.events[0]
        self.assertEqual(event.trace_id, "trace-otlp-1")
        self.assertEqual(event.agent_id, "checkout-agent")
        twin = bundle.synthetic_twin()
        self.assertEqual(len(twin), 1)
        self.assertTrue(twin[0].synthetic)
        self.assertNotEqual(twin[0].trace_id, event.trace_id)
        self.assertNotEqual(twin[0].agent_id, event.agent_id)
        self.assertFalse(twin[0].content_recorded)
        self.assertFalse(twin[0].attributes["executed"])

    def test_bundle_digest_round_trip_and_tamper_rejection(self):
        recorder = FlightRecorder(source_runtime="openai-agents", recorder_id="round-trip")
        recorder.record_openai_span(_FakeSpan())
        value = recorder.snapshot().to_dict()
        restored = flight_bundle_from_mapping(value)
        self.assertEqual(restored.recorder_id, "round-trip")
        self.assertEqual(len(restored.events), 1)
        tampered = json.loads(json.dumps(value))
        tampered["source_runtime"] = "tampered"
        with self.assertRaisesRegex(ValueError, "digest"):
            flight_bundle_from_mapping(tampered)

    def test_loopback_receiver_is_fail_closed(self):
        recorder = FlightRecorder(source_runtime="otlp")
        with self.assertRaisesRegex(ValueError, "explicit allow_loopback"):
            serve_flight_recorder(recorder, port=4318)
        with self.assertRaisesRegex(ValueError, "loopback only"):
            serve_flight_recorder(
                recorder, host="0.0.0.0", port=4318, allow_loopback=True
            )


class DetectionCiTests(unittest.TestCase):
    def setUp(self):
        run = run_reference_fixture("detection-feedback-integrity")
        malicious = [
            event for event in run.events if event.attributes.get("variant") == "malicious"
        ]
        benign = [event for event in run.events if event.attributes.get("variant") == "benign"]
        self.baseline = _bundle(malicious, "baseline-flight")
        self.candidate = _bundle(benign, "candidate-flight")
        self.pack = load_detection_pack()

    def test_detection_ci_blocks_lost_malicious_signals(self):
        report = compare_flight_bundles(self.baseline, self.candidate, pack=self.pack)
        self.assertEqual(report.status, "block")
        self.assertLess(report.score, 100)
        self.assertTrue(any(item.change == "regressed" for item in report.transitions))
        codes = {item.code for item in report.findings}
        self.assertIn("malicious_detection_lost", codes)
        value = report.to_dict()
        self.assertFalse(value["content_values_recorded"])
        self.assertEqual(value["ground_truth_source"], "explicit_expected_classification")
        self.assertEqual(
            detection_ci(self.baseline, self.candidate, expected_classification="malicious")[
                "status"
            ],
            "block",
        )

    def test_detection_ci_passes_identical_baseline_and_exports_artifacts(self):
        report = compare_flight_bundles(self.baseline, self.baseline, pack=self.pack)
        self.assertEqual(report.status, "pass")
        self.assertEqual(report.score, 100)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outputs = report.write_artifacts(
                json_path=root / "report.json",
                markdown_path=root / "report.md",
                junit_path=root / "report.xml",
                sarif_path=root / "report.sarif",
            )
            self.assertEqual(len(outputs), 4)
            self.assertIn("AgentSim Detection CI", (root / "report.md").read_text())
            self.assertIn("testsuite", (root / "report.xml").read_text())
            self.assertEqual(json.loads((root / "report.sarif").read_text())["version"], "2.1.0")

    def test_cli_records_twins_and_runs_detection_ci(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            telemetry = root / "telemetry.jsonl"
            baseline_path = root / "baseline.json"
            candidate_path = root / "candidate.json"
            twin_path = root / "twin.jsonl"
            report_path = root / "ci.json"
            markdown_path = root / "ci.md"
            telemetry.write_text(
                "\n".join(json.dumps(event.to_dict()) for event in self.baseline.events) + "\n",
                encoding="utf-8",
            )
            with redirect_stdout(io.StringIO()):
                code = cli_main(
                    [
                        "telemetry",
                        "record",
                        str(telemetry),
                        "--format",
                        "agent_runtime",
                        "--runtime",
                        "reference-agent",
                        "--classification",
                        "malicious",
                        "--output",
                        str(baseline_path),
                        "--twin-output",
                        str(twin_path),
                    ]
                )
            self.assertEqual(code, 0)
            self.assertTrue(twin_path.is_file())
            candidate_path.write_text(baseline_path.read_text(), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                ci_code = cli_main(
                    [
                        "detection",
                        "ci",
                        str(baseline_path),
                        str(candidate_path),
                        "--output",
                        str(report_path),
                        "--markdown-output",
                        str(markdown_path),
                    ]
                )
            self.assertEqual(ci_code, 0)
            self.assertEqual(json.loads(report_path.read_text())["status"], "pass")


class V16ContractTests(unittest.TestCase):
    def test_endpoint_cloud_preview_is_simulation_only_and_campaigns_run_without_execution(self):
        abilities = load_ability_registry()
        campaigns = load_campaign_registry()
        preview = [
            ability
            for ability in abilities.values()
            if ability.pack_id == "agentsim.preview.endpoint-cloud-controls"
        ]
        self.assertEqual(len(preview), 11)
        for ability in preview:
            self.assertEqual(ability.execution.supported_providers, ("simulate",))
            self.assertEqual(ability.execution.network_access, "denied")
            self.assertFalse(ability.execution.state_changes)
            self.assertFalse(ability.production_allowed)
            self.assertEqual(ability.metadata["trust"], "checksum-review-preview")

        campaign = campaigns["hybrid-agent-control-chain"]
        now = datetime.now(timezone.utc)
        manifest = AuthorizationManifest.from_mapping(
            {
                "manifest_id": "v16-directed-campaign-test",
                "authorized_by": "unit-test",
                "scope": "Non-executing directed campaign test",
                "issued_at": now.isoformat().replace("+00:00", "Z"),
                "expires_at": (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
                "allowed_modes": ["simulate"],
                "allowed_targets": ["synthetic://v16-test"],
                "allowed_ability_ids": list(campaign.ability_ids),
                "allow_network": False,
                "resource_limits": {
                    "max_actions": 12,
                    "max_duration_seconds": 60,
                    "max_processes": 1,
                    "max_cloud_spend_usd": 0,
                },
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = CampaignRunner(abilities, database_path=root / "runs.db").run(
                campaign,
                mode="simulate",
                target=TargetProfile.from_uri("synthetic://v16-test"),
                manifest=manifest,
                output_directory=root / "runs",
                run_id="v16-directed",
            )
        self.assertEqual(result.status, "completed")
        self.assertTrue(all(not action.attempted for action in result.actions))
        self.assertTrue(all(not action.executed for action in result.actions))

    def test_public_schemas_are_strict_json(self):
        for name in ("flight-recorder-bundle.schema.json", "detection-ci-report.schema.json"):
            value = json.loads(Path("schemas", name).read_text(encoding="utf-8"))
            self.assertEqual(value["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertFalse(value["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
