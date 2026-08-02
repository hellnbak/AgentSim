import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from agentsim.api import detection_pack_sweep, telemetry_assurance
from agentsim.cli import main as cli_main
from agentsim.detection import load_detection_pack, parse_detection_pack, sweep_detection_pack
from agentsim.lab import run_reference_suite
from agentsim.models.telemetry import NormalizedEvent
from agentsim.telemetry import assess_telemetry
from agentsim.telemetry.agent_contract import normalize_agent_records


def normalized_event(**changes):
    value = {
        "timestamp": "2026-08-02T00:00:00Z",
        "source": "agent_runtime",
        "event_type": "agent.observed",
        "fields": {"trace_id": "trace-1", "session_id": "session-1", "agent_id": "agent-1"},
        "available_fields": ("timestamp", "source", "event_type", "trace_id", "session_id", "agent_id"),
        "collector": "agent_runtime",
        "synthetic": True,
        "source_record_id": "event-1",
        "metadata": {
            "redacted": True,
            "content_recorded": False,
            "timestamp_present": True,
            "timestamp_valid": True,
            "source_record_id_present": True,
            "generated_identity_fields": [],
        },
    }
    value.update(changes)
    return NormalizedEvent(**value)


class TelemetryAssuranceTests(unittest.TestCase):
    def test_reference_agent_corpus_is_correlation_ready_and_content_safe(self):
        events = tuple(
            event.to_normalized_event()
            for run in run_reference_suite()
            for event in run.events
        )
        report = assess_telemetry(events)
        self.assertEqual(report.status, "healthy")
        self.assertEqual(report.score, 100)
        self.assertEqual(report.metrics["causal_link_success_percent"], 100.0)
        self.assertFalse(report.to_dict()["content_values_recorded"])
        self.assertEqual(telemetry_assurance(events)["status"], "healthy")

    def test_broken_cross_trace_and_content_evidence_cannot_look_healthy(self):
        parent = normalized_event()
        child = normalized_event(
            source_record_id="event-2",
            fields={
                "trace_id": "trace-2",
                "session_id": "session-2",
                "agent_id": "agent-1",
                "parent_event_id": "event-1",
                "prompt": "must-not-cross-boundary",
            },
            available_fields=(
                "timestamp",
                "source",
                "event_type",
                "trace_id",
                "session_id",
                "agent_id",
                "parent_event_id",
                "prompt",
            ),
        )
        report = assess_telemetry((parent, child))
        codes = {finding.code for finding in report.findings}
        self.assertEqual(report.status, "unusable")
        self.assertIn("cross_trace_causal_link", codes)
        self.assertIn("raw_content_exposed", codes)

    def test_agent_adapter_preserves_causal_ids_and_reports_generated_identity(self):
        event = normalize_agent_records(
            [
                {
                    "timestamp": "invalid",
                    "event_type": "agent.tool.requested",
                    "caused_by_event_ids": ["parent-1"],
                }
            ],
            collector="agent_runtime",
            synthetic=True,
        )[0]
        self.assertEqual(event.get("caused_by_event_ids"), ("parent-1",))
        self.assertFalse(event.metadata["timestamp_valid"])
        self.assertIn("trace_id", event.metadata["generated_identity_fields"])
        codes = {finding.code for finding in assess_telemetry((event,)).findings}
        self.assertIn("invalid_or_substituted_timestamp", codes)
        self.assertIn("generated_agent_identity", codes)


class DetectionPackTests(unittest.TestCase):
    def test_builtin_pack_is_answer_key_free_and_sweeps_reference_evidence(self):
        pack = load_detection_pack()
        self.assertEqual(pack.pack_id, "agentsim.agent-security-core")
        self.assertEqual(len(pack.rules), 12)
        self.assertNotIn("expected_detect", json.dumps(pack.to_dict()))
        events = tuple(
            event.to_normalized_event()
            for run in run_reference_suite()
            for event in run.events
        )
        report = sweep_detection_pack(pack, events).to_dict()
        self.assertEqual(report["summary"]["detected"], 9)
        self.assertEqual(report["summary"]["visibility_gap"], 0)
        self.assertFalse(report["ground_truth_used"])
        self.assertEqual(detection_pack_sweep(events)["pack_id"], pack.pack_id)

    def test_reference_mcp_authorization_closes_audience_and_consent_gaps(self):
        runs = {
            run.fixture_id: run
            for run in run_reference_suite()
            if run.fixture_id in {"mcp-permission-expansion", "mcp-identity-audience"}
        }
        permission = [
            event
            for event in runs["mcp-permission-expansion"].events
            if event.event_type == "mcp.authorization.checked"
        ]
        identity = [
            event
            for event in runs["mcp-identity-audience"].events
            if event.event_type == "mcp.authorization.checked"
        ]
        self.assertEqual(len(permission), 2)
        self.assertEqual(len(identity), 2)
        self.assertEqual({event.consent_valid for event in permission}, {False, True})
        self.assertEqual({event.auth_audience_valid for event in identity}, {False, True})
        self.assertTrue(all(event.mcp_client_id and event.mcp_server_id for event in permission + identity))

    def test_pack_loader_rejects_scenario_answer_keys(self):
        value = load_detection_pack().to_dict()
        value["metadata"]["ground_truth"] = "malicious"
        with self.assertRaisesRegex(ValueError, "answer-key"):
            parse_detection_pack(value)

    def test_cli_doctor_and_sweep_write_machine_readable_reports(self):
        records = [
            {
                "timestamp": "2026-08-02T00:00:00Z",
                "event_id": "event-1",
                "event_type": "agent.tool.requested",
                "trace_id": "trace-1",
                "session_id": "session-1",
                "agent_id": "agent-1",
                "principal_id": "principal-1",
                "tool_name": "mcp.synthetic.publish",
                "tool_risk": "high",
                "policy_id": "policy-1",
                "input_trust": "untrusted",
                "taint_labels": ["untrusted_input"],
            }
        ]
        with tempfile.TemporaryDirectory() as directory:
            telemetry_path = Path(directory) / "events.json"
            doctor_path = Path(directory) / "assurance.json"
            sweep_path = Path(directory) / "sweep.json"
            telemetry_path.write_text(json.dumps(records), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    cli_main(
                        [
                            "telemetry",
                            "doctor",
                            str(telemetry_path),
                            "--collector",
                            "agent_runtime",
                            "--output",
                            str(doctor_path),
                        ]
                    ),
                    0,
                )
                self.assertEqual(
                    cli_main(
                        [
                            "detection",
                            "sweep",
                            str(telemetry_path),
                            "--collector",
                            "agent_runtime",
                            "--output",
                            str(sweep_path),
                        ]
                    ),
                    0,
                )
            self.assertEqual(json.loads(doctor_path.read_text())["kind"], "telemetry-assurance-report")
            self.assertEqual(json.loads(sweep_path.read_text())["kind"], "detection-sweep-report")

    def test_v13_schemas_and_pack_content_are_packaged(self):
        names = {
            "telemetry-assurance-report.schema.json",
            "detection-pack.schema.json",
            "detection-sweep-report.schema.json",
        }
        for name in names:
            value = json.loads((Path("schemas") / name).read_text(encoding="utf-8"))
            self.assertEqual(value["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertTrue(
            Path("agentsim/detection/pack_content/agent_security_core.json").is_file()
        )


if __name__ == "__main__":
    unittest.main()
