import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from agentsim.api import detection_drift, detection_feedback_reconciliation
from agentsim.cli import main as cli_main
from agentsim.defense import (
    DetectionAlert,
    DetectionSnapshot,
    OperatorAnnotation,
    compare_detection_snapshots,
    operator_annotation_from_mapping,
    parse_feedback_bundle,
    reconcile_detection_feedback,
)
from agentsim.detection import load_detection_pack, sweep_detection_pack
from agentsim.lab import list_fixtures, run_reference_fixture, run_reference_suite
from scenarios import SCENARIOS


class FeedbackReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.run = run_reference_fixture("detection-feedback-integrity")
        self.events = tuple(event.to_normalized_event() for event in self.run.events)
        self.malicious = tuple(
            event
            for event in self.run.events
            if event.attributes.get("variant") == "malicious"
        )
        self.benign = tuple(
            event
            for event in self.run.events
            if event.attributes.get("variant") == "benign"
        )
        self.alert = DetectionAlert(
            "alert-1",
            "agentsim.feedback-identity-evidence-tampering",
            self.malicious[0].timestamp,
            "critical",
            trace_id=self.malicious[0].trace_id,
            source_record_ids=(self.malicious[0].event_id,),
            agent_id="detection-agent",
        )

    def annotation(self, **overrides):
        values = {
            "annotation_id": "annotation-1",
            "target_type": "alert",
            "target_id": self.alert.alert_id,
            "disposition": "confirmed_true_positive",
            "reason_code": "control_failure",
            "author_id": "human-reviewer",
            "author_type": "human",
            "created_at": self.malicious[1].timestamp,
            "evidence_ids": (self.malicious[0].event_id,),
            "evidence_digest_match": True,
        }
        values.update(overrides)
        return OperatorAnnotation(**values)

    def test_feedback_contract_rejects_free_text_and_invalid_digest_type(self):
        with self.assertRaisesRegex(ValueError, "unknown feedback bundle fields"):
            parse_feedback_bundle(
                {"schema_version": "1.0", "alerts": [], "annotations": [], "prompt": "raw"}
            )
        with self.assertRaisesRegex(ValueError, "boolean or null"):
            operator_annotation_from_mapping(
                {
                    **self.annotation().to_dict(),
                    "evidence_digest_match": "yes",
                }
            )
        with self.assertRaisesRegex(ValueError, "time and UTC offset"):
            parse_feedback_bundle(
                {
                    "schema_version": "1.0",
                    "alerts": [
                        {
                            "alert_id": "alert",
                            "rule_id": "rule",
                            "detected_at": "2026-08-02",
                            "severity": "high",
                        }
                    ],
                    "annotations": [],
                }
            )

    def test_alert_matches_trace_and_human_verdict_is_clean(self):
        report = reconcile_detection_feedback(
            (self.alert,), self.events, (self.annotation(),)
        )
        self.assertEqual(report.status, "clean")
        self.assertEqual(report.score, 100)
        self.assertEqual(report.reconciliations[0].status, "matched")
        self.assertEqual(report.summary["match_rate_percent"], 100.0)
        self.assertEqual(report.summary["annotation_coverage_percent"], 100.0)
        self.assertFalse(report.to_dict()["content_values_recorded"])

    def test_agent_false_positive_and_bad_digest_are_critical(self):
        annotation = self.annotation(
            disposition="false_positive",
            reason_code="insufficient_evidence",
            author_id="remediation-agent",
            author_type="agent",
            evidence_digest_match=False,
        )
        report = reconcile_detection_feedback((self.alert,), self.events, (annotation,))
        codes = {item.code for item in report.conflicts}
        self.assertEqual(report.status, "critical")
        self.assertIn("annotation_evidence_digest_mismatch", codes)
        self.assertIn("agent_authored_final_verdict", codes)
        self.assertIn("high_risk_trace_dismissed", codes)

    def test_conflicting_explicit_and_evidence_traces_are_ambiguous(self):
        alert = DetectionAlert(
            "alert-conflict",
            "test.rule",
            self.malicious[0].timestamp,
            "high",
            trace_id=self.malicious[0].trace_id,
            source_record_ids=(self.benign[0].event_id,),
        )
        report = reconcile_detection_feedback((alert,), self.events)
        self.assertEqual(report.status, "elevated")
        self.assertEqual(report.reconciliations[0].status, "ambiguous")
        self.assertEqual(report.conflicts[0].code, "alert_trace_evidence_conflict")

    def test_stable_and_regressed_drift_reports(self):
        baseline = DetectionSnapshot("baseline", 38, 0, 38, 0, 3.0, 4, 4)
        stable = compare_detection_snapshots(
            baseline, DetectionSnapshot("stable", 38, 0, 38, 0, 3.0, 4, 4)
        )
        self.assertEqual(stable.status, "stable")
        self.assertEqual(stable.score, 100)
        regressed = compare_detection_snapshots(
            baseline, DetectionSnapshot("candidate", 31, 4, 34, 7, 6.0, 2, 4)
        )
        self.assertEqual(regressed.status, "regressed")
        self.assertEqual(
            {item.metric for item in regressed.findings},
            {
                "recall",
                "false_positive_rate",
                "reconciliation_rate",
                "mean_checkpoints_to_detection",
            },
        )
        self.assertEqual(
            detection_drift(baseline, regressed.candidate)["status"], "regressed"
        )
        self.assertEqual(
            detection_feedback_reconciliation(
                (self.alert,), self.events, (self.annotation(),)
            )["status"],
            "clean",
        )
        with self.assertRaisesRegex(ValueError, "cannot exceed"):
            DetectionSnapshot("invalid", 1, 0, 1, 0, 1.0, 2, 1)
        with self.assertRaisesRegex(ValueError, "non-negative numbers"):
            compare_detection_snapshots(baseline, baseline, max_recall_drop=True)

    def test_cli_reconcile_and_drift_write_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            telemetry_path = root / "telemetry.jsonl"
            feedback_path = root / "feedback.json"
            feedback_report_path = root / "feedback-report.json"
            baseline_path = root / "baseline.json"
            candidate_path = root / "candidate.json"
            drift_report_path = root / "drift-report.json"
            telemetry_path.write_text(
                "\n".join(json.dumps(event.to_dict()) for event in self.run.events) + "\n",
                encoding="utf-8",
            )
            feedback_path.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "alerts": [self.alert.to_dict()],
                        "annotations": [self.annotation().to_dict()],
                    }
                ),
                encoding="utf-8",
            )
            baseline_path.write_text(
                json.dumps(
                    {
                        "snapshot_id": "baseline",
                        "true_positive": 38,
                        "false_positive": 0,
                        "true_negative": 38,
                        "false_negative": 0,
                        "mean_checkpoints_to_detection": 3,
                        "reconciled_alerts": 4,
                        "total_alerts": 4,
                    }
                ),
                encoding="utf-8",
            )
            candidate_path.write_text(
                json.dumps(
                    {
                        "snapshot_id": "candidate",
                        "true_positive": 31,
                        "false_positive": 4,
                        "true_negative": 34,
                        "false_negative": 7,
                        "mean_checkpoints_to_detection": 6,
                        "reconciled_alerts": 2,
                        "total_alerts": 4,
                    }
                ),
                encoding="utf-8",
            )
            with redirect_stdout(io.StringIO()):
                reconcile_code = cli_main(
                    [
                        "defense",
                        "reconcile",
                        str(feedback_path),
                        str(telemetry_path),
                        "--collector",
                        "agent_runtime",
                        "--output",
                        str(feedback_report_path),
                        "--fail-on",
                        "never",
                    ]
                )
                drift_code = cli_main(
                    [
                        "defense",
                        "drift",
                        str(baseline_path),
                        str(candidate_path),
                        "--output",
                        str(drift_report_path),
                        "--fail-on",
                        "never",
                    ]
                )
            self.assertEqual(reconcile_code, 0)
            self.assertEqual(drift_code, 0)
            self.assertEqual(
                json.loads(feedback_report_path.read_text(encoding="utf-8"))["status"],
                "clean",
            )
            self.assertEqual(
                json.loads(drift_report_path.read_text(encoding="utf-8"))["status"],
                "regressed",
            )


class V15ContentTests(unittest.TestCase):
    def test_v15_scenarios_and_reference_fixture_are_registered(self):
        expected = {
            "alert-verdict-poisoning",
            "alert-trace-reconciliation-confusion",
            "operator-annotation-trust-abuse",
            "detection-tuning-recall-collapse",
            "feedback-loop-alert-suppression",
        }
        self.assertTrue(expected.issubset(SCENARIOS))
        self.assertEqual(len(SCENARIOS), 41)
        for scenario_id in expected:
            self.assertEqual(SCENARIOS[scenario_id].pack_id, "agentsim.v15-feedback")
        self.assertEqual(len(list_fixtures()), 23)
        run = run_reference_fixture("detection-feedback-integrity")
        self.assertTrue(run.passed)
        self.assertEqual(len(run.events), 12)
        self.assertTrue(all(event.content_recorded is False for event in run.events))

    def test_pack_detects_feedback_fixture_without_answer_keys(self):
        events = tuple(
            event.to_normalized_event()
            for run in run_reference_suite()
            for event in run.events
        )
        pack = load_detection_pack()
        report = sweep_detection_pack(pack, events).to_dict()
        self.assertEqual(pack.version, "1.2.0")
        self.assertEqual(len(pack.rules), 15)
        self.assertEqual(
            report["summary"],
            {"detected": 12, "not_detected": 3, "visibility_gap": 0},
        )
        self.assertFalse(report["ground_truth_used"])

    def test_v15_schemas_are_packaged_source_content(self):
        for name in (
            "detection-feedback.schema.json",
            "detection-feedback-report.schema.json",
            "detection-drift-report.schema.json",
        ):
            value = json.loads(Path("schemas", name).read_text(encoding="utf-8"))
            self.assertEqual(
                value["$schema"], "https://json-schema.org/draft/2020-12/schema"
            )
        feedback_report_schema = json.loads(
            Path("schemas/detection-feedback-report.schema.json").read_text(
                encoding="utf-8"
            )
        )
        drift_report_schema = json.loads(
            Path("schemas/detection-drift-report.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(feedback_report_schema["$defs"]["alert"]["additionalProperties"])
        self.assertFalse(
            feedback_report_schema["$defs"]["annotation"]["additionalProperties"]
        )
        self.assertFalse(
            feedback_report_schema["$defs"]["summary"]["additionalProperties"]
        )
        self.assertFalse(
            drift_report_schema["properties"]["deltas"]["additionalProperties"]
        )
        self.assertFalse(
            drift_report_schema["$defs"]["snapshot"]["additionalProperties"]
        )


if __name__ == "__main__":
    unittest.main()
