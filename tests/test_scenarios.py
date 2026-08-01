import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import scenarios


FROZEN_TIME = datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc)


class ScenarioEngineTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.events_path = Path(self.temp_dir.name) / "events.jsonl"
        self.report_path = Path(self.temp_dir.name) / "validation.json"

    def run_suite(self, scenario_ids="all", **overrides):
        options = {
            "variant": "both",
            "ground_truth_path": self.events_path,
            "validation_path": self.report_path,
            "speed_ms": 0,
            "log_callback": lambda _message: None,
            "run_id": "test-run",
            "clock": lambda: FROZEN_TIME,
        }
        options.update(overrides)
        return scenarios.run_scenario_suite(scenario_ids, **options)

    def test_catalog_has_a_benign_twin_for_every_scenario(self):
        scenario_ids = [definition.scenario_id for definition in scenarios.list_scenarios()]

        self.assertEqual(scenario_ids, sorted(scenarios.SCENARIOS))
        for definition in scenarios.list_scenarios():
            with self.subTest(scenario_id=definition.scenario_id):
                self.assertTrue(definition.malicious_steps)
                self.assertTrue(definition.benign_steps)
                self.assertIn("mitre_atlas", definition.mappings)
                self.assertIn("owasp_agentic", definition.mappings)

    def test_all_scenarios_emit_ground_truth_and_pass_controls(self):
        result = self.run_suite()

        self.assertTrue(result.passed)
        self.assertFalse(result.stopped)
        self.assertEqual(result.event_count, 21)
        self.assertEqual(result.check_count, 6)

        events = scenarios.load_ground_truth(self.events_path)
        self.assertEqual(len(events), 21)
        self.assertEqual(
            {event["scenario_variant"] for event in events},
            {"malicious", "benign"},
        )
        self.assertTrue(all(event["execution_mode"] == "simulation_only" for event in events))
        self.assertTrue(all(event["run_id"] == "test-run" for event in events))
        requested_tools = [
            event for event in events if event["event_type"] == "agent.tool.requested"
        ]
        self.assertTrue(
            all(event["attributes"]["executed"] is False for event in requested_tools)
        )

        report = json.loads(self.report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["summary"]["passed"], 6)
        self.assertEqual(report["summary"]["failed"], 0)
        self.assertTrue(report["summary"]["all_passed"])

    def test_each_malicious_trace_detects_and_benign_trace_does_not(self):
        self.run_suite()
        report = json.loads(self.report_path.read_text(encoding="utf-8"))

        by_scenario = {}
        for check in report["results"]:
            by_scenario.setdefault(check["scenario_id"], {})[check["variant"]] = check

        self.assertEqual(set(by_scenario), set(scenarios.SCENARIOS))
        for scenario_id, variants in by_scenario.items():
            with self.subTest(scenario_id=scenario_id):
                self.assertTrue(variants["malicious"]["detected"])
                self.assertFalse(variants["benign"]["detected"])
                self.assertTrue(variants["malicious"]["passed"])
                self.assertTrue(variants["benign"]["passed"])

    def test_network_events_are_loopback_only_and_never_executed(self):
        self.run_suite("decoy-secret-exfiltration")
        events = scenarios.load_ground_truth(self.events_path)
        network_events = [
            event for event in events if event["event_type"] == "agent.network.requested"
        ]

        self.assertEqual(len(network_events), 2)
        for event in network_events:
            attributes = event["attributes"]
            self.assertEqual(attributes["network_scope"], "loopback")
            self.assertTrue(attributes["destination"].startswith("http://127.0.0.1:"))
            self.assertFalse(attributes["executed"])
            self.assertFalse(attributes["payload_recorded"])

    @mock.patch("scenarios.time.sleep")
    def test_stop_writes_partial_artifacts_without_sleeping(self, sleep_mock):
        stop_callback = mock.Mock(side_effect=[False, False, True, True])

        result = self.run_suite(
            "indirect-prompt-injection",
            speed_ms=50,
            stop_callback=stop_callback,
        )

        self.assertTrue(result.stopped)
        self.assertFalse(result.passed)
        self.assertTrue(self.events_path.exists())
        self.assertTrue(self.report_path.exists())
        self.assertGreaterEqual(stop_callback.call_count, 3)
        sleep_mock.assert_not_called()

    def test_rejects_unknown_scenario_and_missing_output_directory(self):
        with self.assertRaisesRegex(ValueError, "unknown scenario"):
            self.run_suite("not-a-scenario")

        missing_path = Path(self.temp_dir.name) / "missing" / "events.jsonl"
        with self.assertRaisesRegex(FileNotFoundError, "output directory"):
            self.run_suite(ground_truth_path=missing_path)

        with self.assertRaisesRegex(ValueError, "speed_ms"):
            self.run_suite(speed_ms=-1)

    def test_loader_rejects_unknown_schema_version(self):
        self.events_path.write_text(
            json.dumps({"schema_version": "999"}) + "\n", encoding="utf-8"
        )

        with self.assertRaisesRegex(ValueError, "line 1"):
            scenarios.load_ground_truth(self.events_path)


if __name__ == "__main__":
    unittest.main()
