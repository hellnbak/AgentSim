import json
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import core


class AgentSimTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.output_path = Path(self.temp_dir.name) / "layer.json"

    def make_simulator(self, **overrides):
        options = {
            "speed_ms": 0,
            "hallucination_rate": 0.0,
            "context_loss_rate": 0.0,
            "error_retry_rate": 0.0,
            "evasion_rate": 0.0,
            "dry_run": True,
            "output_path": self.output_path,
            "seed": 7,
            "os_type": "Linux",
            "log_callback": lambda _message: None,
        }
        options.update(overrides)
        return core.AgentSim(**options)

    def test_rejects_invalid_configuration(self):
        with self.assertRaisesRegex(ValueError, "speed_ms"):
            self.make_simulator(speed_ms=-1)
        with self.assertRaisesRegex(ValueError, "hallucination_rate"):
            self.make_simulator(hallucination_rate=1.1)
        with self.assertRaisesRegex(ValueError, "os_type"):
            self.make_simulator(os_type="Plan9")

    def test_one_iteration_starts_in_phase_one(self):
        messages = []
        simulator = self.make_simulator(log_callback=messages.append)

        simulator.run_simulation(1)

        output = "\n".join(messages)
        self.assertIn("Phase 1: Host Discovery", output)
        self.assertNotIn("Phase 2: Privilege", output)

    def test_three_iterations_cover_all_phases_and_export_current_layer(self):
        simulator = self.make_simulator()

        exported = simulator.run_simulation(3)

        self.assertEqual(exported, self.output_path)
        layer = json.loads(self.output_path.read_text(encoding="utf-8"))
        self.assertEqual(layer["versions"]["attack"], core.ATTACK_VERSION)
        self.assertEqual(layer["versions"]["navigator"], core.NAVIGATOR_VERSION)
        self.assertEqual(layer["versions"]["layer"], core.LAYER_VERSION)
        technique_ids = {item["techniqueID"] for item in layer["techniques"]}
        self.assertIn("T1526", technique_ids)
        self.assertEqual(len(technique_ids), 3)

    def test_subtechnique_id_is_preserved_in_layer(self):
        simulator = self.make_simulator()
        simulator.executed_tactics.add(
            "T1087.001 - Account Discovery: Local Account"
        )

        simulator._generate_attack_navigator_layer()

        layer = json.loads(self.output_path.read_text(encoding="utf-8"))
        self.assertEqual(layer["techniques"][0]["techniqueID"], "T1087.001")

    @mock.patch("core.subprocess.run")
    def test_dry_run_never_creates_a_process(self, run_mock):
        simulator = self.make_simulator(dry_run=True)

        simulator.run_simulation(3)

        run_mock.assert_not_called()

    @mock.patch("core.subprocess.run")
    def test_network_actions_are_skipped_without_opt_in(self, run_mock):
        run_mock.return_value = subprocess.CompletedProcess([], 0, "", "")
        messages = []
        simulator = self.make_simulator(
            dry_run=False,
            allow_network=False,
            log_callback=messages.append,
        )

        simulator.run_simulation(3)

        self.assertEqual(run_mock.call_count, 2)
        invoked = " ".join(
            " ".join(call.args[0]) for call in run_mock.call_args_list
        )
        self.assertNotRegex(invoked, r"\b(?:aws|az|gcloud)\b")
        self.assertTrue(any("SKIPPED NETWORK ACTION" in message for message in messages))

    def test_nested_posix_command_is_shell_quoted(self):
        simulator = self.make_simulator()

        command = simulator._build_command("bash", "printf '%s' safe", evade=True)

        self.assertEqual(command[:2], ["/bin/sh", "-c"])
        self.assertNotIn("exec /bin/bash", command[2])
        self.assertIn("'\"'\"'", command[2])

    def test_run_rejects_zero_iterations(self):
        simulator = self.make_simulator()
        with self.assertRaisesRegex(ValueError, "total_iterations"):
            simulator.run_simulation(0)

    def test_stop_callback_ends_run_and_exports_partial_layer(self):
        messages = []
        stop_callback = mock.Mock(side_effect=[False, True])
        simulator = self.make_simulator(
            stop_callback=stop_callback,
            log_callback=messages.append,
        )

        exported = simulator.run_simulation(5)

        self.assertEqual(exported, self.output_path)
        self.assertTrue(self.output_path.exists())
        self.assertTrue(any("STOP REQUESTED" in message for message in messages))

    @mock.patch("sys.stdout", new_callable=io.StringIO)
    def test_cli_lists_agentic_scenarios(self, stdout):
        result = core.main(["--list-scenarios"])

        self.assertEqual(result, 0)
        self.assertIn("indirect-prompt-injection", stdout.getvalue())
        self.assertIn("mcp-tool-poisoning", stdout.getvalue())

    @mock.patch("core.run_scenario_suite")
    def test_cli_dispatches_scenario_mode(self, run_suite):
        run_suite.return_value = mock.Mock(passed=True, stopped=False)

        result = core.main(
            [
                "--scenario",
                "decoy-secret-exfiltration",
                "--variant",
                "both",
                "--speed",
                "0",
                "--ground-truth-output",
                str(Path(self.temp_dir.name) / "events.jsonl"),
                "--validation-output",
                str(Path(self.temp_dir.name) / "validation.json"),
            ]
        )

        self.assertEqual(result, 0)
        run_suite.assert_called_once_with(
            "decoy-secret-exfiltration",
            variant="both",
            ground_truth_path=str(Path(self.temp_dir.name) / "events.jsonl"),
            validation_path=str(Path(self.temp_dir.name) / "validation.json"),
            speed_ms=0,
        )


if __name__ == "__main__":
    unittest.main()
