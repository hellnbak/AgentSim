import importlib.util
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PANTHER_RULE_PATH = (
    PROJECT_ROOT / "detections" / "panther" / "agent_discovery_burst.py"
)


def _load_panther_rule():
    spec = importlib.util.spec_from_file_location("agent_discovery_burst", PANTHER_RULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DetectionContentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.panther_rule = _load_panther_rule()

    def test_panther_rule_matches_python_discovery_process(self):
        event = {
            "aid": "endpoint-123",
            "ComputerName": "lab-host",
            "ParentBaseFileName": "python3",
            "ParentProcessId": "4100",
            "CommandLine": "/bin/bash -c uname -a",
        }

        self.assertTrue(self.panther_rule.rule(event))
        self.assertEqual(self.panther_rule.unique(event), "system")
        self.assertEqual(self.panther_rule.dedup(event), "endpoint-123:4100")

    def test_panther_rule_rejects_non_python_parent(self):
        event = {
            "ParentBaseFileName": "terminal",
            "CommandLine": "/bin/bash -c uname -a",
        }

        self.assertFalse(self.panther_rule.rule(event))

    def test_panther_rule_tracks_separate_discovery_families(self):
        commands = {
            "account": "cmd.exe /c whoami",
            "process": "/bin/bash -c ps aux",
            "connections": "/bin/bash -c netstat -anv",
            "cloud": "cmd.exe /c aws ec2 describe-regions",
        }

        for expected_family, command_line in commands.items():
            with self.subTest(expected_family=expected_family):
                self.assertEqual(
                    self.panther_rule.unique({"CommandLine": command_line}),
                    expected_family,
                )

    def test_vendor_detection_files_include_threshold_and_native_fields(self):
        crowdstrike = (
            PROJECT_ROOT
            / "detections"
            / "crowdstrike"
            / "agent_discovery_burst.cql"
        ).read_text(encoding="utf-8")
        graylog = (
            PROJECT_ROOT / "detections" / "graylog" / "agent_discovery_burst.query"
        ).read_text(encoding="utf-8")
        panther = (
            PROJECT_ROOT / "detections" / "panther" / "agent_discovery_burst.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("#event_simpleName=ProcessRollup2", crowdstrike)
        self.assertIn("DistinctDiscoveryCommands >= 4", crowdstrike)
        self.assertIn('gim_event_type:"process started"', graylog)
        self.assertIn("process_parent_name", graylog)
        self.assertIn("Threshold: 4", panther)
        self.assertIn("Crowdstrike.CrowdstrikeProcessRollup2", panther)


if __name__ == "__main__":
    unittest.main()
