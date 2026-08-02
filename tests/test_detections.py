import importlib.util
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PANTHER_RULE_PATH = (
    PROJECT_ROOT / "detections" / "panther" / "agent_discovery_burst.py"
)
PANTHER_AGENT_RULE_PATH = (
    PROJECT_ROOT / "detections" / "panther" / "agentic_attack_lineage.py"
)
PANTHER_CONTROL_RULE_PATH = (
    PROJECT_ROOT / "detections" / "panther" / "agentic_control_plane_abuse.py"
)


def _load_panther_rule():
    spec = importlib.util.spec_from_file_location("agent_discovery_burst", PANTHER_RULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_panther_agent_rule():
    spec = importlib.util.spec_from_file_location(
        "agentic_attack_lineage", PANTHER_AGENT_RULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_panther_control_rule():
    spec = importlib.util.spec_from_file_location(
        "agentic_control_plane_abuse", PANTHER_CONTROL_RULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DetectionContentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.panther_rule = _load_panther_rule()
        cls.panther_agent_rule = _load_panther_agent_rule()
        cls.panther_control_rule = _load_panther_control_rule()

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

    def test_agentic_panther_rule_has_label_independent_correlation_primitives(self):
        origin = {
            "event_type": "agent.memory.retrieved",
            "trace_id": "trace-1",
            "data_lineage_id": "lineage-1",
            "input_trust": "untrusted",
            "taint_labels": ["untrusted_instruction"],
        }
        action = {
            "event_type": "agent.tool.requested",
            "trace_id": "trace-1",
            "data_lineage_id": "lineage-1",
            "tool_risk": "high",
            "expected_detection": False,
        }
        benign = {
            "event_type": "agent.tool.requested",
            "input_trust": "trusted",
            "tool_risk": "low",
        }

        self.assertTrue(self.panther_agent_rule.rule(origin))
        self.assertTrue(self.panther_agent_rule.rule(action))
        self.assertFalse(self.panther_agent_rule.rule(benign))
        self.assertEqual(self.panther_agent_rule.unique(origin), "untrusted_origin")
        self.assertEqual(self.panther_agent_rule.unique(action), "risky_action")
        self.assertEqual(
            self.panther_agent_rule.dedup(origin), "trace-1:lineage-1"
        )

    def test_agent_event_vendor_queries_do_not_use_ground_truth_labels(self):
        paths = [
            PROJECT_ROOT / "detections" / "kql" / "agentic_attack_correlations.kql",
            PROJECT_ROOT / "detections" / "splunk" / "agentic_attack_correlations.spl",
            PROJECT_ROOT / "detections" / "crowdstrike" / "agentic_attack_correlations.cql",
            PROJECT_ROOT / "detections" / "graylog" / "agentic_attack_correlations.query",
            PROJECT_ROOT / "detections" / "elastic" / "agentic_attack_lineage.eql",
        ]
        for path in paths:
            with self.subTest(path=path):
                content = path.read_text(encoding="utf-8")
                executable_lines = "\n".join(
                    line for line in content.splitlines() if not line.lstrip().startswith(("//", "#", "/*", "*"))
                )
                self.assertNotIn("expected_detection", executable_lines)
                self.assertNotIn("scenario_variant", executable_lines)
                self.assertIn("trace_id", content)

    def test_control_plane_panther_rule_covers_emerging_scenarios(self):
        cases = (
            (
                "model_safety_downgrade",
                {
                    "event_type": "agent.model.fallback",
                    "attributes": {
                        "safety_profile_changed": True,
                        "policy_binding_valid": False,
                    },
                },
            ),
            (
                "planner_executor_policy_gap",
                {
                    "event_type": "agent.policy.decision",
                    "policy_decision": "allow",
                    "attributes": {
                        "policy_scope": "executor",
                        "intent_equivalent": True,
                        "policy_version_match": False,
                    },
                },
            ),
            (
                "approval_replay",
                {
                    "event_type": "agent.approval.reused",
                    "attributes": {"action_fingerprint_match": False},
                },
            ),
            (
                "cross_tenant_context_confusion",
                {
                    "event_type": "agent.authorization.context_changed",
                    "attributes": {
                        "tenant_changed": True,
                        "tenant_binding_valid": False,
                    },
                },
            ),
            (
                "tool_chain_capability_escalation",
                {
                    "event_type": "agent.tool.requested",
                    "attributes": {"egress_capable": True, "composite_risk": "high"},
                },
            ),
            (
                "agent_registry_poisoning",
                {
                    "event_type": "agent.registry.entry.changed",
                    "attributes": {
                        "capability_expansion": True,
                        "signature_valid": False,
                    },
                },
            ),
        )

        for expected, event in cases:
            with self.subTest(expected=expected):
                self.assertTrue(self.panther_control_rule.rule(event))
                self.assertEqual(self.panther_control_rule.signal_type(event), expected)

        self.assertFalse(
            self.panther_control_rule.rule(
                {
                    "event_type": "agent.model.fallback",
                    "attributes": {
                        "safety_profile_changed": False,
                        "policy_binding_valid": True,
                    },
                }
            )
        )

    def test_control_plane_queries_avoid_answer_key_fields(self):
        paths = [
            PROJECT_ROOT / "detections" / "kql" / "agentic_control_plane_abuse.kql",
            PROJECT_ROOT / "detections" / "splunk" / "agentic_control_plane_abuse.spl",
            PROJECT_ROOT / "detections" / "crowdstrike" / "agentic_control_plane_abuse.cql",
            PROJECT_ROOT / "detections" / "graylog" / "agentic_control_plane_abuse.query",
            PROJECT_ROOT / "detections" / "elastic" / "agentic_control_plane_abuse.eql",
        ]
        for path in paths:
            with self.subTest(path=path):
                content = path.read_text(encoding="utf-8")
                self.assertNotIn("expected_detection", content)
                self.assertNotIn("scenario_variant", content)
                self.assertIn("trace_id", content)


if __name__ == "__main__":
    unittest.main()
