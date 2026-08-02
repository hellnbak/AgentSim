import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from agentsim.cli import main as cli_main
from agentsim.detection import evaluate_rule, parse_rule
from agentsim.lab import run_reference_fixture
from agentsim.models.agent_trace import AGENT_TRACE_SCHEMA_VERSION
from agentsim.models.telemetry import NormalizedEvent
from agentsim.telemetry import investigate_telemetry
from scenarios import SCENARIOS


def event(event_id, event_type, **fields):
    values = {"trace_id": "trace-graph", "agent_id": "orchestrator-agent"}
    values.update(fields)
    return NormalizedEvent(
        timestamp=f"2026-08-02T00:00:0{len(event_id)}Z",
        source="agent_runtime",
        event_type=event_type,
        fields=values,
        available_fields=tuple(sorted({"timestamp", "source", "event_type", *values})),
        collector="agent_runtime",
        synthetic=True,
        source_record_id=event_id,
        metadata={"redacted": True},
    )


class GraphDetectionTests(unittest.TestCase):
    def setUp(self):
        self.events = (
            event("e0", "agent.goal.integrity", goal_integrity_valid=False),
            event(
                "e1",
                "agent.memory.written",
                parent_event_id="e0",
                caused_by_event_ids=("e0",),
                agent_id="research-agent",
                memory_retention_valid=False,
                memory_provenance_valid=False,
            ),
            event(
                "e2",
                "agent.delegation.accepted",
                parent_event_id="e1",
                caused_by_event_ids=("e1",),
                agent_id="research-agent",
                identity_binding_valid=False,
            ),
            event(
                "e3",
                "agent.tool.requested",
                parent_event_id="e2",
                caused_by_event_ids=("e2",),
                agent_id="execution-agent",
                identity_binding_valid=False,
                tool_risk="high",
            ),
        )

    def test_graph_path_traverses_non_adjacent_causal_steps(self):
        rule = parse_rule(
            {
                "rule_id": "test.graph-path",
                "name": "Graph path",
                "severity": "critical",
                "group_by": ["trace_id"],
                "expression": {
                    "type": "graph_path",
                    "max_depth": 3,
                    "link_fields": ["parent_event_id", "caused_by_event_ids"],
                    "steps": [
                        {"type": "match", "predicates": [{"field": "goal_integrity_valid", "operator": "eq", "value": False}]},
                        {"type": "match", "predicates": [{"field": "memory_retention_valid", "operator": "eq", "value": False}]},
                        {"type": "match", "predicates": [{"field": "tool_risk", "operator": "eq", "value": "high"}]},
                    ],
                },
            }
        )
        result = evaluate_rule(rule, self.events)
        self.assertTrue(result.matched)
        self.assertEqual(result.matched_indices, (0, 1, 3))

    def test_graph_fanout_counts_distinct_descendant_agents(self):
        rule = parse_rule(
            {
                "rule_id": "test.graph-fanout",
                "name": "Graph fan-out",
                "severity": "critical",
                "group_by": ["trace_id"],
                "expression": {
                    "type": "graph_fanout",
                    "root": {"type": "match", "predicates": [{"field": "memory_provenance_valid", "operator": "eq", "value": False}]},
                    "descendant": {"type": "match", "predicates": [{"field": "identity_binding_valid", "operator": "eq", "value": False}]},
                    "count": 2,
                    "distinct_field": "agent_id",
                    "max_depth": 3,
                },
            }
        )
        result = evaluate_rule(rule, self.events)
        self.assertTrue(result.matched)
        self.assertEqual(result.matched_indices, (1, 2, 3))


class MultiAgentInvestigationTests(unittest.TestCase):
    def setUp(self):
        self.run = run_reference_fixture("multi-agent-delegation-cascade")
        self.events = tuple(item.to_normalized_event() for item in self.run.events)

    def test_malicious_trace_explains_invariants_and_benign_twin_is_clean(self):
        report = investigate_telemetry(self.events)
        codes = {item.code for item in report.findings}
        self.assertEqual(report.status, "critical")
        self.assertIn("delegation_identity_binding_failed", codes)
        self.assertIn("delegation_principal_drift", codes)
        self.assertIn("unapproved_goal_fingerprint_change", codes)
        self.assertIn("memory_retention_policy_failed", codes)
        self.assertTrue(report.paths)
        self.assertGreaterEqual(report.max_depth, 7)

        benign_trace = next(
            trace["trace_id"]
            for trace in report.traces
            if trace.get("variant") == "benign"
        )
        benign = investigate_telemetry(
            event for event in self.events if event.get("trace_id") == benign_trace
        )
        self.assertEqual(benign.status, "clean")
        self.assertEqual(benign.score, 100)
        self.assertFalse(benign.findings)

    def test_v14_scenarios_and_agent_contract_are_versioned(self):
        self.assertEqual(AGENT_TRACE_SCHEMA_VERSION, "1.1")
        for scenario_id in (
            "delegation-identity-drift",
            "shared-memory-retention-escape",
            "cross-agent-goal-fingerprint-drift",
            "multi-agent-trust-cascade",
        ):
            self.assertIn(scenario_id, SCENARIOS)
            self.assertEqual(SCENARIOS[scenario_id].pack_id, "agentsim.v14-multi-agent")

    def test_cli_writes_content_safe_investigation_report(self):
        with tempfile.TemporaryDirectory() as directory:
            events_path = Path(directory) / "events.json"
            report_path = Path(directory) / "investigation.json"
            events_path.write_text(
                json.dumps([item.to_dict() for item in self.run.events]),
                encoding="utf-8",
            )
            with redirect_stdout(io.StringIO()):
                code = cli_main(
                    [
                        "telemetry",
                        "investigate",
                        str(events_path),
                        "--collector",
                        "agent_runtime",
                        "--output",
                        str(report_path),
                        "--fail-on",
                        "never",
                    ]
                )
            self.assertEqual(code, 0)
            value = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(value["kind"], "multi-agent-investigation-report")
            self.assertFalse(value["content_values_recorded"])

    def test_investigation_schema_is_packaged_source_content(self):
        value = json.loads(
            Path("schemas/multi-agent-investigation-report.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(value["$schema"], "https://json-schema.org/draft/2020-12/schema")


if __name__ == "__main__":
    unittest.main()
