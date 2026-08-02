import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agentsim.cli import main as cli_main
from agentsim.content import load_ability_registry, load_campaign_registry
from agentsim.content.integrity import verify_integrity
from agentsim.defense import analyze_gaps, run_regression
from agentsim.detection import analyze_coverage, evaluate_rule, generate_candidate
from agentsim.detection.ast import (
    CausalGraphNode,
    DetectionRule,
    MatchNode,
    ParentChildNode,
    Predicate,
    SequenceNode,
    ThresholdNode,
    rule_to_dict,
)
from agentsim.detection.renderers import FORMATS, render_candidate, write_candidate_bundle
from agentsim.external import build_atomic_plan, build_caldera_plan, build_stratus_plan
from agentsim.lab import list_fixtures, run_lab_suite
from agentsim.plugins import discover_plugins
from agentsim.reporting.attack_flow import export_campaign, import_campaign
from agentsim.telemetry.collectors import collector_for
from agentsim.telemetry.correlation import correlate_lifecycle
from agentsim.telemetry.normalization import normalize_records


def match(field, value):
    return MatchNode((Predicate(field, "eq", value),))


class V1DetectionTests(unittest.TestCase):
    def setUp(self):
        self.abilities = load_ability_registry()

    def test_normalization_redacts_sensitive_values_and_preserves_field_inventory(self):
        event = normalize_records(
            [
                {
                    "@timestamp": "2026-08-02T00:00:00Z",
                    "event": {"action": "start"},
                    "process": {"name": "ps", "command_line": "ps aux"},
                    "host": {"id": "host-1"},
                    "authorization_token": "never-record-this",
                    "prompt": "never-record-this-either",
                }
            ],
            collector="otel",
        )[0]
        serialized = json.dumps(event.to_dict())
        self.assertEqual(event.get("process_name"), "ps")
        self.assertIn("process.name", event.available_fields)
        self.assertIn("process_name", event.available_fields)
        self.assertNotIn("authorization_token", serialized)
        self.assertNotIn("never-record", serialized)

    def test_collectors_accept_json_jsonl_and_nested_exports(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            jsonl = root / "events.jsonl"
            nested = root / "events.json"
            jsonl.write_text('{"source":"process_creation","process_name":"ps"}\n', encoding="utf-8")
            nested.write_text(json.dumps({"Records": [{"eventSource": "iam.amazonaws.com"}]}), encoding="utf-8")
            self.assertEqual(len(collector_for("jsonl").collect(jsonl)), 1)
            cloud = collector_for("cloudtrail").collect(nested)
            self.assertEqual(cloud[0].source, "iam.amazonaws.com")

    def test_lifecycle_correlation_respects_source_run_and_time_bounds(self):
        lifecycle = [
            {
                "run_id": "run-1",
                "action_id": "action-1",
                "ability_id": "endpoint.discovery.processes",
                "sequence": 1,
                "timestamp": "2026-01-01T00:00:00Z",
                "lifecycle_state": "planned",
                "expected_telemetry": ["process_creation"],
            },
            {
                "run_id": "run-1",
                "action_id": "action-1",
                "ability_id": "endpoint.discovery.processes",
                "sequence": 2,
                "timestamp": "2026-01-01T00:00:02Z",
                "lifecycle_state": "verified",
                "expected_telemetry": ["process_creation"],
            },
        ]
        telemetry = normalize_records(
            [
                {
                    "timestamp": "2026-01-01T00:00:01Z",
                    "source": "process_creation",
                    "run_id": "run-1",
                },
                {
                    "timestamp": "2026-01-01T00:00:01Z",
                    "source": "process_creation",
                    "run_id": "another-run",
                },
                {
                    "timestamp": "2026-01-01T01:00:00Z",
                    "source": "process_creation",
                    "run_id": "run-1",
                },
            ]
        )
        correlated = correlate_lifecycle(lifecycle, telemetry, tolerance_seconds=5)
        self.assertEqual(correlated[0].event_indexes, (0,))
        self.assertEqual(correlated[0].status, "verified")

    def test_sequence_is_ordered_time_bounded_and_group_scoped(self):
        rule = DetectionRule(
            "sequence",
            "Sequence",
            SequenceNode((match("event_type", "one"), match("event_type", "two")), 10),
            group_by=("host_id",),
        )
        cross_host = normalize_records(
            [
                {"timestamp": "2026-01-01T00:00:00Z", "event_type": "one", "host_id": "a"},
                {"timestamp": "2026-01-01T00:00:01Z", "event_type": "two", "host_id": "b"},
            ]
        )
        self.assertFalse(evaluate_rule(rule, cross_host).matched)
        same_host = normalize_records(
            [
                {"timestamp": "2026-01-01T00:00:00Z", "event_type": "one", "host_id": "a"},
                {"timestamp": "2026-01-01T00:00:01Z", "event_type": "two", "host_id": "a"},
            ]
        )
        self.assertEqual(evaluate_rule(rule, same_host).matched_indices, (0, 1))

    def test_threshold_distinct_parent_child_and_causal_graph(self):
        threshold = DetectionRule(
            "threshold",
            "Threshold",
            ThresholdNode(match("event_type", "tool"), 2, 60, "resource"),
        )
        distinct_events = normalize_records(
            [
                {"timestamp": "2026-01-01T00:00:00Z", "event_type": "tool", "resource": "a"},
                {"timestamp": "2026-01-01T00:00:01Z", "event_type": "tool", "resource": "b"},
            ]
        )
        self.assertTrue(evaluate_rule(threshold, distinct_events).matched)

        parent_child = DetectionRule(
            "lineage",
            "Lineage",
            ParentChildNode(match("process_name", "python"), match("process_name", "ps")),
        )
        process_events = normalize_records(
            [
                {"process_name": "python", "process_id": "100"},
                {"process_name": "ps", "parent_process_id": "100"},
            ]
        )
        self.assertEqual(evaluate_rule(parent_child, process_events).match_count, 2)

        causal = DetectionRule(
            "causal",
            "Causal",
            CausalGraphNode((match("event_type", "input"), match("event_type", "tool"))),
        )
        causal_events = normalize_records(
            [
                {"id": "root", "event_type": "input"},
                {"id": "child", "parent_event_id": "root", "event_type": "tool"},
            ]
        )
        self.assertEqual(evaluate_rule(causal, causal_events).matched_indices, (0, 1))

    def test_coverage_gap_generation_and_regression(self):
        ability = self.abilities["endpoint.discovery.processes"]
        complete = normalize_records(
            [
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "source": "process_creation",
                    "host_id": "host",
                    "process_name": "ps",
                    "command_line": "ps aux",
                    "parent_process_name": "python",
                    "parent_process_id": "100",
                },
                {
                    "timestamp": "2026-01-01T00:00:01Z",
                    "source": "process_creation",
                    "host_id": "host",
                    "process_name": "top",
                    "command_line": "top -bn 1",
                    "parent_process_name": "python",
                    "parent_process_id": "100",
                },
            ],
            synthetic=True,
        )
        coverage = analyze_coverage(ability, complete)
        self.assertEqual(coverage.coverage_percent, 100.0)
        self.assertEqual(analyze_gaps(self.abilities, (coverage,)), ())
        candidate = generate_candidate(ability)
        benign = normalize_records(
            [{"source": "process_creation", "host_id": "host", "process_name": "notepad"}]
        )
        regression = run_regression(candidate.rule, complete, benign)
        self.assertTrue(regression.passed)

    def test_candidate_renderers_are_marked_for_human_review(self):
        candidate = generate_candidate(self.abilities["endpoint.discovery.processes"])
        for format_name in FORMATS:
            rendered = render_candidate(candidate, format_name)
            self.assertTrue(rendered.strip())
            if format_name != "sigma":
                self.assertIn("HUMAN REVIEW", rendered)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = write_candidate_bundle(candidate, temp_dir)
            self.assertEqual(len(tuple(root.iterdir())), len(FORMATS) + 1)


class V1PlatformTests(unittest.TestCase):
    def setUp(self):
        self.abilities = load_ability_registry()
        self.campaigns = load_campaign_registry()

    def test_builtin_content_has_valid_trusted_signatures(self):
        for path, key in (
            (Path("agentsim/content/packs/endpoint_discovery.json"), "abilities"),
            (Path("agentsim/content/campaigns/foundation.json"), "campaigns"),
            (Path("agentsim/content/catalogs/endpoint_commands.json"), "commands"),
        ):
            value = json.loads(path.read_text(encoding="utf-8"))
            verify_integrity(value, key)
            tampered = copy.deepcopy(value)
            signature = tampered["integrity"]["signature"]["value"]
            tampered["integrity"]["signature"]["value"] = ("A" if signature[0] != "A" else "B") + signature[1:]
            with self.assertRaisesRegex(ValueError, "signature"):
                verify_integrity(tampered, key)

    def test_agentic_lab_covers_all_release_fixtures_without_execution(self):
        self.assertEqual(len(list_fixtures()), 10)
        results = run_lab_suite()
        self.assertTrue(all(result.passed for result in results))
        self.assertTrue(all(not result.safety["process_started"] for result in results))
        self.assertTrue(all(not result.safety["network_opened"] for result in results))

    def test_external_plans_are_version_pinned_audited_and_nonexecuting(self):
        atomic = build_atomic_plan(
            technique_id="T1057",
            test_guid="11111111-1111-4111-8111-111111111111",
            provider_version="2.2.0",
            target_uri="localhost://lab",
        ).to_dict()
        self.assertFalse(atomic["execution_supported_by_core"])
        self.assertEqual(len(atomic["plan_sha256"]), 64)
        stratus = build_stratus_plan(
            technique_id="aws.discovery.ec2-describe-instances",
            provider_version="2.17.0",
            target_uri="cloud://aws/security-sandbox",
        )
        self.assertEqual(stratus.phases[-1]["phase"], "cleanup")
        caldera = build_caldera_plan(
            adversary_id="reviewed-profile",
            provider_version="5.1.0",
            target_uri="lab-agent://purple-01",
            server_url="https://caldera.lab.example",
        )
        self.assertFalse(caldera.execution_supported_by_core)
        with self.assertRaises(ValueError):
            build_caldera_plan(
                adversary_id="reviewed-profile",
                provider_version="latest",
                target_uri="lab-agent://purple-01",
                server_url="https://user:secret@caldera.lab.example",
            )

    def test_attack_flow_round_trip_preserves_reviewed_campaign_graph(self):
        campaign = self.campaigns["endpoint-discovery-baseline"]
        bundle = export_campaign(campaign, self.abilities)
        restored = import_campaign(bundle, self.abilities)
        self.assertEqual(bundle["type"], "bundle")
        self.assertEqual(len(restored.campaign.steps), len(campaign.steps))
        self.assertEqual(restored.campaign.ability_ids, campaign.ability_ids)
        self.assertEqual(restored.warnings, ())

    def test_plugin_discovery_does_not_require_plugins(self):
        self.assertIsInstance(discover_plugins(), tuple)

    @mock.patch("sys.stdout", new_callable=io.StringIO)
    def test_v1_cli_ci_interfaces(self, stdout):
        self.assertEqual(cli_main(["lab", "list"]), 0)
        self.assertIn("indirect-prompt-injection", stdout.getvalue())
        stdout.seek(0)
        stdout.truncate(0)
        self.assertEqual(cli_main(["external", "list"]), 0)
        self.assertIn("atomic-red-team", stdout.getvalue())

    @mock.patch("sys.stdout", new_callable=io.StringIO)
    def test_detection_cli_returns_useful_exit_codes(self, stdout):
        candidate = generate_candidate(self.abilities["endpoint.discovery.processes"])
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            rule_path = root / "rule.json"
            events_path = root / "events.jsonl"
            rule_path.write_text(json.dumps(rule_to_dict(candidate.rule)), encoding="utf-8")
            events_path.write_text(
                "\n".join(
                    json.dumps(event)
                    for event in (
                        {"source": "process_creation", "host_id": "h", "user_id": "u", "process_name": "ps"},
                        {"source": "process_creation", "host_id": "h", "user_id": "u", "process_name": "top"},
                    )
                ),
                encoding="utf-8",
            )
            self.assertEqual(cli_main(["detection", "evaluate", str(rule_path), str(events_path)]), 0)
            self.assertIn('"matched": true', stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
