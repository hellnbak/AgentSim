import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing, redirect_stdout
from dataclasses import replace
from pathlib import Path

from agentsim.cli import main as cli_main
from agentsim.content import load_ability_registry
from agentsim.detection import evaluate_live_ability
from agentsim.lab import list_fixtures, run_lab_suite, run_reference_fixture, run_reference_suite
from agentsim.lab.server import serve_reference_lab
from agentsim.models.agent_trace import agent_trace_from_mapping
from agentsim.storage import RunStore
from agentsim.telemetry.agent_contract import agent_trace_from_record, normalize_agent_records
from agentsim.telemetry.connectors import (
    CONNECTOR_NAMES,
    QuerySpec,
    build_query_plan,
    execute_query_plan,
)
from scenarios import SCENARIOS


class FakeTransport:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def request(self, method, url, headers, body):
        self.requests.append((method, url, dict(headers), body))
        if not self.responses:
            raise AssertionError("unexpected connector request")
        value = self.responses.pop(0)
        return value if isinstance(value, bytes) else json.dumps(value).encode("utf-8")


def query_spec(connector):
    datasets = {
        "splunk": "main",
        "elastic": "logs-endpoint.events.process-default",
        "crowdstrike": "falcon-events",
        "sentinel": "00000000-0000-4000-8000-000000000000:SecurityEvent",
        "panther": "panther_logs.public.synthetic_events",
        "graylog": "000000000000000000000001",
    }
    return QuerySpec(
        connector=connector,
        base_url="https://siem.example.test",
        dataset=datasets[connector],
        target="host-1",
        since="2026-08-02T00:00:00Z",
        until="2026-08-02T00:05:00Z",
        limit=25,
    )


class AgentTelemetryContractTests(unittest.TestCase):
    def test_agent_contract_redacts_content_and_preserves_security_context(self):
        event = agent_trace_from_record(
            {
                "timestamp": "2026-08-02T00:00:00Z",
                "event_id": "event-1",
                "event_type": "agent.tool.requested",
                "trace_id": "trace-1",
                "session_id": "session-1",
                "agent_id": "agent-1",
                "attributes": {
                    "prompt": "do not retain",
                    "gen_ai.tool.call.arguments": {"password": "do not retain"},
                    "token": "do not retain",
                    "token_audience": "mcp-server",
                    "audience_valid": False,
                    "policy_decision": "deny",
                },
            }
        )
        serialized = json.dumps(event.to_dict())
        self.assertNotIn("do not retain", serialized)
        self.assertNotIn('"token"', serialized)
        self.assertEqual(event.attributes["token_audience"], "mcp-server")
        self.assertFalse(event.content_recorded)

    def test_otel_genai_profile_normalizes_ids_usage_and_tool_without_content(self):
        events = normalize_agent_records(
            [
                {
                    "timeUnixNano": 1785638400000000000,
                    "span_id": "span-1",
                    "trace_id": "trace-1",
                    "attributes": {
                        "gen_ai.operation.name": "execute_tool",
                        "gen_ai.conversation.id": "conversation-1",
                        "gen_ai.agent.id": "agent-1",
                        "gen_ai.tool.call.id": "call-1",
                        "gen_ai.tool.name": "synthetic.search",
                        "gen_ai.usage.input_tokens": 12,
                        "gen_ai.usage.output_tokens": 4,
                        "gen_ai.tool.call.arguments": "sensitive content",
                    },
                }
            ],
            collector="otel_genai",
        )
        self.assertEqual(events[0].event_type, "gen_ai.execute_tool")
        self.assertEqual(events[0].get("tool_name"), "synthetic.search")
        self.assertEqual(events[0].get("attributes.input_token_count"), 12)
        self.assertNotIn("sensitive content", json.dumps(events[0].to_dict()))

    def test_canonical_mapping_rejects_content_recording(self):
        with self.assertRaisesRegex(ValueError, "content_recorded"):
            agent_trace_from_mapping(
                {
                    "timestamp": "2026-08-02T00:00:00Z",
                    "event_id": "event",
                    "event_type": "agent.observed",
                    "trace_id": "trace",
                    "session_id": "session",
                    "agent_id": "agent",
                    "content_recorded": True,
                }
            )

    def test_agent_contract_bounds_optional_ids_lists_and_attributes(self):
        base = {
            "timestamp": "2026-08-02T00:00:00Z",
            "event_id": "event",
            "event_type": "agent.observed",
            "trace_id": "trace",
            "session_id": "session",
            "agent_id": "agent",
        }
        with self.assertRaisesRegex(ValueError, "tool_name"):
            agent_trace_from_mapping({**base, "tool_name": "x" * 513})
        with self.assertRaisesRegex(ValueError, "auth_scopes"):
            agent_trace_from_mapping({**base, "auth_scopes": ["scope"] * 51})
        with self.assertRaisesRegex(ValueError, "attributes"):
            agent_trace_from_mapping({**base, "attributes": []})


class LiveConnectorTests(unittest.TestCase):
    def test_all_connectors_build_secret_free_exact_target_plans(self):
        self.assertEqual(len(CONNECTOR_NAMES), 6)
        for connector in CONNECTOR_NAMES:
            plan = build_query_plan(query_spec(connector))
            value = plan.to_dict()
            serialized = json.dumps(value)
            self.assertEqual(len(value["query_sha256"]), 64)
            self.assertFalse(value["credential_value_recorded"])
            self.assertNotIn("Authorization", serialized)
            self.assertEqual(value["target"], "host-1")

    def test_query_scope_rejects_wildcards_insecure_origins_and_large_windows(self):
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            QuerySpec("elastic", "http://siem.example.test", "logs", "host", "2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z")
        with self.assertRaisesRegex(ValueError, "specific"):
            QuerySpec("elastic", "https://siem.example.test", "logs", "*", "2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z")
        with self.assertRaisesRegex(ValueError, "24 hours"):
            QuerySpec("elastic", "https://siem.example.test", "logs", "host", "2026-01-01T00:00:00Z", "2026-01-03T00:00:00Z")
        with self.assertRaisesRegex(ValueError, "origin"):
            QuerySpec("elastic", "https://siem.example.test/proxy", "logs", "host", "2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z")

    def test_forged_or_mutated_query_plan_never_reaches_transport(self):
        plan = build_query_plan(query_spec("elastic"))
        transport = FakeTransport({"hits": {"hits": []}})
        forged = replace(plan, url="https://siem.example.test/_security/api_key")
        with self.assertRaisesRegex(ValueError, "endpoint"):
            execute_query_plan(
                forged,
                allow_network=True,
                transport=transport,
                environ={"AGENTSIM_ELASTIC_API_KEY": "test-only"},
            )
        self.assertEqual(transport.requests, [])

    def test_elastic_execution_is_double_opt_in_normalized_and_detectable(self):
        plan = build_query_plan(query_spec("elastic"))
        response = {
            "hits": {
                "hits": [
                    {"_id": "1", "_source": {"@timestamp": "2026-08-02T00:00:01Z", "event": {"dataset": "process_creation"}, "host": {"id": "host-1"}, "process": {"name": "ps"}}},
                    {"_id": "2", "_source": {"@timestamp": "2026-08-02T00:00:02Z", "event": {"dataset": "process_creation"}, "host": {"id": "host-1"}, "process": {"name": "top"}}},
                ]
            }
        }
        transport = FakeTransport(response)
        with self.assertRaisesRegex(PermissionError, "allow_network"):
            execute_query_plan(plan, transport=transport, environ={"AGENTSIM_ELASTIC_API_KEY": "test"})
        result = execute_query_plan(
            plan,
            allow_network=True,
            transport=transport,
            environ={"AGENTSIM_ELASTIC_API_KEY": "test-only-key"},
        )
        self.assertEqual(len(result.events), 2)
        self.assertIn("ApiKey test-only-key", transport.requests[0][2]["Authorization"])
        self.assertNotIn("test-only-key", json.dumps(result.to_dict(include_events=True)))
        ability = load_ability_registry()["endpoint.discovery.processes"]
        self.assertEqual(evaluate_live_ability(ability, result.events).status, "detected")

    def test_panther_async_query_is_polled_without_recording_api_key(self):
        plan = build_query_plan(query_spec("panther"))
        transport = FakeTransport(
            {"data": {"executeDataLakeQuery": {"id": "query-1"}}},
            {"data": {"dataLakeQuery": {"status": "running", "message": "running", "results": None}}},
            {"data": {"dataLakeQuery": {"status": "succeeded", "message": "done", "results": {"edges": [{"node": json.dumps({"p_event_time": "2026-08-02T00:00:01Z", "p_log_type": "process_creation", "host_id": "host-1"})}], "pageInfo": {"hasNextPage": False, "endCursor": None}}}}},
        )
        result = execute_query_plan(
            plan,
            allow_network=True,
            transport=transport,
            environ={"AGENTSIM_PANTHER_API_KEY": "panther-test-key"},
            sleeper=lambda _seconds: None,
        )
        self.assertEqual(result.provider_query_id, "query-1")
        self.assertEqual(result.request_count, 3)
        self.assertEqual(len(result.events), 1)
        self.assertNotIn("panther-test-key", json.dumps(result.to_dict()))

    def test_splunk_sentinel_logscale_and_graylog_responses_normalize(self):
        responses = {
            "splunk": b'{"result":{"_time":"2026-08-02T00:00:01Z","sourcetype":"process_creation","host":"host-1"}}\n',
            "sentinel": {
                "tables": [{
                    "columns": [{"name": "TimeGenerated"}, {"name": "Type"}, {"name": "Computer"}],
                    "rows": [["2026-08-02T00:00:01Z", "process_creation", "host-1"]],
                }]
            },
            "crowdstrike": {"events": [{"timestamp": "2026-08-02T00:00:01Z", "event_platform": "process_creation", "aid": "host-1"}]},
            "graylog": {"messages": [{"message": {"timestamp": "2026-08-02T00:00:01Z", "source": "host-1", "event_type": "process_creation"}}]},
        }
        for connector, response in responses.items():
            with self.subTest(connector=connector):
                environment = {
                    build_query_plan(query_spec(connector)).credential_env: "test-only"
                }
                result = execute_query_plan(
                    build_query_plan(query_spec(connector)),
                    allow_network=True,
                    transport=FakeTransport(response),
                    environ=environment,
                )
                self.assertEqual(len(result.events), 1)
                self.assertNotIn("test-only", json.dumps(result.to_dict(include_events=True)))

    def test_query_audit_persists_without_secrets(self):
        plan = build_query_plan(query_spec("elastic"))
        result = execute_query_plan(
            plan,
            allow_network=True,
            transport=FakeTransport({"hits": {"hits": []}}),
            environ={"AGENTSIM_ELASTIC_API_KEY": "not-persisted"},
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            store = RunStore(Path(temp_dir) / "runs.sqlite3")
            store.record_telemetry_query("query-1", result.to_dict())
            history = store.telemetry_query_history()
            self.assertEqual(history[0]["query_id"], "query-1")
            self.assertNotIn("not-persisted", json.dumps(history))

    def test_run_store_closes_each_sqlite_connection(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = RunStore(Path(temp_dir) / "runs.sqlite3")
            with store._connect() as connection:
                connection.execute("SELECT 1").fetchone()
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute("SELECT 1").fetchone()

    def test_query_history_schema_migrates_existing_v1_database(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "runs.sqlite3"
            with closing(sqlite3.connect(database)) as connection, connection:
                connection.execute(
                    """
                    CREATE TABLE telemetry_queries (
                        query_id TEXT PRIMARY KEY, connector TEXT NOT NULL,
                        dataset TEXT NOT NULL, target TEXT NOT NULL, since TEXT NOT NULL,
                        until TEXT NOT NULL, status TEXT NOT NULL, query_sha256 TEXT NOT NULL,
                        event_count INTEGER NOT NULL, audit_json TEXT NOT NULL
                    )
                    """
                )
            RunStore(database)
            with closing(sqlite3.connect(database)) as connection:
                columns = {row[1] for row in connection.execute("PRAGMA table_info(telemetry_queries)")}
            self.assertIn("run_id", columns)

    def test_cli_query_defaults_to_nonexecuting_plan(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = cli_main(
                [
                    "telemetry", "query", "elastic",
                    "--base-url", "https://siem.example.test",
                    "--dataset", "endpoint-events",
                    "--target", "host-1",
                    "--since", "2026-08-02T00:00:00Z",
                    "--until", "2026-08-02T00:05:00Z",
                ]
            )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["network_execution"], "disabled_until_explicit_execute_and_allow_network")


class ReferenceAgentLabTests(unittest.TestCase):
    def test_v12_doubles_control_fixtures_and_all_pairs_pass(self):
        self.assertEqual(len(list_fixtures()), 23)
        results = run_lab_suite()
        self.assertTrue(all(result.passed for result in results))
        self.assertTrue(all(not result.safety["network_opened"] for result in results))

    def test_reference_agent_emits_causal_contract_and_resets_state(self):
        result = run_reference_fixture("tool-definition-poisoning")
        self.assertTrue(result.passed)
        self.assertTrue(result.reset_verified)
        self.assertEqual(len(result.events), 6)
        self.assertEqual(len(result.synthetic_effects), 1)
        self.assertTrue(all(not event.content_recorded for event in result.events))
        self.assertTrue(all(event.synthetic for event in result.events))
        self.assertFalse(result.safety["process_started"])
        self.assertFalse(result.safety["network_opened"])
        self.assertFalse(result.safety["external_tool_executed"])

    def test_reference_suite_and_v12_scenarios_cover_release_scope(self):
        self.assertEqual(len(run_reference_suite()), 23)
        self.assertEqual(len(SCENARIOS), 41)
        self.assertIn("cross-turn-goal-hijack", SCENARIOS)
        self.assertIn("agent-task-id-replay", SCENARIOS)

    def test_reference_server_is_fail_closed_without_explicit_opt_in(self):
        with self.assertRaisesRegex(PermissionError, "explicit loopback opt-in"):
            serve_reference_lab("127.0.0.1", 8765)

    def test_container_definition_is_hardened_and_loopback_only(self):
        compose = Path("labs/reference-agent/compose.yaml").read_text(encoding="utf-8")
        dockerfile = Path("labs/reference-agent/Dockerfile").read_text(encoding="utf-8")
        for value in (
            "read_only: true",
            "cap_drop:",
            "no-new-privileges:true",
            'com.docker.network.bridge.host_binding_ipv4: "127.0.0.1"',
            "127.0.0.1:8765:8765",
            "pids_limit: 64",
            "mem_limit: 256m",
            "cpus: 0.50",
        ):
            self.assertIn(value, compose)
        self.assertNotIn("0.0.0.0:8765", compose)
        self.assertIn("USER 65532:65532", dockerfile)
        self.assertNotIn("pip install", dockerfile)

    def test_reference_cli_runs_one_fixture(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = cli_main(["lab", "reference", "goal-hijack"])
        value = json.loads(output.getvalue())
        self.assertEqual(code, 0)
        self.assertTrue(value["passed"])
        self.assertEqual(value["fixture_count"], 1)

    def test_v12_public_schemas_are_valid_json_and_packaged(self):
        schema_names = {
            "agent-trace-event.schema.json",
            "live-query-plan.schema.json",
            "reference-lab-result.schema.json",
        }
        for name in schema_names:
            value = json.loads((Path("schemas") / name).read_text(encoding="utf-8"))
            self.assertEqual(value["$schema"], "https://json-schema.org/draft/2020-12/schema")
        pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
        setup = Path("setup.py").read_text(encoding="utf-8")
        for name in schema_names:
            self.assertIn(name, pyproject)
            self.assertIn(name, setup)


if __name__ == "__main__":
    unittest.main()
