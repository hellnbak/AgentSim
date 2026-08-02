import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    import web_ui
except ModuleNotFoundError as exc:
    if exc.name != "flask":
        raise
    web_ui = None


@unittest.skipIf(web_ui is None, "Flask is not installed")
class WebUiTests(unittest.TestCase):
    def setUp(self):
        web_ui.app.config.update(TESTING=True)
        self.client = web_ui.app.test_client()
        self.original_layer_path = web_ui.LAYER_OUTPUT_PATH
        self.original_ground_truth_path = web_ui.GROUND_TRUTH_OUTPUT_PATH
        self.original_validation_path = web_ui.VALIDATION_OUTPUT_PATH
        self.original_junit_path = web_ui.JUNIT_OUTPUT_PATH
        self.original_sarif_path = web_ui.SARIF_OUTPUT_PATH
        self.original_otel_path = web_ui.OTEL_OUTPUT_PATH
        self.original_coverage_path = web_ui.COVERAGE_OUTPUT_PATH
        self.original_bundle_path = web_ui.BUNDLE_OUTPUT_PATH
        self.original_campaign_database_path = web_ui.CAMPAIGN_DATABASE_PATH
        self.original_campaign_output_directory = web_ui.CAMPAIGN_OUTPUT_DIRECTORY
        self.campaign_temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.campaign_temp_dir.cleanup)
        campaign_root = Path(self.campaign_temp_dir.name)
        web_ui.CAMPAIGN_DATABASE_PATH = campaign_root / "runs.db"
        web_ui.CAMPAIGN_OUTPUT_DIRECTORY = campaign_root / "campaign-runs"
        with web_ui.state_lock:
            web_ui.is_running = False
            web_ui.log_queue.clear()
            web_ui.event_sequence = 0
            web_ui.last_layer_path = None
            web_ui.last_ground_truth_path = None
            web_ui.last_validation_path = None
            web_ui.last_bundle_path = None
            web_ui.last_benchmark_metrics = {}
            web_ui.run_started_at = None
            web_ui.run_finished_at = None
            web_ui.current_params = {}
            web_ui.last_outcome = "ready"
            web_ui.stop_event.clear()

    def tearDown(self):
        web_ui.LAYER_OUTPUT_PATH = self.original_layer_path
        web_ui.GROUND_TRUTH_OUTPUT_PATH = self.original_ground_truth_path
        web_ui.VALIDATION_OUTPUT_PATH = self.original_validation_path
        web_ui.JUNIT_OUTPUT_PATH = self.original_junit_path
        web_ui.SARIF_OUTPUT_PATH = self.original_sarif_path
        web_ui.OTEL_OUTPUT_PATH = self.original_otel_path
        web_ui.COVERAGE_OUTPUT_PATH = self.original_coverage_path
        web_ui.BUNDLE_OUTPUT_PATH = self.original_bundle_path
        web_ui.CAMPAIGN_DATABASE_PATH = self.original_campaign_database_path
        web_ui.CAMPAIGN_OUTPUT_DIRECTORY = self.original_campaign_output_directory

    def valid_form(self):
        return {
            "form_token": web_ui.form_token,
            "run_mode": "behavior",
            "iterations": "3",
            "speed": "0",
            "hallucination_rate": "0.15",
            "context_loss_rate": "0.05",
            "retry_rate": "0.30",
            "evasion_rate": "0.10",
            "seed": "42",
            "dry_run": "on",
        }

    def test_index_has_security_headers_and_safe_structured_rendering(self):
        response = self.client.get("/")
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(
            response.headers["Permissions-Policy"],
            "camera=(), microphone=(), geolocation=()",
        )
        self.assertIn("Detection-First Adversary Emulation", page)
        self.assertIn("Authorized campaign foundation", page)
        self.assertIn("Validate visibility and agent safeguards", page)
        self.assertIn("endpoint-discovery-baseline", page)
        self.assertIn("Detection debugger", page)
        self.assertIn("Check telemetry assurance", page)
        self.assertIn("Agentic attack scenarios", page)
        self.assertIn("Indirect prompt injection", page)
        self.assertIn("message.textContent", page)
        self.assertNotIn(".innerHTML", page)

    def test_foundation_catalog_and_safe_campaign_api(self):
        catalog_response = self.client.get("/api/v1/catalog")
        self.assertEqual(catalog_response.status_code, 200)
        catalog = catalog_response.get_json()
        self.assertEqual(catalog["version"], "1.3.0")
        self.assertEqual(len(catalog["abilities"]), 8)
        self.assertEqual(len(catalog["campaigns"]), 2)
        self.assertEqual(catalog["capabilities"]["agentic_fixtures"], 20)
        self.assertTrue(catalog["capabilities"]["signed_builtin_content"])
        self.assertEqual(catalog["history"], [])

        denied = self.client.post(
            "/api/v0.4/campaign/simulate",
            json={"campaign_id": "endpoint-discovery-baseline"},
        )
        self.assertEqual(denied.status_code, 400)

        response = self.client.post(
            "/api/v0.4/campaign/simulate",
            json={"campaign_id": "endpoint-discovery-baseline"},
            headers={"X-AgentSim-Form-Token": web_ui.form_token},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["status"], "completed")
        self.assertEqual(payload["summary"]["verified_actions"], 7)
        self.assertEqual(payload["summary"]["executed_actions"], 0)
        self.assertTrue(payload["events"])
        self.assertTrue(all(event["schema_version"] == "3.0" for event in payload["events"]))
        self.assertEqual(payload["history"][0]["run_id"], payload["run_id"])
        self.assertTrue(web_ui.CAMPAIGN_DATABASE_PATH.exists())
        self.assertEqual(len(list(web_ui.CAMPAIGN_OUTPUT_DIRECTORY.glob("*/evidence.zip"))), 1)

    def test_v1_detection_and_agentic_lab_apis_are_synthetic(self):
        headers = {"X-AgentSim-Form-Token": web_ui.form_token}
        detection = self.client.post(
            "/api/v1/detection/demo",
            json={"ability_id": "endpoint.discovery.processes"},
            headers=headers,
        )
        self.assertEqual(detection.status_code, 200)
        value = detection.get_json()
        self.assertTrue(value["evaluation"]["matched"])
        self.assertEqual(value["coverage"]["coverage_percent"], 100.0)
        self.assertFalse(value["process_started"])
        self.assertFalse(value["network_opened"])

        lab = self.client.post(
            "/api/v1/lab/run", json={"fixture_id": "all"}, headers=headers
        )
        self.assertEqual(lab.status_code, 200)
        lab_value = lab.get_json()
        self.assertTrue(lab_value["passed"])
        self.assertEqual(len(lab_value["results"]), 20)
        self.assertTrue(
            all(not result["safety"]["tool_executed"] for result in lab_value["results"])
        )

        assurance = self.client.post(
            "/api/v1/telemetry/assurance",
            json={"corpus": "reference-agent"},
            headers=headers,
        )
        self.assertEqual(assurance.status_code, 200)
        assurance_value = assurance.get_json()
        self.assertEqual(assurance_value["assurance"]["status"], "healthy")
        self.assertEqual(assurance_value["assurance"]["score"], 100)
        self.assertEqual(assurance_value["sweep"]["summary"]["detected"], 7)
        self.assertEqual(assurance_value["sweep"]["summary"]["visibility_gap"], 0)
        self.assertFalse(assurance_value["sweep"]["ground_truth_used"])

    def test_classifies_command_cycle_and_anomaly_events(self):
        command = web_ui._classify_message("[*] EXECUTING: whoami (bash)")
        cycle = web_ui._classify_message(
            "--- Agent Cycle 4 (Phase 2: Privilege and Network Discovery) ---"
        )
        anomaly = web_ui._classify_message(
            "[!] HALLUCINATION: ipconfig /all (bash)"
        )

        self.assertEqual(command["kind"], "command")
        self.assertEqual(command["command"], "whoami")
        self.assertEqual(cycle["cycle"], 4)
        self.assertEqual(cycle["phase"], "Phase 2: Privilege and Network Discovery")
        self.assertEqual(anomaly["category"], "anomaly")

    def test_classifies_agentic_tool_and_policy_checkpoints(self):
        tool = web_ui._classify_message(
            "    [pre_tool] Agent proposes reading a decoy credential fixture."
        )
        blocked = web_ui._classify_message(
            "    [policy] Policy blocked the sensitive tool request."
        )

        self.assertEqual(tool["kind"], "tool")
        self.assertEqual(tool["category"], "anomaly")
        self.assertEqual(tool["stage"], "pre_tool")
        self.assertEqual(blocked["kind"], "blocked")
        self.assertEqual(blocked["category"], "anomaly")

        delegation = web_ui._classify_message(
            "    [delegation] Agent accepted a spoofed recursive delegation."
        )
        self.assertEqual(delegation["kind"], "tool")
        self.assertEqual(delegation["category"], "anomaly")

    def test_status_reports_host_and_run_state(self):
        with web_ui.state_lock:
            web_ui.current_params = {"iterations": 12, "dry_run": True}
            web_ui.run_started_at = 123.0

        response = self.client.get("/api/status")
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertIn(payload["os"], {"Windows", "Linux", "macOS", "Unknown"})
        self.assertFalse(payload["running"])
        self.assertEqual(payload["params"]["iterations"], 12)
        self.assertEqual(payload["started_at"], 123.0)

    def test_start_rejects_missing_form_token(self):
        form = self.valid_form()
        del form["form_token"]

        response = self.client.post("/start", data=form)

        self.assertEqual(response.status_code, 400)

    def test_start_rejects_out_of_range_values(self):
        form = self.valid_form()
        form["hallucination_rate"] = "1.5"

        response = self.client.post("/start", data=form)

        self.assertEqual(response.status_code, 400)

    @mock.patch("web_ui.threading.Thread")
    def test_start_dispatches_validated_background_run(self, thread_class):
        thread = thread_class.return_value

        response = self.client.post(
            "/start",
            data=self.valid_form(),
            headers={"Accept": "application/json"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "started")
        thread.start.assert_called_once_with()
        kwargs = thread_class.call_args.kwargs["kwargs"]
        self.assertEqual(kwargs["iterations"], 3)
        self.assertEqual(kwargs["run_mode"], "behavior")
        self.assertEqual(kwargs["seed"], 42)
        self.assertTrue(kwargs["dry_run"])
        self.assertFalse(kwargs["allow_network"])
        self.assertEqual(web_ui.log_queue[0]["kind"], "start")
        self.assertEqual(web_ui.log_queue[0]["params"]["iterations"], 3)

    @mock.patch("web_ui.threading.Thread")
    def test_start_dispatches_safe_scenario_suite(self, thread_class):
        form = {
            "form_token": web_ui.form_token,
            "run_mode": "scenario",
            "scenario": "mcp-tool-poisoning",
            "variant": "both",
            "speed": "0",
        }

        response = self.client.post(
            "/start", data=form, headers={"Accept": "application/json"}
        )

        self.assertEqual(response.status_code, 200)
        self.assertIs(
            thread_class.call_args.kwargs["target"], web_ui.run_scenario_background
        )
        kwargs = thread_class.call_args.kwargs["kwargs"]
        self.assertEqual(kwargs["run_mode"], "scenario")
        self.assertEqual(kwargs["scenario"], "mcp-tool-poisoning")
        self.assertEqual(kwargs["variant"], "both")
        self.assertEqual(kwargs["checkpoints"], 6)
        self.assertEqual(kwargs["mutations"], 0)
        self.assertIsNone(kwargs["mutation_seed"])
        self.assertNotIn("allow_network", kwargs)

    def test_start_rejects_unknown_scenario(self):
        response = self.client.post(
            "/start",
            data={
                "form_token": web_ui.form_token,
                "run_mode": "scenario",
                "scenario": "unknown",
                "variant": "both",
                "speed": "0",
            },
        )

        self.assertEqual(response.status_code, 400)

    def test_scenario_worker_generates_downloadable_validated_artifacts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            web_ui.GROUND_TRUTH_OUTPUT_PATH = Path(temp_dir) / "events.jsonl"
            web_ui.VALIDATION_OUTPUT_PATH = Path(temp_dir) / "validation.json"
            web_ui.JUNIT_OUTPUT_PATH = Path(temp_dir) / "junit.xml"
            web_ui.SARIF_OUTPUT_PATH = Path(temp_dir) / "results.sarif"
            web_ui.OTEL_OUTPUT_PATH = Path(temp_dir) / "otel.jsonl"
            web_ui.COVERAGE_OUTPUT_PATH = Path(temp_dir) / "coverage.json"
            web_ui.BUNDLE_OUTPUT_PATH = Path(temp_dir) / "evidence.zip"
            with web_ui.state_lock:
                web_ui.is_running = True
                web_ui.last_outcome = "running"

            web_ui.run_scenario_background(
                run_mode="scenario",
                scenario="indirect-prompt-injection",
                variant="both",
                speed=0,
                checkpoints=8,
                mutations=0,
                mutation_seed=None,
            )

            self.assertFalse(web_ui.is_running)
            self.assertEqual(web_ui.last_outcome, "complete")
            self.assertTrue(web_ui.last_ground_truth_path.exists())
            self.assertTrue(web_ui.last_validation_path.exists())
            self.assertTrue(web_ui.last_bundle_path.exists())
            self.assertEqual(web_ui.last_benchmark_metrics["precision"], 1.0)
            report = json.loads(
                web_ui.last_validation_path.read_text(encoding="utf-8")
            )
            self.assertTrue(report["summary"]["all_passed"])
            self.assertEqual(report["summary"]["checks"], 2)
            self.assertEqual(web_ui.log_queue[-1]["kind"], "complete")

    def test_stop_sets_event_and_records_operator_action(self):
        with web_ui.state_lock:
            web_ui.is_running = True

        response = self.client.post(
            "/stop",
            data={"form_token": web_ui.form_token},
            headers={"Accept": "application/json"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(web_ui.stop_event.is_set())
        self.assertEqual(web_ui.log_queue[-1]["kind"], "stop_requested")

    def test_stop_returns_conflict_when_idle(self):
        response = self.client.post(
            "/stop",
            data={"form_token": web_ui.form_token},
            headers={"Accept": "application/json"},
        )

        self.assertEqual(response.status_code, 409)

    def test_clear_removes_idle_event_history(self):
        web_ui._append_event("[*] test event")

        response = self.client.post(
            "/clear",
            data={"form_token": web_ui.form_token},
            headers={"Accept": "application/json"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(web_ui.log_queue, [])

    def test_download_returns_generated_layer(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            layer_path = Path(temp_dir) / "layer.json"
            layer_path.write_text(json.dumps({"name": "test"}), encoding="utf-8")
            with web_ui.state_lock:
                web_ui.last_layer_path = layer_path

            response = self.client.get("/download-layer")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.mimetype, "application/json")
            self.assertIn(
                "attachment; filename=agent_sim_layer.json",
                response.headers["Content-Disposition"],
            )
            response.close()

    def test_download_returns_not_found_before_a_run(self):
        response = self.client.get("/download-layer")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.client.get("/download-ground-truth").status_code, 404)
        self.assertEqual(self.client.get("/download-validation").status_code, 404)
        self.assertEqual(self.client.get("/download-bundle").status_code, 404)

    def test_download_returns_scenario_artifacts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            events_path = Path(temp_dir) / "events.jsonl"
            report_path = Path(temp_dir) / "report.json"
            bundle_path = Path(temp_dir) / "evidence.zip"
            events_path.write_text('{"schema_version":"1.0"}\n', encoding="utf-8")
            report_path.write_text('{"summary":{}}\n', encoding="utf-8")
            bundle_path.write_bytes(b"PK synthetic")
            with web_ui.state_lock:
                web_ui.last_ground_truth_path = events_path
                web_ui.last_validation_path = report_path
                web_ui.last_bundle_path = bundle_path

            status = self.client.get("/api/status").get_json()
            self.assertTrue(status["ground_truth_available"])
            self.assertTrue(status["validation_available"])
            self.assertTrue(status["bundle_available"])

            ground_truth = self.client.get("/download-ground-truth")
            validation = self.client.get("/download-validation")
            bundle = self.client.get("/download-bundle")
            self.assertEqual(ground_truth.status_code, 200)
            self.assertEqual(ground_truth.mimetype, "application/x-ndjson")
            self.assertIn("agent_sim_events.jsonl", ground_truth.headers["Content-Disposition"])
            self.assertEqual(validation.status_code, 200)
            self.assertEqual(validation.mimetype, "application/json")
            self.assertIn("agent_sim_validation.json", validation.headers["Content-Disposition"])
            self.assertEqual(bundle.status_code, 200)
            self.assertEqual(bundle.mimetype, "application/zip")
            self.assertIn("agent_sim_evidence.zip", bundle.headers["Content-Disposition"])
            ground_truth.close()
            validation.close()
            bundle.close()

    def test_detection_debugger_explains_rule_signals_and_timeline(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            web_ui.GROUND_TRUTH_OUTPUT_PATH = Path(temp_dir) / "events.jsonl"
            web_ui.VALIDATION_OUTPUT_PATH = Path(temp_dir) / "validation.json"
            web_ui.JUNIT_OUTPUT_PATH = Path(temp_dir) / "junit.xml"
            web_ui.SARIF_OUTPUT_PATH = Path(temp_dir) / "results.sarif"
            web_ui.OTEL_OUTPUT_PATH = Path(temp_dir) / "otel.jsonl"
            web_ui.COVERAGE_OUTPUT_PATH = Path(temp_dir) / "coverage.json"
            web_ui.BUNDLE_OUTPUT_PATH = Path(temp_dir) / "evidence.zip"
            with web_ui.state_lock:
                web_ui.is_running = True
                web_ui.last_outcome = "running"

            web_ui.run_scenario_background(
                run_mode="scenario",
                scenario="approval-replay",
                variant="both",
                speed=0,
                checkpoints=6,
                mutations=0,
                mutation_seed=42,
            )

            summary_response = self.client.get("/api/detection-debug")
            self.assertEqual(summary_response.status_code, 200)
            summary = summary_response.get_json()
            self.assertEqual(summary["summary"]["checks"], 2)
            self.assertEqual(len(summary["traces"]), 2)
            malicious = next(
                trace for trace in summary["traces"] if trace["variant"] == "malicious"
            )
            self.assertTrue(malicious["passed"])
            self.assertEqual(malicious["signal_count"], 2)

            detail_response = self.client.get(
                "/api/detection-debug/trace",
                query_string={"trace_id": malicious["trace_id"]},
            )
            self.assertEqual(detail_response.status_code, 200)
            detail = detail_response.get_json()
            self.assertEqual(len(detail["detector"]["conditions"]), 2)
            self.assertEqual(len(detail["events"]), 3)
            self.assertEqual(len(detail["result"]["signal_event_ids"]), 2)

    def test_detection_debugger_requires_current_artifacts(self):
        self.assertEqual(self.client.get("/api/detection-debug").status_code, 404)
        self.assertEqual(
            self.client.get(
                "/api/detection-debug/trace", query_string={"trace_id": "missing"}
            ).status_code,
            404,
        )


if __name__ == "__main__":
    unittest.main()
