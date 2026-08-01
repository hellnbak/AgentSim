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
        with web_ui.state_lock:
            web_ui.is_running = False
            web_ui.log_queue.clear()
            web_ui.event_sequence = 0
            web_ui.last_layer_path = None
            web_ui.run_started_at = None
            web_ui.run_finished_at = None
            web_ui.current_params = {}
            web_ui.stop_event.clear()

    def tearDown(self):
        web_ui.LAYER_OUTPUT_PATH = self.original_layer_path

    def valid_form(self):
        return {
            "form_token": web_ui.form_token,
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
        self.assertIn("Behavioral Telemetry Lab", page)
        self.assertIn("message.textContent", page)
        self.assertNotIn(".innerHTML", page)

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
        self.assertEqual(kwargs["seed"], 42)
        self.assertTrue(kwargs["dry_run"])
        self.assertFalse(kwargs["allow_network"])
        self.assertEqual(web_ui.log_queue[0]["kind"], "start")
        self.assertEqual(web_ui.log_queue[0]["params"]["iterations"], 3)

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


if __name__ == "__main__":
    unittest.main()
