import unittest
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
        with web_ui.state_lock:
            web_ui.is_running = False
            web_ui.log_queue.clear()

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

    def test_index_has_security_headers_and_safe_log_rendering(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("logs.textContent", response.get_data(as_text=True))
        self.assertNotIn("logs.innerHTML", response.get_data(as_text=True))

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

        response = self.client.post("/start", data=self.valid_form())

        self.assertEqual(response.status_code, 302)
        thread.start.assert_called_once_with()
        kwargs = thread_class.call_args.kwargs["kwargs"]
        self.assertEqual(kwargs["iterations"], 3)
        self.assertEqual(kwargs["seed"], 42)
        self.assertTrue(kwargs["dry_run"])
        self.assertFalse(kwargs["allow_network"])


if __name__ == "__main__":
    unittest.main()
