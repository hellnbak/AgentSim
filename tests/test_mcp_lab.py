import json
import tempfile
import unittest
from pathlib import Path

import mcp_lab


class McpLabTests(unittest.TestCase):
    def test_all_mcp_boundary_controls_pass_without_execution(self):
        report = mcp_lab.build_mcp_lab_report()

        self.assertTrue(report["summary"]["all_passed"])
        self.assertEqual(report["summary"]["checks"], 6)
        self.assertFalse(report["transport_opened"])
        self.assertFalse(report["tool_executed"])
        self.assertFalse(report["token_recorded"])
        self.assertTrue(all(check["passed"] for check in report["checks"]))

    def test_lab_exports_json_report(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "mcp.json"

            result = mcp_lab.run_mcp_lab(output, log_callback=lambda _message: None)

            self.assertEqual(result, output)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["execution_mode"], "in_memory_simulation_only")

    def test_scope_and_invalid_jsonrpc_are_rejected(self):
        server = mcp_lab.SyntheticMcpServer()
        auth = mcp_lab.SyntheticAuthContext(
            principal_id="synthetic-user",
            audience="agentsim-mcp",
            scopes=(),
            session_id="synthetic-session",
            client_id="synthetic-client",
            per_client_consent=True,
        )

        invalid = server.exchange({"jsonrpc": "1.0", "id": 1}, auth)
        missing_scope = server.exchange(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "synthetic.search"},
            },
            auth,
        )

        self.assertEqual(invalid["error"]["code"], -32600)
        self.assertEqual(missing_scope["error"]["code"], -32005)


if __name__ == "__main__":
    unittest.main()
