"""In-memory MCP JSON-RPC security boundary lab.

The lab serializes and parses protocol-shaped JSON-RPC messages but never opens
a socket, loads a plugin, accesses a real token, or invokes a tool. All results
are fixed synthetic fixtures.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping


MCP_LAB_SCHEMA_VERSION = "1.0"
DEFAULT_MCP_LAB_PATH = "agent_sim_mcp_lab.json"
LogCallback = Callable[[str], None]


@dataclass(frozen=True)
class SyntheticAuthContext:
    """Non-secret authorization facts supplied to the in-memory MCP server."""

    principal_id: str
    audience: str
    scopes: tuple[str, ...]
    session_id: str
    client_id: str
    per_client_consent: bool
    token_passthrough: bool = False
    token_fingerprint: str = "sha256:synthetic-token"


class SyntheticMcpServer:
    """Minimal JSON-RPC MCP boundary with deterministic security controls."""

    expected_audience = "agentsim-mcp"
    server_id = "agentsim-synthetic-mcp"
    allowed_tool = "synthetic.search"

    def __init__(self) -> None:
        self._session_principals: dict[str, str] = {}

    @staticmethod
    def _error(request_id: object, code: int, message: str) -> dict[str, object]:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": code, "message": message},
        }

    def _authorize(
        self, request_id: object, auth: SyntheticAuthContext
    ) -> dict[str, object] | None:
        if auth.token_passthrough:
            return self._error(request_id, -32001, "token passthrough rejected")
        if auth.audience != self.expected_audience:
            return self._error(request_id, -32002, "token audience rejected")
        if not auth.per_client_consent:
            return self._error(request_id, -32003, "per-client consent required")
        bound_principal = self._session_principals.get(auth.session_id)
        if bound_principal is not None and bound_principal != auth.principal_id:
            return self._error(request_id, -32004, "session principal mismatch")
        self._session_principals.setdefault(auth.session_id, auth.principal_id)
        return None

    def handle(
        self, request: Mapping[str, object], auth: SyntheticAuthContext
    ) -> dict[str, object]:
        request_id = request.get("id")
        if request.get("jsonrpc") != "2.0":
            return self._error(request_id, -32600, "invalid JSON-RPC version")
        authorization_error = self._authorize(request_id, auth)
        if authorization_error:
            return authorization_error

        method = request.get("method")
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "serverInfo": {"name": self.server_id, "version": "1.0"},
                    "capabilities": {"tools": {"listChanged": False}},
                },
            }
        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "tools": [
                        {
                            "name": self.allowed_tool,
                            "description": "Read a fixed synthetic public catalog.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"query_fingerprint": {"type": "string"}},
                                "additionalProperties": False,
                            },
                        }
                    ]
                },
            }
        if method == "tools/call":
            params = request.get("params")
            params = params if isinstance(params, Mapping) else {}
            if params.get("name") != self.allowed_tool:
                return self._error(request_id, -32601, "unknown synthetic tool")
            if "catalog.read" not in auth.scopes:
                return self._error(request_id, -32005, "required scope missing")
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": "synthetic-public-result-fingerprint-v1",
                        }
                    ],
                    "isError": False,
                    "classification": "public",
                    "executed": False,
                    "simulationOnly": True,
                },
            }
        return self._error(request_id, -32601, "unsupported method")

    def exchange(
        self, request: Mapping[str, object], auth: SyntheticAuthContext
    ) -> dict[str, object]:
        """Exercise serialization and parsing without transport or tool execution."""

        wire_request = json.dumps(dict(request), separators=(",", ":"))
        parsed_request = json.loads(wire_request)
        response = self.handle(parsed_request, auth)
        wire_response = json.dumps(response, separators=(",", ":"))
        return json.loads(wire_response)


def _request(request_id: int, method: str, **params: object) -> dict[str, object]:
    request: dict[str, object] = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
    }
    if params:
        request["params"] = params
    return request


def _rejected(response: Mapping[str, object], code: int) -> bool:
    error = response.get("error")
    return isinstance(error, Mapping) and error.get("code") == code


def build_mcp_lab_report() -> dict[str, object]:
    """Run safe positive and negative MCP authorization checks."""

    server = SyntheticMcpServer()
    valid = SyntheticAuthContext(
        principal_id="synthetic-user-a",
        audience="agentsim-mcp",
        scopes=("catalog.read",),
        session_id="synthetic-session-a",
        client_id="synthetic-approved-client",
        per_client_consent=True,
    )
    valid_response = server.exchange(
        _request(
            1,
            "tools/call",
            name="synthetic.search",
            arguments={"query_fingerprint": "sha256:synthetic-query"},
        ),
        valid,
    )
    checks: list[dict[str, object]] = [
        {
            "check_id": "valid-read-allowed",
            "expected": "allow",
            "passed": "result" in valid_response and "error" not in valid_response,
        }
    ]

    cases = (
        (
            "token-passthrough-rejected",
            SyntheticAuthContext(
                **{**valid.__dict__, "session_id": "synthetic-session-b", "token_passthrough": True}
            ),
            -32001,
        ),
        (
            "wrong-audience-rejected",
            SyntheticAuthContext(
                **{**valid.__dict__, "session_id": "synthetic-session-c", "audience": "synthetic-downstream"}
            ),
            -32002,
        ),
        (
            "missing-consent-rejected",
            SyntheticAuthContext(
                **{**valid.__dict__, "session_id": "synthetic-session-d", "per_client_consent": False}
            ),
            -32003,
        ),
    )
    for index, (check_id, auth, error_code) in enumerate(cases, start=2):
        response = server.exchange(_request(index, "tools/list"), auth)
        checks.append(
            {
                "check_id": check_id,
                "expected": "reject",
                "expected_error_code": error_code,
                "passed": _rejected(response, error_code),
            }
        )

    session_owner = SyntheticAuthContext(
        **{**valid.__dict__, "session_id": "synthetic-shared-session"}
    )
    server.exchange(_request(5, "initialize"), session_owner)
    hijacker = SyntheticAuthContext(
        **{**session_owner.__dict__, "principal_id": "synthetic-user-b"}
    )
    hijack_response = server.exchange(_request(6, "tools/list"), hijacker)
    checks.append(
        {
            "check_id": "session-hijack-rejected",
            "expected": "reject",
            "expected_error_code": -32004,
            "passed": _rejected(hijack_response, -32004),
        }
    )
    unknown_response = server.exchange(
        _request(7, "tools/call", name="synthetic.publish", arguments={}),
        SyntheticAuthContext(**{**valid.__dict__, "session_id": "synthetic-session-e"}),
    )
    checks.append(
        {
            "check_id": "unknown-tool-rejected",
            "expected": "reject",
            "expected_error_code": -32601,
            "passed": _rejected(unknown_response, -32601),
        }
    )

    passed = sum(1 for check in checks if check["passed"])
    return {
        "schema_version": MCP_LAB_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        ),
        "execution_mode": "in_memory_simulation_only",
        "transport_opened": False,
        "tool_executed": False,
        "token_recorded": False,
        "summary": {
            "checks": len(checks),
            "passed": passed,
            "failed": len(checks) - passed,
            "all_passed": passed == len(checks),
        },
        "checks": checks,
    }


def run_mcp_lab(
    output_path: str | Path = DEFAULT_MCP_LAB_PATH,
    *,
    log_callback: LogCallback | None = None,
) -> Path:
    path = Path(output_path).expanduser()
    if not path.parent.exists():
        raise FileNotFoundError(f"output directory does not exist: {path.parent}")
    report = build_mcp_lab_report()
    with path.open("w", encoding="utf-8") as output_file:
        json.dump(report, output_file, indent=2, sort_keys=True)
        output_file.write("\n")
    log = log_callback or print
    summary = report["summary"]
    assert isinstance(summary, Mapping)
    log("[*] MCP lab used in-memory JSON-RPC only; no transport or tool opened.")
    log(f"[+] MCP protocol report exported to '{path}'")
    log(f"[+] MCP security checks passed: {summary['passed']}/{summary['checks']}.")
    return path
