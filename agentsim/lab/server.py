"""Loopback/container entry point for the disposable reference-agent lab."""

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Sequence

from .fixtures import list_fixtures
from .reference import run_reference_fixture


MAX_REQUEST_BYTES = 64 * 1024


class ReferenceLabHandler(BaseHTTPRequestHandler):
    server_version = "AgentSimReferenceLab/1.5"

    def _json(self, status: int, value: object) -> None:
        body = json.dumps(value, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - standard-library handler contract
        if self.path == "/health":
            self._json(200, {"status": "ok", "version": "1.5.0", "synthetic_only": True})
            return
        if self.path == "/fixtures":
            self._json(
                200,
                {
                    "fixtures": [
                        {
                            "fixture_id": item.fixture_id,
                            "name": item.name,
                            "control": item.control,
                            "atlas_techniques": list(item.atlas_techniques),
                            "owasp_risks": list(item.owasp_risks),
                        }
                        for item in list_fixtures()
                    ]
                },
            )
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802 - standard-library handler contract
        if self.path != "/run":
            self._json(404, {"error": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._json(400, {"error": "invalid_content_length"})
            return
        if not 0 < length <= MAX_REQUEST_BYTES:
            self._json(413, {"error": "request_too_large_or_empty"})
            return
        try:
            value = json.loads(self.rfile.read(length))
            if not isinstance(value, dict) or set(value) != {"fixture_id"}:
                raise ValueError("request must contain fixture_id only")
            result = run_reference_fixture(str(value["fixture_id"]))
        except (json.JSONDecodeError, ValueError) as exc:
            self._json(400, {"error": "invalid_request", "message": str(exc)})
            return
        self._json(200, result.to_dict())

    def log_message(self, format: str, *args: object) -> None:
        print(f"reference-lab {self.client_address[0]} {format % args}")


def serve_reference_lab(
    host: str = "127.0.0.1", port: int = 8765, *, allow_loopback: bool = False,
    allow_container_bind: bool = False,
) -> None:
    if isinstance(port, bool) or not 1024 <= port <= 65535:
        raise ValueError("reference lab port must be between 1024 and 65535")
    loopback = host in {"127.0.0.1", "localhost", "::1"}
    container_allowed = (
        host == "0.0.0.0"
        and allow_container_bind
        and os.environ.get("AGENTSIM_DISPOSABLE_CONTAINER") == "1"
    )
    if not allow_loopback or (not loopback and not container_allowed):
        raise PermissionError(
            "reference lab requires explicit loopback opt-in or the disposable-container guard"
        )
    server = ThreadingHTTPServer((host, port), ReferenceLabHandler)
    try:
        print(f"AgentSim reference lab listening on http://{host}:{port}")
        server.serve_forever()
    finally:
        server.server_close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AgentSim disposable reference-agent lab")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--allow-loopback", action="store_true")
    parser.add_argument("--allow-container-bind", action="store_true")
    args = parser.parse_args(argv)
    serve_reference_lab(
        args.host,
        args.port,
        allow_loopback=args.allow_loopback,
        allow_container_bind=args.allow_container_bind,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
