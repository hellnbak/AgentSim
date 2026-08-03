"""Loopback-only OTLP/HTTP JSON receiver for the AgentSim flight recorder."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Mapping

from .flight_recorder import FlightRecorder


MAX_OTLP_REQUEST_BYTES = 8 * 1024 * 1024


class FlightRecorderHandler(BaseHTTPRequestHandler):
    server_version = "AgentSimFlightRecorder/1.0"

    @property
    def recorder(self) -> FlightRecorder:
        return self.server.recorder  # type: ignore[attr-defined,no-any-return]

    @property
    def output_path(self) -> Path | None:
        return self.server.output_path  # type: ignore[attr-defined,no-any-return]

    def _json(self, status: int, value: Mapping[str, object]) -> None:
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
            self._json(
                200,
                {
                    "status": "ok",
                    "receiver": "agentsim-flight-recorder",
                    "loopback_only": True,
                    "content_values_recorded": False,
                },
            )
            return
        if self.path == "/snapshot":
            self._json(200, self.recorder.snapshot().to_dict())
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802 - standard-library handler contract
        if self.path != "/v1/traces":
            self._json(404, {"error": "not_found"})
            return
        if self.headers.get_content_type() != "application/json":
            self._json(415, {"error": "application_json_required"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._json(400, {"error": "invalid_content_length"})
            return
        if not 0 < length <= MAX_OTLP_REQUEST_BYTES:
            self._json(413, {"error": "request_too_large_or_empty"})
            return
        try:
            value = json.loads(self.rfile.read(length))
            if not isinstance(value, Mapping):
                raise ValueError("OTLP trace export must be a JSON object")
            accepted = self.recorder.ingest_otlp_export(value)
            if self.output_path is not None:
                self.recorder.snapshot().write(self.output_path)
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            self.recorder.record_error()
            self._json(400, {"error": "invalid_otlp_export", "message": str(exc)[:512]})
            return
        self._json(200, {"accepted_spans": accepted, "content_values_recorded": False})

    def log_message(self, format: str, *args: object) -> None:
        print(f"flight-recorder {self.client_address[0]} {format % args}")


def serve_flight_recorder(
    recorder: FlightRecorder,
    *,
    host: str = "127.0.0.1",
    port: int = 4318,
    allow_loopback: bool = False,
    output_path: str | Path | None = None,
) -> None:
    """Serve a bounded OTLP JSON receiver with no outbound request capability."""

    if isinstance(port, bool) or not 1024 <= port <= 65535:
        raise ValueError("flight recorder port must be between 1024 and 65535")
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("flight recorder receiver may bind to loopback only")
    if not allow_loopback:
        raise ValueError("flight recorder receiver requires explicit allow_loopback")
    server = ThreadingHTTPServer((host, port), FlightRecorderHandler)
    server.recorder = recorder  # type: ignore[attr-defined]
    server.output_path = Path(output_path) if output_path else None  # type: ignore[attr-defined]
    try:
        server.serve_forever()
    finally:
        server.server_close()
        if output_path:
            recorder.snapshot().write(output_path)


__all__ = ["FlightRecorderHandler", "serve_flight_recorder"]
