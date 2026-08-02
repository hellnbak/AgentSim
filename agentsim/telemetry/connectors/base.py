"""Safety primitives for bounded, read-only telemetry queries."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import ssl
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Mapping, Protocol
from urllib.parse import urlparse

from agentsim.models.telemetry import NormalizedEvent


MAX_LIVE_RECORDS = 10_000
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_QUERY_WINDOW = timedelta(hours=24)
_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
_DATASET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:$-]{0,254}$")
_TARGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,254}$")
_ENVIRONMENT = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")


def utc_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("query timestamps must be ISO 8601") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def iso_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def validate_base_url(value: str) -> str:
    parsed = urlparse(value)
    local_http = parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    if parsed.scheme != "https" and not local_http:
        raise ValueError("live connector base_url must use HTTPS or explicit loopback HTTP")
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or parsed.params
    ):
        raise ValueError("live connector base_url must be an origin without credentials or query data")
    return value.rstrip("/")


@dataclass(frozen=True)
class QuerySpec:
    connector: str
    base_url: str
    dataset: str
    target: str
    since: str
    until: str
    limit: int = 1000
    target_field: str | None = None
    credential_env: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "base_url", validate_base_url(self.base_url))
        if not _NAME.fullmatch(self.connector):
            raise ValueError("invalid connector name")
        if not _DATASET.fullmatch(self.dataset) or "*" in self.dataset:
            raise ValueError("dataset must be an exact index, repository, table, or workspace ID")
        if not _TARGET.fullmatch(self.target) or self.target in {"*", "_all"}:
            raise ValueError("target must be a specific host, agent, principal, or resource identifier")
        if self.target_field is not None and not _NAME.fullmatch(self.target_field):
            raise ValueError("target_field contains unsupported characters")
        if isinstance(self.limit, bool) or not isinstance(self.limit, int) or not 1 <= self.limit <= MAX_LIVE_RECORDS:
            raise ValueError(f"limit must be between 1 and {MAX_LIVE_RECORDS}")
        start, end = utc_time(self.since), utc_time(self.until)
        if start >= end:
            raise ValueError("query since must be before until")
        if end - start > MAX_QUERY_WINDOW:
            raise ValueError("live query windows may not exceed 24 hours")
        object.__setattr__(self, "since", iso_time(start))
        object.__setattr__(self, "until", iso_time(end))
        if self.credential_env is not None and not _ENVIRONMENT.fullmatch(self.credential_env):
            raise ValueError("credential_env must be an uppercase environment variable name")


@dataclass(frozen=True)
class QueryPlan:
    connector: str
    method: str
    url: str
    content_type: str
    body: bytes
    credential_env: str
    auth_style: str
    profile: str
    since: str
    until: str
    target: str
    dataset: str
    limit: int
    metadata: Mapping[str, object] = field(default_factory=dict)

    @property
    def query_sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value.pop("body")
        value.update(
            {
                "schema_version": "1.0",
                "query_sha256": self.query_sha256,
                "credential_value_recorded": False,
                "authorization_header_recorded": False,
                "network_execution": "disabled_until_explicit_execute_and_allow_network",
            }
        )
        return value


@dataclass(frozen=True)
class LiveQueryResult:
    plan: QueryPlan
    events: tuple[NormalizedEvent, ...]
    response_bytes: int
    request_count: int = 1
    provider_query_id: str | None = None

    def to_dict(self, *, include_events: bool = False) -> dict[str, object]:
        value: dict[str, object] = {
            "schema_version": "1.0",
            "status": "completed",
            "query": self.plan.to_dict(),
            "record_count": len(self.events),
            "response_bytes": self.response_bytes,
            "request_count": self.request_count,
            "provider_query_id": self.provider_query_id,
            "sources": sorted({event.source for event in self.events}),
            "event_types": sorted({event.event_type for event in self.events}),
            "sensitive_values_recorded": False,
        }
        if include_events:
            value["events"] = [event.to_dict() for event in self.events]
        return value


class QueryTransport(Protocol):
    def request(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes
    ) -> bytes: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class HttpQueryTransport:
    """TLS-validating transport that denies redirects and bounds responses."""

    def __init__(self, timeout_seconds: int = 30) -> None:
        if not 1 <= timeout_seconds <= 120:
            raise ValueError("timeout_seconds must be between 1 and 120")
        self.timeout_seconds = timeout_seconds
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl.create_default_context()), _NoRedirect()
        )

    def request(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes
    ) -> bytes:
        if method not in {"GET", "POST"}:
            raise ValueError("live connectors support GET and POST only")
        validate_base_url(f"{urlparse(url).scheme}://{urlparse(url).netloc}")
        request = urllib.request.Request(url, data=body or None, headers=dict(headers), method=method)
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                length = response.headers.get("Content-Length")
                if length and int(length) > MAX_RESPONSE_BYTES:
                    raise ValueError("live telemetry response exceeds 32 MiB")
                content = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"live telemetry query returned HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"live telemetry query failed: {exc.reason}") from exc
        if len(content) > MAX_RESPONSE_BYTES:
            raise ValueError("live telemetry response exceeds 32 MiB")
        return content


def authorization_headers(plan: QueryPlan, environ: Mapping[str, str] | None = None) -> dict[str, str]:
    values = os.environ if environ is None else environ
    credential = values.get(plan.credential_env)
    if not credential:
        raise ValueError(f"required credential environment variable is not set: {plan.credential_env}")
    if any(character in credential for character in "\r\n"):
        raise ValueError("credential environment variable contains an invalid newline")
    headers = {"Accept": "application/json", "Content-Type": plan.content_type}
    if plan.auth_style == "bearer":
        headers["Authorization"] = f"Bearer {credential}"
    elif plan.auth_style == "api-key":
        headers["Authorization"] = f"ApiKey {credential}"
    elif plan.auth_style == "x-api-key":
        headers["X-API-Key"] = credential
    elif plan.auth_style == "graylog-token":
        encoded = base64.b64encode(f"{credential}:token".encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {encoded}"
    else:
        raise ValueError(f"unsupported connector auth style: {plan.auth_style}")
    return headers


def json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
