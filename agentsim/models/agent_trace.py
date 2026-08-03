"""Canonical, content-safe telemetry contract for agent and MCP runtimes."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Mapping, Sequence

from .telemetry import NormalizedEvent


AGENT_TRACE_SCHEMA_VERSION = "1.1"
ALLOWED_EVENT_PREFIXES = ("agent.", "gen_ai.", "mcp.")
_SENSITIVE_KEYS = (
    "argument",
    "body",
    "completion",
    "content",
    "credential",
    "document",
    "instruction",
    "message",
    "password",
    "payload",
    "prompt",
    "query",
    "reasoning",
    "response",
    "result",
    "secret",
    "text",
)
_TOKEN_SAFE_SUFFIXES = (
    "_audience",
    "_count",
    "_fingerprint",
    "_present",
    "_recorded",
    "_resource",
    "_scopes",
    "_valid",
)
_SAFE_CONTENT_FLAGS = frozenset(
    {
        "arguments_recorded",
        "result_recorded",
        "prompts_recorded",
        "messages_recorded",
        "tool_arguments_recorded",
        "tool_results_recorded",
        "credentials_recorded",
    }
)


def _utc_timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError("agent trace timestamp must be ISO 8601") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _text(value: object, field_name: str, *, required: bool = False) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    if len(value) > 512:
        raise ValueError(f"{field_name} exceeds 512 characters")
    return value


def _sensitive_key(name: str) -> bool:
    lowered = name.casefold()
    # These exact boolean field names communicate that content was omitted.
    # Broader ``*_recorded`` exceptions would let content-bearing keys bypass
    # the deny-list, so keep this allow-list deliberately narrow.
    if lowered in _SAFE_CONTENT_FLAGS:
        return False
    if any(term in lowered for term in _SENSITIVE_KEYS):
        return True
    if "token" in lowered and not lowered.endswith(_TOKEN_SAFE_SUFFIXES):
        return True
    return False


def _safe_value(value: object, depth: int = 0) -> object:
    if depth > 3:
        return "<depth-limited>"
    if isinstance(value, str):
        return value[:1000]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, Mapping):
        return {
            str(key): _safe_value(item, depth + 1)
            for key, item in list(value.items())[:50]
            if not _sensitive_key(str(key))
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return tuple(_safe_value(item, depth + 1) for item in value[:50])
    return str(value)[:500]


def sanitize_agent_attributes(attributes: Mapping[str, object]) -> dict[str, object]:
    """Bound runtime attributes and discard raw content, credentials, and tokens."""

    return {
        str(key): _safe_value(value)
        for key, value in list(attributes.items())[:100]
        if not _sensitive_key(str(key))
    }


@dataclass(frozen=True)
class AgentTraceEvent:
    """One observable checkpoint in an agent, model, tool, or MCP lifecycle."""

    timestamp: str
    event_id: str
    event_type: str
    trace_id: str
    session_id: str
    agent_id: str
    source: str = "agent_runtime"
    conversation_id: str | None = None
    agent_instance_id: str | None = None
    principal_id: str | None = None
    turn_id: str | None = None
    tool_call_id: str | None = None
    tool_name: str | None = None
    tool_risk: str | None = None
    parent_event_id: str | None = None
    caused_by_event_ids: tuple[str, ...] = ()
    delegation_id: str | None = None
    delegated_from_agent_id: str | None = None
    delegated_to_agent_id: str | None = None
    identity_binding_valid: bool | None = None
    data_lineage_id: str | None = None
    memory_id: str | None = None
    memory_scope: str | None = None
    memory_provenance_valid: bool | None = None
    memory_retention_valid: bool | None = None
    goal_id: str | None = None
    goal_fingerprint: str | None = None
    goal_integrity_valid: bool | None = None
    goal_change_approved: bool | None = None
    model_id: str | None = None
    mcp_client_id: str | None = None
    mcp_server_id: str | None = None
    auth_audience: str | None = None
    auth_resource: str | None = None
    auth_scopes: tuple[str, ...] = ()
    auth_audience_valid: bool | None = None
    consent_valid: bool | None = None
    policy_id: str | None = None
    policy_version: str | None = None
    policy_decision: str | None = None
    approval_id: str | None = None
    approval_fingerprint: str | None = None
    input_trust: str | None = None
    taint_labels: tuple[str, ...] = ()
    outcome: str | None = None
    synthetic: bool = False
    content_recorded: bool = False
    attributes: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "timestamp", _utc_timestamp(self.timestamp))
        for name in ("event_id", "trace_id", "session_id", "agent_id", "source"):
            _text(getattr(self, name), name, required=True)
        for name in (
            "conversation_id",
            "agent_instance_id",
            "principal_id",
            "turn_id",
            "tool_call_id",
            "tool_name",
            "tool_risk",
            "parent_event_id",
            "delegation_id",
            "delegated_from_agent_id",
            "delegated_to_agent_id",
            "data_lineage_id",
            "memory_id",
            "memory_scope",
            "goal_id",
            "goal_fingerprint",
            "model_id",
            "mcp_client_id",
            "mcp_server_id",
            "auth_audience",
            "auth_resource",
            "policy_id",
            "policy_version",
            "policy_decision",
            "approval_id",
            "approval_fingerprint",
            "input_trust",
            "outcome",
        ):
            _text(getattr(self, name), name)
        if not self.event_type.startswith(ALLOWED_EVENT_PREFIXES):
            raise ValueError("event_type must start with agent., gen_ai., or mcp.")
        _text(self.event_type, "event_type", required=True)
        for name in (
            "auth_audience_valid",
            "consent_valid",
            "identity_binding_valid",
            "memory_provenance_valid",
            "memory_retention_valid",
            "goal_integrity_valid",
            "goal_change_approved",
        ):
            value = getattr(self, name)
            if value is not None and not isinstance(value, bool):
                raise ValueError(f"{name} must be a boolean or null")
        if not isinstance(self.synthetic, bool) or not isinstance(self.content_recorded, bool):
            raise ValueError("synthetic and content_recorded must be booleans")
        if self.content_recorded:
            raise ValueError("agent trace content_recorded must remain false")
        for name in ("auth_scopes", "taint_labels", "caused_by_event_ids"):
            value = getattr(self, name)
            if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
                raise ValueError(f"{name} must be an array")
            if len(value) > 50:
                raise ValueError(f"{name} is limited to 50 values")
            object.__setattr__(self, name, tuple(value))
        for value in (*self.auth_scopes, *self.taint_labels, *self.caused_by_event_ids):
            _text(value, "agent trace list value", required=True)
        if not isinstance(self.attributes, Mapping):
            raise ValueError("agent trace attributes must be an object")
        object.__setattr__(self, "attributes", sanitize_agent_attributes(self.attributes))

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["schema_version"] = AGENT_TRACE_SCHEMA_VERSION
        value["content_recorded"] = False
        return value

    def to_normalized_event(self, *, collector: str = "agent_runtime") -> NormalizedEvent:
        fields = {
            key: value
            for key, value in self.to_dict().items()
            if key
            not in {
                "schema_version",
                "timestamp",
                "source",
                "event_type",
                "event_id",
                "attributes",
                "synthetic",
                "content_recorded",
            }
            and value not in (None, (), [], {})
        }
        safe_attributes = dict(self.attributes)
        fields.update(
            {
                f"attributes.{key}": value
                for key, value in safe_attributes.items()
                if not isinstance(value, Mapping)
            }
        )
        available = {
            "timestamp",
            "source",
            "event_type",
            "event_id",
            *fields,
            *(f"attributes.{key}" for key in safe_attributes),
        }
        return NormalizedEvent(
            timestamp=self.timestamp,
            source=self.source,
            event_type=self.event_type,
            fields=fields,
            available_fields=tuple(sorted(available)),
            collector=collector,
            synthetic=self.synthetic,
            source_record_id=self.event_id,
            metadata={
                "agent_trace_schema_version": AGENT_TRACE_SCHEMA_VERSION,
                "content_recorded": False,
                "redacted": True,
                "timestamp_present": True,
                "timestamp_valid": True,
                "source_record_id_present": True,
                "generated_identity_fields": [],
            },
        )


def agent_trace_from_mapping(value: Mapping[str, object]) -> AgentTraceEvent:
    """Validate a canonical mapping without accepting raw prompt or tool content."""

    converted: dict[str, object] = dict(value)
    converted.pop("schema_version", None)
    for name in ("caused_by_event_ids", "auth_scopes", "taint_labels"):
        raw = converted.get(name, ())
        if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes, bytearray)):
            raise ValueError(f"{name} must be an array")
        converted[name] = tuple(raw)
    attributes = converted.get("attributes", {})
    if not isinstance(attributes, Mapping):
        raise ValueError("attributes must be an object")
    converted["attributes"] = attributes
    allowed = set(AgentTraceEvent.__dataclass_fields__)
    unknown = sorted(set(converted) - allowed)
    if unknown:
        raise ValueError(f"unknown agent trace fields: {', '.join(unknown)}")
    return AgentTraceEvent(**converted)  # type: ignore[arg-type]


def agent_trace_json(event: AgentTraceEvent) -> str:
    return json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":"))
