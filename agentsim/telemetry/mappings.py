"""Version-pinned, content-safe mappings for portable agent security telemetry.

The mappings intentionally separate fields defined by a target standard from
AgentSim security extensions.  This avoids presenting policy, delegation, or
memory fields as native OTel, ECS, or OCSF fields when the standards do not
define them.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping, Sequence

from agentsim.models.agent_trace import AgentTraceEvent, sanitize_agent_attributes


MAPPING_SCHEMA_VERSION = "1.0"
PORTABLE_PROFILES = ("otel", "ecs", "ocsf")
PROFILE_VERSIONS: Mapping[str, str] = {
    "otel": "semantic-conventions-1.43.0",
    "ecs": "9.4.0",
    "ocsf": "1.8.0",
}
PROFILE_REFERENCES: Mapping[str, str] = {
    "otel": "https://opentelemetry.io/docs/specs/semconv/",
    "ecs": "https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html",
    "ocsf": "https://github.com/ocsf/ocsf-schema/releases/tag/1.8.0",
}

# Canonical fields that have a defensible native representation.  Every other
# canonical security field is carried under an explicit AgentSim extension.
NATIVE_FIELD_PATHS: Mapping[str, Mapping[str, str]] = {
    "otel": {
        "timestamp": "timestamp",
        "event_type": "name",
        "trace_id": "trace_id",
        "event_id": "span_id",
        "parent_event_id": "parent_span_id",
        "conversation_id": "attributes.gen_ai.conversation.id",
        "agent_id": "attributes.gen_ai.agent.id",
        "tool_call_id": "attributes.gen_ai.tool.call.id",
        "tool_name": "attributes.gen_ai.tool.name",
        "data_lineage_id": "attributes.gen_ai.data_source.id",
        "model_id": "attributes.gen_ai.response.model",
        "outcome": "status.code",
    },
    "ecs": {
        "timestamp": "@timestamp",
        "event_id": "event.id",
        "event_type": "event.action",
        "trace_id": "trace.id",
        "session_id": "session.id",
        "principal_id": "user.id",
        "source": "event.dataset",
        "outcome": "event.outcome",
    },
    "ocsf": {
        "timestamp": "time",
        "event_id": "metadata.original_event_uid",
        "event_type": "activity_name",
        "trace_id": "trace.uid",
        "parent_event_id": "trace.span.parent_uid",
        "session_id": "message_context.uid",
        "conversation_id": "message_context.name",
        "agent_id": "actor.app_uid",
        "principal_id": "actor.user.uid",
        "model_id": "ai_model.name",
        "outcome": "status",
        "source": "metadata.source",
    },
}

_CORE_FIELDS = tuple(AgentTraceEvent.__dataclass_fields__)
_OTEL_SCHEMA_URL = "https://opentelemetry.io/schemas/1.43.0"
_MAX_RECORD_BYTES = 2 * 1024 * 1024
_LOSSY_NATIVE_FIELDS: Mapping[str, set[str]] = {
    "otel": {"outcome"},
    "ecs": {"outcome"},
    "ocsf": {"outcome"},
}


def _get_path(value: Mapping[str, object], path: str) -> object:
    if path in value:
        return value[path]
    current: object = value
    components = path.split(".")
    for index, component in enumerate(components):
        if isinstance(current, Mapping):
            remainder = ".".join(components[index:])
            if remainder in current:
                return current[remainder]
        if not isinstance(current, Mapping) or component not in current:
            return None
        current = current[component]
    return current


def _nonempty(value: object) -> bool:
    return value not in (None, "", (), [], {})


def _timestamp_millis(value: str) -> int:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.astimezone(timezone.utc).timestamp() * 1000)


def _iso_timestamp(value: object) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(float(value) / 1000, tz=timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
    if isinstance(value, str) and value:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    raise ValueError("portable record timestamp is missing or invalid")


def _status(value: str | None) -> tuple[str, int]:
    selected = (value or "unknown").casefold()
    if selected in {"allow", "allowed", "complete", "completed", "detected", "success", "verified"}:
        return "Success", 1
    if selected in {"block", "blocked", "deny", "denied", "error", "failed", "failure", "prevented", "rejected"}:
        return "Failure", 2
    return value or "Unknown", 0 if not value else 99


def _ecs_outcome(value: str | None) -> str:
    status, status_id = _status(value)
    if status_id == 1:
        return "success"
    if status_id == 2:
        return "failure"
    return "unknown"


def _otel_operation(event_type: str) -> str:
    if ".tool." in event_type:
        return "execute_tool"
    if ".retriev" in event_type or ".memory." in event_type:
        return "retrieval"
    if ".delegation." in event_type or ".workflow." in event_type:
        return "invoke_workflow"
    return "invoke_agent"


def _extension(event: AgentTraceEvent, native_fields: set[str]) -> dict[str, object]:
    value = event.to_dict()
    extension: dict[str, object] = {}
    for field in _CORE_FIELDS:
        if (
            field in native_fields
            and field not in {"outcome"}
        ) or field in {"content_recorded"}:
            continue
        item = value.get(field)
        if _nonempty(item):
            extension[field] = item
    extension["content_recorded"] = False
    extension["mapping_schema_version"] = MAPPING_SCHEMA_VERSION
    return extension


def _native_fields(event: AgentTraceEvent, profile: str) -> tuple[str, ...]:
    value = event.to_dict()
    return tuple(
        field
        for field in NATIVE_FIELD_PATHS[profile]
        if field == "timestamp" or _nonempty(value.get(field))
    )


def _otel_record(event: AgentTraceEvent) -> dict[str, object]:
    attributes: dict[str, object] = {
        "gen_ai.operation.name": _otel_operation(event.event_type),
        "agentsim.content.recorded": False,
        "agentsim.synthetic": event.synthetic,
    }
    native = set(_native_fields(event, "otel"))
    for field, path in NATIVE_FIELD_PATHS["otel"].items():
        if not path.startswith("attributes."):
            continue
        item = getattr(event, field)
        if _nonempty(item):
            attributes[path.removeprefix("attributes.")] = item
    attributes["agentsim"] = _extension(event, native)
    status, status_id = _status(event.outcome)
    return {
        "schema_url": _OTEL_SCHEMA_URL,
        "timestamp": event.timestamp,
        "trace_id": event.trace_id,
        "span_id": event.event_id,
        "parent_span_id": event.parent_event_id,
        "name": event.event_type,
        "kind": "INTERNAL",
        "status": {"code": "STATUS_CODE_OK" if status_id == 1 else "STATUS_CODE_ERROR" if status_id == 2 else "STATUS_CODE_UNSET", "description": status},
        "attributes": attributes,
    }


def _ecs_record(event: AgentTraceEvent) -> dict[str, object]:
    native = set(_native_fields(event, "ecs"))
    value: dict[str, object] = {
        "@timestamp": event.timestamp,
        "ecs": {"version": PROFILE_VERSIONS["ecs"]},
        "event": {
            "id": event.event_id,
            "action": event.event_type,
            "kind": "event",
            "category": ["process"] if event.event_type.startswith("agent.tool") else ["configuration"],
            "outcome": _ecs_outcome(event.outcome),
            "dataset": event.source,
        },
        "trace": {"id": event.trace_id},
        "session": {"id": event.session_id},
        "service": {"name": event.source},
        "labels": {
            "agentsim_synthetic": event.synthetic,
            "agentsim_content_recorded": False,
        },
        "agentsim": _extension(event, native),
    }
    if event.principal_id:
        value["user"] = {"id": event.principal_id}
    return value


def _ocsf_record(event: AgentTraceEvent) -> dict[str, object]:
    native = set(_native_fields(event, "ocsf"))
    status, status_id = _status(event.outcome)
    actor: dict[str, object] = {"app_uid": event.agent_id, "app_name": event.source}
    if event.principal_id:
        actor["user"] = {"uid": event.principal_id}
    message_context: dict[str, object] = {
        "uid": event.session_id,
        "name": event.conversation_id or event.session_id,
        "ai_role": "Agent",
        "ai_role_id": 4,
        "application": {"name": event.source, "uid": event.agent_instance_id or event.agent_id},
    }
    input_tokens = event.attributes.get("input_token_count")
    output_tokens = event.attributes.get("output_token_count")
    if isinstance(input_tokens, int) and not isinstance(input_tokens, bool):
        message_context["prompt_tokens"] = input_tokens
    if isinstance(output_tokens, int) and not isinstance(output_tokens, bool):
        message_context["completion_tokens"] = output_tokens
    if isinstance(input_tokens, int) and isinstance(output_tokens, int):
        message_context["total_tokens"] = input_tokens + output_tokens
    span: dict[str, object] = {
        "uid": event.event_id,
        "start_time": _timestamp_millis(event.timestamp),
        "end_time": _timestamp_millis(event.timestamp),
        "operation": event.event_type,
        "status_code": status,
    }
    if event.parent_event_id:
        span["parent_uid"] = event.parent_event_id
    value: dict[str, object] = {
        "activity_id": 99,
        "activity_name": event.event_type,
        "category_name": "Application Activity",
        "category_uid": 6,
        "class_name": "API Activity",
        "class_uid": 6003,
        "type_name": f"API Activity: {event.event_type}",
        "type_uid": 600399,
        "severity_id": 0,
        "time": _timestamp_millis(event.timestamp),
        "status": status,
        "status_id": status_id,
        "actor": actor,
        "api": {"operation": event.event_type},
        "src_endpoint": {"uid": event.agent_instance_id or event.agent_id},
        "trace": {"uid": event.trace_id, "span": span},
        "message_context": message_context,
        "metadata": {
            "version": PROFILE_VERSIONS["ocsf"],
            "profiles": ["trace", "ai_operation"],
            "product": {"name": "AgentSim", "vendor_name": "AgentSim contributors"},
            "original_event_uid": event.event_id,
            "source": event.source,
            "labels": ["synthetic"] if event.synthetic else [],
        },
        "unmapped": {"agentsim": _extension(event, native)},
    }
    if event.model_id:
        value["ai_model"] = {
            "name": event.model_id,
            "ai_provider": str(event.attributes.get("gen_ai.provider.name", "Unknown")),
        }
    return value


@dataclass(frozen=True)
class PortableMappingResult:
    profile: str
    profile_version: str
    record: Mapping[str, object]
    native_mapped_fields: tuple[str, ...]
    extension_mapped_fields: tuple[str, ...]
    omitted_fields: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": MAPPING_SCHEMA_VERSION,
            "kind": "portable-agent-telemetry-mapping",
            "profile": self.profile,
            "profile_version": self.profile_version,
            "record": dict(self.record),
            "mapping": {
                "native_fields": list(self.native_mapped_fields),
                "extension_fields": list(self.extension_mapped_fields),
                "omitted_fields": list(self.omitted_fields),
                "native_coverage_percent": round(
                    100.0 * len(self.native_mapped_fields)
                    / max(1, len(self.native_mapped_fields) + len(self.extension_mapped_fields)),
                    2,
                ),
            },
            "content_values_recorded": False,
        }


def map_agent_trace(event: AgentTraceEvent, profile: str) -> PortableMappingResult:
    """Map one canonical event to a pinned standard plus explicit extensions."""

    if profile not in PORTABLE_PROFILES:
        raise ValueError(f"unsupported portable mapping profile: {profile}")
    if profile == "otel":
        record = _otel_record(event)
    elif profile == "ecs":
        record = _ecs_record(event)
    else:
        record = _ocsf_record(event)
    rendered = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    if len(rendered.encode("utf-8")) > _MAX_RECORD_BYTES:
        raise ValueError("portable mapped record exceeds the 2 MiB limit")
    native = _native_fields(event, profile)
    extension = tuple(
        field
        for field in _CORE_FIELDS
        if field not in native
        and field != "content_recorded"
        and _nonempty(getattr(event, field))
    )
    return PortableMappingResult(
        profile,
        PROFILE_VERSIONS[profile],
        record,
        native,
        extension,
        (),
    )


def _identifier(record: Mapping[str, object], prefix: str) -> str:
    safe = sanitize_agent_attributes(record)
    digest = hashlib.sha256(
        json.dumps(safe, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:24]
    return f"{prefix}-{digest}"


def _extension_from_record(record: Mapping[str, object], profile: str) -> Mapping[str, object]:
    if profile == "otel":
        attributes = record.get("attributes")
        return attributes.get("agentsim", {}) if isinstance(attributes, Mapping) else {}
    if profile == "ecs":
        value = record.get("agentsim")
        return value if isinstance(value, Mapping) else {}
    unmapped = record.get("unmapped")
    if isinstance(unmapped, Mapping) and isinstance(unmapped.get("agentsim"), Mapping):
        return unmapped["agentsim"]  # type: ignore[return-value]
    return {}


def _native_value(record: Mapping[str, object], profile: str, field: str) -> object:
    path = NATIVE_FIELD_PATHS[profile].get(field)
    return _get_path(record, path) if path else None


def _tuple_value(value: object) -> tuple[str, ...]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return tuple(str(item) for item in value[:50] if str(item))
    if isinstance(value, str) and value:
        return tuple(part for part in value.replace(",", " ").split() if part)[:50]
    return ()


def _bool_value(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.casefold() in {"true", "false"}:
        return value.casefold() == "true"
    return None


def agent_trace_from_portable_record(
    record: Mapping[str, object], *, profile: str, synthetic: bool = False
) -> AgentTraceEvent:
    """Import a portable record, preferring native fields and safe extensions."""

    if profile not in PORTABLE_PROFILES:
        raise ValueError(f"unsupported portable mapping profile: {profile}")
    rendered = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    if len(rendered.encode("utf-8")) > _MAX_RECORD_BYTES:
        raise ValueError("portable input record exceeds the 2 MiB limit")
    extension = sanitize_agent_attributes(_extension_from_record(record, profile))

    def selected(field: str, fallback: object = None) -> object:
        item = extension.get(field)
        if field in _LOSSY_NATIVE_FIELDS[profile] and _nonempty(item):
            return item
        native = _native_value(record, profile, field)
        if _nonempty(native):
            return native
        return item if _nonempty(item) else fallback

    timestamp = _iso_timestamp(selected("timestamp"))
    trace_id = str(selected("trace_id", _identifier(record, "trace")))
    event_id = str(selected("event_id", _identifier(record, "event")))
    raw_event_type = str(selected("event_type", "agent.observation"))
    event_type = raw_event_type if raw_event_type.startswith(("agent.", "gen_ai.", "mcp.")) else f"agent.{raw_event_type}"
    raw_attributes = extension.get("attributes", {})
    attributes = sanitize_agent_attributes(raw_attributes) if isinstance(raw_attributes, Mapping) else {}
    attributes["portable_source_profile"] = profile
    attributes["content_recorded"] = False
    kwargs = {
        "timestamp": timestamp,
        "event_id": event_id,
        "event_type": event_type,
        "trace_id": trace_id,
        "session_id": str(selected("session_id", f"session-{trace_id[-12:]}")),
        "agent_id": str(selected("agent_id", "unknown-agent")),
        "source": str(selected("source", f"portable_{profile}")),
        "conversation_id": selected("conversation_id"),
        "agent_instance_id": selected("agent_instance_id"),
        "principal_id": selected("principal_id"),
        "turn_id": selected("turn_id"),
        "tool_call_id": selected("tool_call_id"),
        "tool_name": selected("tool_name"),
        "tool_risk": selected("tool_risk"),
        "parent_event_id": selected("parent_event_id"),
        "caused_by_event_ids": _tuple_value(selected("caused_by_event_ids", ())),
        "delegation_id": selected("delegation_id"),
        "delegated_from_agent_id": selected("delegated_from_agent_id"),
        "delegated_to_agent_id": selected("delegated_to_agent_id"),
        "identity_binding_valid": _bool_value(selected("identity_binding_valid")),
        "data_lineage_id": selected("data_lineage_id"),
        "memory_id": selected("memory_id"),
        "memory_scope": selected("memory_scope"),
        "memory_provenance_valid": _bool_value(selected("memory_provenance_valid")),
        "memory_retention_valid": _bool_value(selected("memory_retention_valid")),
        "goal_id": selected("goal_id"),
        "goal_fingerprint": selected("goal_fingerprint"),
        "goal_integrity_valid": _bool_value(selected("goal_integrity_valid")),
        "goal_change_approved": _bool_value(selected("goal_change_approved")),
        "model_id": selected("model_id"),
        "mcp_client_id": selected("mcp_client_id"),
        "mcp_server_id": selected("mcp_server_id"),
        "auth_audience": selected("auth_audience"),
        "auth_resource": selected("auth_resource"),
        "auth_scopes": _tuple_value(selected("auth_scopes", ())),
        "auth_audience_valid": _bool_value(selected("auth_audience_valid")),
        "consent_valid": _bool_value(selected("consent_valid")),
        "policy_id": selected("policy_id"),
        "policy_version": selected("policy_version"),
        "policy_decision": selected("policy_decision"),
        "approval_id": selected("approval_id"),
        "approval_fingerprint": selected("approval_fingerprint"),
        "input_trust": selected("input_trust"),
        "taint_labels": _tuple_value(selected("taint_labels", ())),
        "outcome": selected("outcome"),
        "synthetic": bool(selected("synthetic", synthetic)),
        "content_recorded": False,
        "attributes": attributes,
    }
    return AgentTraceEvent(**kwargs)  # type: ignore[arg-type]


def mapping_catalog() -> dict[str, object]:
    """Return an inspectable profile and field catalog for CLI and GUI use."""

    profiles = []
    for profile in PORTABLE_PROFILES:
        native = NATIVE_FIELD_PATHS[profile]
        profiles.append(
            {
                "profile": profile,
                "version": PROFILE_VERSIONS[profile],
                "reference": PROFILE_REFERENCES[profile],
                "extension_namespace": (
                    "attributes.agentsim" if profile == "otel" else "agentsim" if profile == "ecs" else "unmapped.agentsim"
                ),
                "fields": [
                    {
                        "canonical": field,
                        "target": native.get(field),
                        "mapping": "native" if field in native else "extension",
                    }
                    for field in _CORE_FIELDS
                    if field != "content_recorded"
                ],
            }
        )
    return {
        "schema_version": MAPPING_SCHEMA_VERSION,
        "kind": "portable-mapping-catalog",
        "profiles": profiles,
        "content_values_recorded": False,
    }


__all__ = [
    "MAPPING_SCHEMA_VERSION",
    "NATIVE_FIELD_PATHS",
    "PORTABLE_PROFILES",
    "PROFILE_REFERENCES",
    "PROFILE_VERSIONS",
    "PortableMappingResult",
    "agent_trace_from_portable_record",
    "map_agent_trace",
    "mapping_catalog",
]
