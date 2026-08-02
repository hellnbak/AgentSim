"""Vendor-neutral normalization with secret-safe field projection."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterable, Mapping, Sequence

from agentsim.models.telemetry import NormalizedEvent


SENSITIVE_TERMS = (
    "authorization",
    "bearer",
    "credential",
    "password",
    "payload",
    "prompt",
    "secret",
    "token",
)

CANONICAL_ALIASES: Mapping[str, tuple[str, ...]] = {
    "timestamp": (
        "timestamp",
        "@timestamp",
        "TimeGenerated",
        "event.created",
        "event.ingested",
        "CreationUtcTime",
    ),
    "source": ("source", "data_source", "event.dataset", "event.module", "SourceName"),
    "event_type": ("event_type", "event.action", "event.category", "EventType", "name"),
    "record_id": ("record_id", "event_id", "event.id", "id", "EventRecordID", "_id"),
    "host_id": ("host_id", "host.id", "host.name", "Computer", "aid", "device_id"),
    "user_id": ("user_id", "user.id", "user.name", "User", "AccountName"),
    "process_name": (
        "process_name",
        "process.name",
        "Image",
        "FileName",
        "event_simpleName",
    ),
    "command_line": ("command_line", "process.command_line", "CommandLine", "ProcessCommandLine"),
    "process_id": ("process_id", "process.pid", "ProcessId", "TargetProcessId"),
    "parent_process_name": (
        "parent_process_name",
        "process.parent.name",
        "ParentImage",
        "ParentBaseFileName",
    ),
    "parent_process_id": (
        "parent_process_id",
        "process.parent.pid",
        "ParentProcessId",
        "ParentProcessId_decimal",
    ),
    "session_id": ("session_id", "session.id", "ContextProcessId", "trace_id"),
    "agent_id": ("agent_id", "agent.id", "service.name", "AgentId"),
    "principal_id": ("principal_id", "user.id", "user_identity.principalId", "actor.id"),
    "resource": ("resource", "resource.id", "requestParameters.resource", "object.id"),
    "action": ("action", "event.action", "eventName", "operationName", "OperationName"),
    "outcome": ("outcome", "event.outcome", "status", "result", "ResultType"),
    "run_id": ("run_id", "agentsim.run_id", "attributes.run_id"),
    "ability_id": ("ability_id", "agentsim.ability_id", "attributes.ability_id"),
    "parent_event_id": ("parent_event_id", "event.parent_id", "caused_by"),
    "caused_by_event_ids": ("caused_by_event_ids", "event.caused_by_ids"),
    "trace_id": ("trace_id", "trace.id", "TraceId"),
    "conversation_id": ("conversation_id", "gen_ai.conversation.id"),
    "turn_id": ("turn_id", "gen_ai.turn.id"),
    "tool_call_id": ("tool_call_id", "gen_ai.tool.call.id", "mcp.request.id"),
    "tool_name": ("tool_name", "gen_ai.tool.name", "mcp.tool.name"),
    "tool_risk": ("tool_risk", "agent.tool.risk"),
    "delegation_id": ("delegation_id", "agent.delegation.id"),
    "delegated_from_agent_id": ("delegated_from_agent_id", "agent.delegation.from_agent.id"),
    "delegated_to_agent_id": ("delegated_to_agent_id", "agent.delegation.to_agent.id"),
    "identity_binding_valid": ("identity_binding_valid", "agent.identity.binding_valid"),
    "data_lineage_id": ("data_lineage_id", "gen_ai.data_source.id"),
    "memory_id": ("memory_id", "agent.memory.id"),
    "memory_scope": ("memory_scope", "agent.memory.scope"),
    "memory_provenance_valid": ("memory_provenance_valid", "agent.memory.provenance_valid"),
    "memory_retention_valid": ("memory_retention_valid", "agent.memory.retention_valid"),
    "goal_id": ("goal_id", "agent.goal.id"),
    "goal_fingerprint": ("goal_fingerprint", "agent.goal.fingerprint"),
    "goal_integrity_valid": ("goal_integrity_valid", "agent.goal.integrity_valid"),
    "goal_change_approved": ("goal_change_approved", "agent.goal.change_approved"),
    "model_id": ("model_id", "gen_ai.response.model", "gen_ai.request.model"),
    "mcp_client_id": ("mcp_client_id", "mcp.client.id"),
    "mcp_server_id": ("mcp_server_id", "mcp.server.id"),
    "auth_audience": ("auth_audience", "auth.audience", "audience"),
    "auth_resource": ("auth_resource", "auth.resource"),
    "auth_scopes": ("auth_scopes", "auth.scopes", "scopes"),
    "auth_audience_valid": ("auth_audience_valid", "auth.audience_valid", "audience_valid"),
    "consent_valid": ("consent_valid", "auth.consent_valid", "per_client_consent"),
    "policy_id": ("policy_id", "agent.policy.id"),
    "policy_version": ("policy_version", "agent.policy.version"),
    "policy_decision": ("policy_decision", "agent.policy.decision"),
    "approval_id": ("approval_id", "agent.approval.id"),
    "approval_fingerprint": ("approval_fingerprint", "agent.approval.fingerprint"),
    "input_trust": ("input_trust", "agent.input.trust"),
    "taint_labels": ("taint_labels", "agent.taint.labels"),
    "input_token_count": ("input_token_count", "gen_ai.usage.input_tokens"),
    "output_token_count": ("output_token_count", "gen_ai.usage.output_tokens"),
}

PROFILE_ALIASES: Mapping[str, Mapping[str, tuple[str, ...]]] = {
    "sysmon": {"source": ("Channel",), "event_type": ("EventID",)},
    "auditd": {"source": ("type",), "event_type": ("record_type", "type")},
    "cloudtrail": {
        "source": ("eventSource",),
        "event_type": ("eventType", "eventName"),
        "timestamp": ("eventTime",),
    },
    "crowdstrike": {
        "source": ("event_platform", "event_simpleName"),
        "timestamp": ("@timestamp", "timestamp"),
    },
    "splunk": {"timestamp": ("_time",), "source": ("sourcetype", "source")},
    "elastic": {"timestamp": ("@timestamp",), "source": ("event.dataset",)},
    "sentinel": {"timestamp": ("TimeGenerated",), "source": ("Type", "SourceSystem")},
    "logscale": {"timestamp": ("@timestamp", "timestamp"), "source": ("#repo", "event_platform")},
    "panther": {"timestamp": ("p_event_time", "timestamp"), "source": ("p_log_type",)},
    "graylog": {"timestamp": ("timestamp",), "source": ("source",)},
    "otel": {
        "timestamp": ("timeUnixNano", "observedTimeUnixNano"),
        "event_type": ("name",),
    },
    "agent_runtime": {"source": ("event_source",), "event_type": ("event_type",)},
}


def _get_path(value: Mapping[str, object], path: str) -> object:
    if path in value:
        return value[path]
    current: object = value
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current[part]
    return current


def _first(value: Mapping[str, object], paths: Sequence[str]) -> object:
    for path in paths:
        observed = _get_path(value, path)
        if observed not in (None, ""):
            return observed
    return None


def _timestamp_with_status(value: object) -> tuple[str, bool, bool]:
    present = value not in (None, "")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        numeric = float(value)
        if numeric > 10**14:
            numeric /= 10**9
        elif numeric > 10**11:
            numeric /= 1000
        try:
            rendered = datetime.fromtimestamp(numeric, tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), present, False
        return rendered.replace("+00:00", "Z"), present, True
    if isinstance(value, str) and value.strip():
        candidate = value.strip()
        if candidate.isdigit():
            return _timestamp_with_status(int(candidate))
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), True, False
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"), True, True
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), present, False


def _timestamp(value: object) -> str:
    return _timestamp_with_status(value)[0]


def _safe_scalar(value: object) -> object:
    if isinstance(value, str):
        return value[:2000]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return tuple(_safe_scalar(item) for item in value[:25])
    return json.dumps(value, sort_keys=True, default=str)[:500]


def _available_paths(value: Mapping[str, object], prefix: str = "") -> list[str]:
    observed: list[str] = []
    for key, item in value.items():
        name = f"{prefix}.{key}" if prefix else str(key)
        if any(term in name.lower() for term in SENSITIVE_TERMS):
            continue
        observed.append(name)
        if isinstance(item, Mapping):
            observed.extend(_available_paths(item, name))
    return observed


def normalize_record(
    record: Mapping[str, object], *, collector: str = "jsonl", synthetic: bool = False
) -> NormalizedEvent:
    """Normalize one record while discarding prompt, token, secret, and payload fields."""

    profile = PROFILE_ALIASES.get(collector, {})
    values: dict[str, object] = {}
    for canonical, aliases in CANONICAL_ALIASES.items():
        paths = tuple(profile.get(canonical, ())) + tuple(aliases)
        observed = _first(record, paths)
        if observed is not None and canonical not in {"timestamp", "source", "event_type", "record_id"}:
            values[canonical] = _safe_scalar(observed)
    source = _first(record, tuple(profile.get("source", ())) + CANONICAL_ALIASES["source"])
    event_type = _first(
        record, tuple(profile.get("event_type", ())) + CANONICAL_ALIASES["event_type"]
    )
    timestamp = _first(
        record, tuple(profile.get("timestamp", ())) + CANONICAL_ALIASES["timestamp"]
    )
    record_id = _first(record, CANONICAL_ALIASES["record_id"])
    normalized_timestamp, timestamp_present, timestamp_valid = _timestamp_with_status(timestamp)
    return NormalizedEvent(
        timestamp=normalized_timestamp,
        source=str(source or collector),
        event_type=str(event_type or "unknown"),
        fields=values,
        available_fields=tuple(
            sorted(
                set(_available_paths(record))
                | set(values)
                | {"timestamp", "source", "event_type"}
            )
        ),
        collector=collector,
        synthetic=synthetic,
        source_record_id=str(record_id) if record_id is not None else None,
        metadata={
            "redacted": True,
            "timestamp_present": timestamp_present,
            "timestamp_valid": timestamp_valid,
            "source_record_id_present": record_id is not None,
        },
    )


def normalize_records(
    records: Iterable[Mapping[str, object]], *, collector: str = "jsonl", synthetic: bool = False
) -> tuple[NormalizedEvent, ...]:
    return tuple(
        normalize_record(record, collector=collector, synthetic=synthetic) for record in records
    )
