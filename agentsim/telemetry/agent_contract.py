"""Adapters from common agent/MCP telemetry shapes to the AgentSim contract."""

from __future__ import annotations

import hashlib
import json
from typing import Iterable, Mapping, Sequence

from agentsim.models.agent_trace import AgentTraceEvent, sanitize_agent_attributes
from agentsim.models.telemetry import NormalizedEvent

from .normalization import normalize_record


AGENT_COLLECTOR_NAMES = ("agent_runtime", "otel_genai", "mcp_audit")

_ALIASES: Mapping[str, tuple[str, ...]] = {
    "timestamp": ("timestamp", "@timestamp", "timeUnixNano", "start_time"),
    "event_id": ("event_id", "event.id", "span_id", "id"),
    "event_type": ("event_type", "event.name", "name", "gen_ai.operation.name", "method"),
    "trace_id": ("trace_id", "trace.id", "context.trace_id"),
    "session_id": ("session_id", "session.id", "gen_ai.conversation.id", "conversation_id"),
    "conversation_id": ("conversation_id", "gen_ai.conversation.id"),
    "agent_id": ("agent_id", "agent.id", "gen_ai.agent.id", "service.name"),
    "agent_instance_id": ("agent_instance_id", "service.instance.id"),
    "principal_id": ("principal_id", "user.id", "enduser.id", "actor.id"),
    "turn_id": ("turn_id", "gen_ai.turn.id"),
    "tool_call_id": ("tool_call_id", "gen_ai.tool.call.id", "mcp.request.id"),
    "tool_name": ("tool_name", "gen_ai.tool.name", "mcp.tool.name", "params.name"),
    "tool_risk": ("tool_risk", "agent.tool.risk"),
    "parent_event_id": ("parent_event_id", "parent_span_id", "event.parent_id"),
    "delegation_id": ("delegation_id", "agent.delegation.id"),
    "data_lineage_id": ("data_lineage_id", "gen_ai.data_source.id"),
    "memory_id": ("memory_id", "agent.memory.id"),
    "model_id": ("model_id", "gen_ai.response.model", "gen_ai.request.model"),
    "mcp_client_id": ("mcp_client_id", "mcp.client.id", "client_id"),
    "mcp_server_id": ("mcp_server_id", "mcp.server.id", "server_id"),
    "auth_audience": ("auth_audience", "auth.audience", "token_audience", "audience"),
    "auth_resource": ("auth_resource", "auth.resource", "resource"),
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
    "outcome": ("outcome", "event.outcome", "status"),
}

_SAFE_ATTRIBUTE_ALIASES: Mapping[str, tuple[str, ...]] = {
    "input_token_count": ("gen_ai.usage.input_tokens", "usage.input_tokens"),
    "output_token_count": ("gen_ai.usage.output_tokens", "usage.output_tokens"),
    "error_type": ("error.type",),
    "server_address": ("server.address",),
    "budget_remaining": ("agent.budget.remaining", "budget_remaining"),
    "delegation_depth": ("agent.delegation.depth", "delegation_depth"),
    "arguments_recorded": ("arguments_recorded",),
    "result_recorded": ("result_recorded",),
}


def _path(value: Mapping[str, object], name: str) -> object:
    current: object = value
    for part in name.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current[part]
    return current


def _first(value: Mapping[str, object], names: Sequence[str]) -> object:
    for name in names:
        observed = value.get(name) if name in value else _path(value, name)
        if observed not in (None, ""):
            return observed
    attributes = value.get("attributes")
    if isinstance(attributes, Mapping):
        for name in names:
            observed = attributes.get(name)
            if observed not in (None, ""):
                return observed
    return None


def _identifier(record: Mapping[str, object], prefix: str) -> str:
    safe = sanitize_agent_attributes(record)
    digest = hashlib.sha256(
        json.dumps(safe, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:24]
    return f"{prefix}-{digest}"


def _event_type(value: object, collector: str) -> str:
    selected = str(value or "observation").strip().replace("/", ".").replace(" ", "_")
    if selected.startswith(("agent.", "gen_ai.", "mcp.")):
        return selected
    if collector == "mcp_audit" or selected.startswith(("tools.", "resources.", "prompts.")):
        return f"mcp.{selected}"
    if collector == "otel_genai":
        return f"gen_ai.{selected}"
    return f"agent.{selected}"


def _string(record: Mapping[str, object], name: str) -> str | None:
    observed = _first(record, _ALIASES[name])
    return str(observed) if observed not in (None, "") else None


def _strings(record: Mapping[str, object], name: str) -> tuple[str, ...]:
    observed = _first(record, _ALIASES[name])
    if observed is None:
        return ()
    if isinstance(observed, Sequence) and not isinstance(observed, (str, bytes, bytearray)):
        return tuple(str(item) for item in observed[:50])
    return tuple(part for part in str(observed).replace(",", " ").split() if part)[:50]


def _boolean(record: Mapping[str, object], name: str) -> bool | None:
    observed = _first(record, _ALIASES[name])
    if isinstance(observed, bool):
        return observed
    if isinstance(observed, str) and observed.casefold() in {"true", "false"}:
        return observed.casefold() == "true"
    return None


def agent_trace_from_record(
    record: Mapping[str, object], *, collector: str = "agent_runtime", synthetic: bool = False
) -> AgentTraceEvent:
    """Project a runtime record without retaining prompts, arguments, results, or tokens."""

    if collector not in AGENT_COLLECTOR_NAMES:
        raise ValueError(f"unsupported agent telemetry profile: {collector}")
    generic = normalize_record(record, collector="otel" if collector == "otel_genai" else "agent_runtime")
    event_id = _string(record, "event_id") or generic.source_record_id or _identifier(record, "event")
    trace_id = _string(record, "trace_id") or _identifier(record, "trace")
    attributes: dict[str, object] = {}
    raw_attributes = record.get("attributes")
    if isinstance(raw_attributes, Mapping):
        attributes.update(sanitize_agent_attributes(raw_attributes))
    for canonical, aliases in _SAFE_ATTRIBUTE_ALIASES.items():
        observed = _first(record, aliases)
        if observed is not None:
            attributes[canonical] = observed
    attributes["arguments_recorded"] = False
    attributes["result_recorded"] = False
    return AgentTraceEvent(
        timestamp=generic.timestamp,
        event_id=event_id,
        event_type=_event_type(_first(record, _ALIASES["event_type"]), collector),
        trace_id=trace_id,
        session_id=_string(record, "session_id") or f"session-{trace_id[-12:]}",
        conversation_id=_string(record, "conversation_id"),
        agent_id=_string(record, "agent_id") or "unknown-agent",
        agent_instance_id=_string(record, "agent_instance_id"),
        principal_id=_string(record, "principal_id"),
        turn_id=_string(record, "turn_id"),
        tool_call_id=_string(record, "tool_call_id"),
        tool_name=_string(record, "tool_name"),
        tool_risk=_string(record, "tool_risk"),
        parent_event_id=_string(record, "parent_event_id"),
        delegation_id=_string(record, "delegation_id"),
        data_lineage_id=_string(record, "data_lineage_id"),
        memory_id=_string(record, "memory_id"),
        model_id=_string(record, "model_id"),
        mcp_client_id=_string(record, "mcp_client_id"),
        mcp_server_id=_string(record, "mcp_server_id"),
        auth_audience=_string(record, "auth_audience"),
        auth_resource=_string(record, "auth_resource"),
        auth_scopes=_strings(record, "auth_scopes"),
        auth_audience_valid=_boolean(record, "auth_audience_valid"),
        consent_valid=_boolean(record, "consent_valid"),
        policy_id=_string(record, "policy_id"),
        policy_version=_string(record, "policy_version"),
        policy_decision=_string(record, "policy_decision"),
        approval_id=_string(record, "approval_id"),
        approval_fingerprint=_string(record, "approval_fingerprint"),
        input_trust=_string(record, "input_trust"),
        taint_labels=_strings(record, "taint_labels"),
        outcome=_string(record, "outcome"),
        source="mcp" if collector == "mcp_audit" else "agent_runtime",
        synthetic=synthetic,
        content_recorded=False,
        attributes=attributes,
    )


def normalize_agent_records(
    records: Iterable[Mapping[str, object]], *, collector: str, synthetic: bool = False
) -> tuple[NormalizedEvent, ...]:
    return tuple(
        agent_trace_from_record(record, collector=collector, synthetic=synthetic).to_normalized_event(
            collector=collector
        )
        for record in records
    )
