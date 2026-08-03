"""Content-safe flight recording for live agent runtimes and OTLP exports.

The recorder keeps identity, topology, policy, tool, and outcome metadata. It
never calls an SDK span's general export method because those exports may
contain model inputs, function arguments, or tool results.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from agentsim.models.agent_trace import AgentTraceEvent, sanitize_agent_attributes
from agentsim.models.telemetry import NormalizedEvent
from agentsim.telemetry.agent_contract import agent_trace_from_record


FLIGHT_RECORDER_SCHEMA_VERSION = "1.0"
MAX_FLIGHT_EVENTS = 50_000
MAX_OTLP_SPANS = 25_000
CLASSIFICATIONS = frozenset({"malicious", "benign", "unknown"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _timestamp(value: object | None) -> str:
    if not isinstance(value, str) or not value:
        return _now()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return _now()
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _bounded(value: object | None, fallback: str) -> str:
    selected = str(value or fallback).strip() or fallback
    return selected[:512]


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _classification(value: object) -> str:
    selected = str(value)
    if selected not in CLASSIFICATIONS:
        raise ValueError("flight classification must be malicious, benign, or unknown")
    return selected


def _event_type(span_type: str) -> str:
    return {
        "agent": "agent.run.completed",
        "task": "agent.task.completed",
        "turn": "agent.turn.completed",
        "function": "agent.tool.completed",
        "computer": "agent.tool.completed",
        "handoff": "agent.delegation.completed",
        "guardrail": "agent.guardrail.checked",
        "generation": "gen_ai.inference.completed",
        "response": "gen_ai.response.completed",
        "custom": "agent.custom.observed",
        "transcription": "gen_ai.audio.completed",
        "speech": "gen_ai.audio.completed",
        "speech_group": "gen_ai.audio.completed",
    }.get(span_type, "agent.span.completed")


def _safe_span_attributes(span: object, span_data: object, span_type: str) -> dict[str, object]:
    """Select structural span metadata without serializing input or output fields."""

    values: dict[str, object] = {
        "span_type": span_type,
        "error_present": getattr(span, "error", None) is not None,
        "started_at_present": bool(getattr(span, "started_at", None)),
        "ended_at_present": bool(getattr(span, "ended_at", None)),
        "arguments_recorded": False,
        "result_recorded": False,
    }
    for name in (
        "name",
        "from_agent",
        "to_agent",
        "model",
        "triggered",
        "turn",
        "agent_name",
    ):
        observed = getattr(span_data, name, None)
        if observed not in (None, ""):
            values[name] = observed
    for name in ("handoffs", "tools"):
        observed = getattr(span_data, name, None)
        if isinstance(observed, Sequence) and not isinstance(observed, (str, bytes, bytearray)):
            values[f"{name}_count"] = min(len(observed), 1000)
    usage = getattr(span_data, "usage", None)
    if isinstance(usage, Mapping):
        for source, target in (
            ("input_tokens", "input_token_count"),
            ("output_tokens", "output_token_count"),
            ("total_tokens", "total_token_count"),
        ):
            if isinstance(usage.get(source), int) and usage[source] >= 0:
                values[target] = usage[source]
    metadata = getattr(span_data, "metadata", None)
    if isinstance(metadata, Mapping):
        values.update(sanitize_agent_attributes(metadata))
    trace_metadata = getattr(span, "trace_metadata", None)
    if isinstance(trace_metadata, Mapping):
        values.update(sanitize_agent_attributes(trace_metadata))
    error = getattr(span, "error", None)
    if isinstance(error, Mapping):
        values.update(
            {
                f"error_{key}": child
                for key, child in sanitize_agent_attributes(error).items()
                if key in {"type", "code"}
            }
        )
    return sanitize_agent_attributes(values)


@dataclass(frozen=True)
class FlightRecorderBundle:
    recorder_id: str
    source_runtime: str
    classification: str
    started_at: str
    ended_at: str
    events: tuple[AgentTraceEvent, ...]
    dropped_events: int = 0
    recording_errors: int = 0
    metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.recorder_id or len(self.recorder_id) > 512:
            raise ValueError("flight recorder_id must be a bounded non-empty string")
        if not self.source_runtime or len(self.source_runtime) > 512:
            raise ValueError("flight source_runtime must be a bounded non-empty string")
        _classification(self.classification)
        if len(self.events) > MAX_FLIGHT_EVENTS:
            raise ValueError(f"flight recorder bundles are limited to {MAX_FLIGHT_EVENTS} events")
        if self.dropped_events < 0 or self.recording_errors < 0:
            raise ValueError("flight recorder counters must be non-negative")
        object.__setattr__(self, "metadata", sanitize_agent_attributes(self.metadata))

    @property
    def normalized_events(self) -> tuple[NormalizedEvent, ...]:
        return tuple(event.to_normalized_event(collector="agent_runtime") for event in self.events)

    def to_dict(self) -> dict[str, object]:
        event_values = [event.to_dict() for event in self.events]
        traces = {event.trace_id for event in self.events}
        agents = {event.agent_id for event in self.events}
        body: dict[str, object] = {
            "schema_version": FLIGHT_RECORDER_SCHEMA_VERSION,
            "kind": "agent-security-flight-recorder",
            "recorder_id": self.recorder_id,
            "source_runtime": self.source_runtime,
            "classification": self.classification,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "summary": {
                "events": len(self.events),
                "traces": len(traces),
                "agents": len(agents),
                "dropped_events": self.dropped_events,
                "recording_errors": self.recording_errors,
                "event_types": sorted({event.event_type for event in self.events}),
            },
            "events": event_values,
            "metadata": dict(self.metadata),
            "sanitization": {
                "prompts_recorded": False,
                "messages_recorded": False,
                "tool_arguments_recorded": False,
                "tool_results_recorded": False,
                "credentials_recorded": False,
            },
            "content_values_recorded": False,
        }
        body["bundle_digest"] = _digest(body)
        return body

    def synthetic_twin(self) -> tuple[AgentTraceEvent, ...]:
        """Create a deterministic, pseudonymous, non-executing structural twin."""

        salt = self.recorder_id

        def alias(kind: str, value: str | None) -> str | None:
            if value is None:
                return None
            return f"{kind}-{hashlib.sha256(f'{salt}:{kind}:{value}'.encode()).hexdigest()[:20]}"

        event_ids = {event.event_id: alias("event", event.event_id) for event in self.events}
        values: list[AgentTraceEvent] = []
        for event in self.events:
            values.append(
                replace(
                    event,
                    event_id=str(event_ids[event.event_id]),
                    trace_id=str(alias("trace", event.trace_id)),
                    session_id=str(alias("session", event.session_id)),
                    conversation_id=alias("conversation", event.conversation_id),
                    agent_id=str(alias("agent", event.agent_id)),
                    agent_instance_id=alias("instance", event.agent_instance_id),
                    principal_id=alias("principal", event.principal_id),
                    turn_id=alias("turn", event.turn_id),
                    tool_call_id=alias("call", event.tool_call_id),
                    parent_event_id=event_ids.get(event.parent_event_id),
                    caused_by_event_ids=tuple(
                        str(event_ids[item])
                        for item in event.caused_by_event_ids
                        if item in event_ids
                    ),
                    delegation_id=alias("delegation", event.delegation_id),
                    delegated_from_agent_id=alias("agent", event.delegated_from_agent_id),
                    delegated_to_agent_id=alias("agent", event.delegated_to_agent_id),
                    data_lineage_id=alias("lineage", event.data_lineage_id),
                    memory_id=alias("memory", event.memory_id),
                    goal_id=alias("goal", event.goal_id),
                    mcp_client_id=alias("mcp-client", event.mcp_client_id),
                    mcp_server_id=alias("mcp-server", event.mcp_server_id),
                    approval_id=alias("approval", event.approval_id),
                    source="agent_runtime",
                    synthetic=True,
                    content_recorded=False,
                    attributes={
                        **event.attributes,
                        "synthetic_twin": True,
                        "source_runtime": self.source_runtime,
                        "source_event_digest": _digest(event.to_dict()),
                        "executed": False,
                    },
                )
            )
        return tuple(values)

    def write(self, path: str | Path) -> Path:
        candidate = Path(path)
        candidate.parent.mkdir(parents=True, exist_ok=True)
        candidate.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return candidate

    def write_synthetic_twin(self, path: str | Path) -> Path:
        candidate = Path(path)
        candidate.parent.mkdir(parents=True, exist_ok=True)
        candidate.write_text(
            "\n".join(json.dumps(event.to_dict(), sort_keys=True) for event in self.synthetic_twin())
            + ("\n" if self.events else ""),
            encoding="utf-8",
        )
        return candidate


class FlightRecorder:
    """Thread-safe bounded recorder used by SDK processors and local receivers."""

    def __init__(
        self,
        *,
        source_runtime: str,
        classification: str = "unknown",
        recorder_id: str | None = None,
        max_events: int = MAX_FLIGHT_EVENTS,
        metadata: Mapping[str, object] | None = None,
    ) -> None:
        if isinstance(max_events, bool) or not 1 <= max_events <= MAX_FLIGHT_EVENTS:
            raise ValueError(f"max_events must be between 1 and {MAX_FLIGHT_EVENTS}")
        self.recorder_id = _bounded(recorder_id, f"flight-{uuid.uuid4()}")
        self.source_runtime = _bounded(source_runtime, "unknown-runtime")
        self.classification = _classification(classification)
        self.max_events = max_events
        self.metadata = sanitize_agent_attributes(metadata or {})
        self.started_at = _now()
        self._events: list[AgentTraceEvent] = []
        self._event_ids: set[str] = set()
        self._dropped_events = 0
        self._recording_errors = 0
        self._lock = threading.Lock()

    def record(self, event: AgentTraceEvent) -> bool:
        with self._lock:
            if event.event_id in self._event_ids:
                return False
            if len(self._events) >= self.max_events:
                self._dropped_events += 1
                return False
            self._events.append(event)
            self._event_ids.add(event.event_id)
            return True

    def record_error(self) -> None:
        with self._lock:
            self._recording_errors += 1

    def ingest_records(
        self, records: Iterable[Mapping[str, object]], *, collector: str
    ) -> int:
        count = 0
        for record in records:
            if self.record(agent_trace_from_record(record, collector=collector)):
                count += 1
        return count

    def record_openai_trace(self, trace: object, *, ended: bool) -> bool:
        trace_id = _bounded(getattr(trace, "trace_id", None), f"trace-{uuid.uuid4()}")
        metadata = getattr(trace, "metadata", None)
        safe_metadata = sanitize_agent_attributes(metadata) if isinstance(metadata, Mapping) else {}
        group_id = _bounded(getattr(trace, "group_id", None), f"session-{trace_id[-20:]}")
        return self.record(
            AgentTraceEvent(
                timestamp=_now(),
                event_id=_bounded(
                    f"{trace_id}:{'end' if ended else 'start'}",
                    f"trace-boundary-{uuid.uuid4()}",
                ),
                event_type="agent.workflow.completed" if ended else "agent.workflow.started",
                trace_id=trace_id,
                session_id=group_id,
                agent_id=_bounded(safe_metadata.get("agent_id"), "openai-workflow"),
                source="openai_agents",
                outcome="success" if ended else "started",
                content_recorded=False,
                attributes={
                    **safe_metadata,
                    "workflow_name": _bounded(
                        getattr(trace, "name", None)
                        or getattr(trace, "workflow_name", None),
                        "agent-workflow",
                    ),
                    "trace_boundary": "end" if ended else "start",
                },
            )
        )

    def record_openai_span(self, span: object) -> bool:
        span_data = getattr(span, "span_data", None)
        span_type = _bounded(getattr(span_data, "type", None), "unknown").casefold()
        attributes = _safe_span_attributes(span, span_data, span_type)
        trace_id = _bounded(getattr(span, "trace_id", None), f"trace-{uuid.uuid4()}")
        span_id = _bounded(getattr(span, "span_id", None), f"span-{uuid.uuid4()}")
        name = getattr(span_data, "name", None)
        from_agent = getattr(span_data, "from_agent", None)
        to_agent = getattr(span_data, "to_agent", None)
        tool_name = name if span_type in {"function", "computer"} else None
        model_id = getattr(span_data, "model", None) if span_type in {"generation", "response"} else None
        agent_id = (
            name
            if span_type == "agent"
            else getattr(span_data, "agent_name", None)
            or attributes.get("agent_id")
            or "openai-agent"
        )
        return self.record(
            AgentTraceEvent(
                timestamp=_timestamp(getattr(span, "ended_at", None) or getattr(span, "started_at", None)),
                event_id=span_id,
                event_type=_event_type(span_type),
                trace_id=trace_id,
                session_id=_bounded(attributes.get("group_id"), f"session-{trace_id[-20:]}"),
                agent_id=_bounded(agent_id, "openai-agent"),
                tool_call_id=span_id if tool_name else None,
                tool_name=_bounded(tool_name, "tool") if tool_name else None,
                parent_event_id=_bounded(getattr(span, "parent_id", None), "") or None,
                delegation_id=span_id if span_type == "handoff" else None,
                delegated_from_agent_id=_bounded(from_agent, "") or None,
                delegated_to_agent_id=_bounded(to_agent, "") or None,
                model_id=_bounded(model_id, "") or None,
                source="openai_agents",
                outcome="failed" if getattr(span, "error", None) is not None else "success",
                content_recorded=False,
                attributes=attributes,
            )
        )

    def ingest_otlp_export(self, payload: Mapping[str, object]) -> int:
        records = otlp_records(payload)
        if len(records) > MAX_OTLP_SPANS:
            raise ValueError(f"OTLP export exceeds the {MAX_OTLP_SPANS} span limit")
        return self.ingest_records(records, collector="otel_genai")

    def snapshot(self) -> FlightRecorderBundle:
        with self._lock:
            return FlightRecorderBundle(
                recorder_id=self.recorder_id,
                source_runtime=self.source_runtime,
                classification=self.classification,
                started_at=self.started_at,
                ended_at=_now(),
                events=tuple(self._events),
                dropped_events=self._dropped_events,
                recording_errors=self._recording_errors,
                metadata=self.metadata,
            )


class AgentSimTraceProcessor:
    """Duck-typed OpenAI Agents SDK ``TracingProcessor`` implementation.

    ``add_trace_processor(AgentSimTraceProcessor(...))`` works without making
    the OpenAI Agents SDK a required AgentSim dependency.
    """

    def __init__(
        self,
        recorder: FlightRecorder | None = None,
        *,
        output_path: str | Path | None = None,
        classification: str = "unknown",
    ) -> None:
        self.recorder = recorder or FlightRecorder(
            source_runtime="openai-agents", classification=classification
        )
        self.output_path = Path(output_path) if output_path else None

    def _guard(self, operation: Any) -> None:
        try:
            operation()
        except Exception:  # SDK processors must not raise into the agent loop.
            self.recorder.record_error()

    def on_trace_start(self, trace: object) -> None:
        self._guard(lambda: self.recorder.record_openai_trace(trace, ended=False))

    def on_trace_end(self, trace: object) -> None:
        self._guard(lambda: self.recorder.record_openai_trace(trace, ended=True))
        self.force_flush()

    def on_span_start(self, span: object) -> None:
        return None

    def on_span_end(self, span: object) -> None:
        self._guard(lambda: self.recorder.record_openai_span(span))

    def force_flush(self) -> None:
        if self.output_path is not None:
            self._guard(lambda: self.recorder.snapshot().write(self.output_path))

    def shutdown(self) -> None:
        self.force_flush()


def attach_to_openai_agents(processor: AgentSimTraceProcessor) -> AgentSimTraceProcessor:
    """Register the processor when the optional ``openai-agents`` package exists."""

    try:
        from agents import add_trace_processor  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError("install openai-agents before attaching the AgentSim processor") from exc
    add_trace_processor(processor)
    return processor


def _otlp_value(value: object) -> object:
    if not isinstance(value, Mapping):
        return value
    for key in ("stringValue", "intValue", "doubleValue", "boolValue"):
        if key in value:
            observed = value[key]
            if key == "intValue":
                try:
                    return int(str(observed))
                except ValueError:
                    return 0
            return observed
    array = value.get("arrayValue")
    if isinstance(array, Mapping) and isinstance(array.get("values"), Sequence):
        return tuple(_otlp_value(item) for item in array["values"][:50])
    mapping = value.get("kvlistValue")
    if isinstance(mapping, Mapping):
        return _otlp_attributes(mapping.get("values"))
    return None


def _otlp_attributes(value: object) -> dict[str, object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return {}
    attributes: dict[str, object] = {}
    for item in value[:100]:
        if not isinstance(item, Mapping) or not isinstance(item.get("key"), str):
            continue
        attributes[str(item["key"])] = _otlp_value(item.get("value"))
    return sanitize_agent_attributes(attributes)


def _nanos_timestamp(value: object) -> str:
    try:
        nanos = int(str(value))
    except (TypeError, ValueError):
        return _now()
    return datetime.fromtimestamp(nanos / 1_000_000_000, tz=timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def otlp_records(payload: Mapping[str, object]) -> tuple[Mapping[str, object], ...]:
    """Flatten an OTLP/HTTP JSON trace export without retaining content attributes."""

    resource_spans = payload.get("resourceSpans", ())
    if not isinstance(resource_spans, Sequence) or isinstance(
        resource_spans, (str, bytes, bytearray)
    ):
        raise ValueError("OTLP resourceSpans must be an array")
    records: list[Mapping[str, object]] = []
    for resource_item in resource_spans:
        if not isinstance(resource_item, Mapping):
            raise ValueError("OTLP resourceSpans entries must be objects")
        resource = resource_item.get("resource", {})
        resource_attributes = _otlp_attributes(
            resource.get("attributes") if isinstance(resource, Mapping) else ()
        )
        scopes = resource_item.get("scopeSpans", ())
        if not isinstance(scopes, Sequence) or isinstance(scopes, (str, bytes, bytearray)):
            raise ValueError("OTLP scopeSpans must be an array")
        for scope_item in scopes:
            if not isinstance(scope_item, Mapping):
                raise ValueError("OTLP scopeSpans entries must be objects")
            scope = scope_item.get("scope", {})
            scope_name = scope.get("name") if isinstance(scope, Mapping) else None
            spans = scope_item.get("spans", ())
            if not isinstance(spans, Sequence) or isinstance(spans, (str, bytes, bytearray)):
                raise ValueError("OTLP spans must be an array")
            for span in spans:
                if not isinstance(span, Mapping):
                    raise ValueError("OTLP spans entries must be objects")
                attributes = {**resource_attributes, **_otlp_attributes(span.get("attributes"))}
                if scope_name:
                    attributes["otel_scope_name"] = str(scope_name)[:512]
                status = span.get("status", {})
                status_code = status.get("code") if isinstance(status, Mapping) else None
                records.append(
                    {
                        "timestamp": _nanos_timestamp(
                            span.get("endTimeUnixNano") or span.get("startTimeUnixNano")
                        ),
                        "span_id": span.get("spanId"),
                        "trace_id": span.get("traceId"),
                        "parent_span_id": span.get("parentSpanId"),
                        "name": span.get("name") or "span",
                        "service.name": attributes.get("service.name", "otel-agent"),
                        "status": "failed" if status_code in {"STATUS_CODE_ERROR", 2, "2"} else "success",
                        "attributes": attributes,
                    }
                )
                if len(records) > MAX_OTLP_SPANS:
                    raise ValueError(f"OTLP export exceeds the {MAX_OTLP_SPANS} span limit")
    return tuple(records)


def flight_bundle_from_mapping(value: Mapping[str, object]) -> FlightRecorderBundle:
    allowed = {
        "schema_version",
        "kind",
        "recorder_id",
        "source_runtime",
        "classification",
        "started_at",
        "ended_at",
        "summary",
        "events",
        "metadata",
        "sanitization",
        "content_values_recorded",
        "bundle_digest",
    }
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"unknown flight recorder bundle fields: {', '.join(unknown)}")
    if value.get("schema_version") != FLIGHT_RECORDER_SCHEMA_VERSION:
        raise ValueError(f"unsupported flight recorder schema: {value.get('schema_version')}")
    if value.get("kind") != "agent-security-flight-recorder":
        raise ValueError("invalid flight recorder bundle kind")
    if value.get("content_values_recorded") is not False:
        raise ValueError("flight recorder bundles must declare content_values_recorded false")
    raw_events = value.get("events", ())
    if not isinstance(raw_events, Sequence) or isinstance(raw_events, (str, bytes, bytearray)):
        raise ValueError("flight recorder events must be an array")
    if len(raw_events) > MAX_FLIGHT_EVENTS:
        raise ValueError(f"flight recorder bundles are limited to {MAX_FLIGHT_EVENTS} events")
    events: list[AgentTraceEvent] = []
    for item in raw_events:
        if not isinstance(item, Mapping):
            raise ValueError("flight recorder events must be objects")
        raw = {key: child for key, child in item.items() if key != "schema_version"}
        events.append(AgentTraceEvent(**raw))  # type: ignore[arg-type]
    summary = value.get("summary", {})
    metadata = value.get("metadata", {})
    if not isinstance(summary, Mapping) or not isinstance(metadata, Mapping):
        raise ValueError("flight recorder summary and metadata must be objects")
    counters: dict[str, int] = {}
    for name in ("dropped_events", "recording_errors"):
        observed = summary.get(name, 0)
        if isinstance(observed, bool) or not isinstance(observed, int) or observed < 0:
            raise ValueError(f"flight recorder summary.{name} must be a non-negative integer")
        counters[name] = observed
    bundle = FlightRecorderBundle(
        recorder_id=_bounded(value.get("recorder_id"), "flight-imported"),
        source_runtime=_bounded(value.get("source_runtime"), "unknown-runtime"),
        classification=_classification(value.get("classification", "unknown")),
        started_at=_timestamp(value.get("started_at")),
        ended_at=_timestamp(value.get("ended_at")),
        events=tuple(events),
        dropped_events=counters["dropped_events"],
        recording_errors=counters["recording_errors"],
        metadata=metadata,
    )
    expected = value.get("bundle_digest")
    if isinstance(expected, str):
        body = dict(value)
        body.pop("bundle_digest", None)
        if _digest(body) != expected:
            raise ValueError("flight recorder bundle digest does not match its content")
    return bundle


def load_flight_bundle(path: str | Path) -> FlightRecorderBundle:
    candidate = Path(path)
    if not candidate.is_file():
        raise FileNotFoundError(f"flight recorder bundle does not exist: {candidate}")
    if candidate.stat().st_size > 256 * 1024 * 1024:
        raise ValueError("flight recorder bundle exceeds the 256 MiB limit")
    value = json.loads(candidate.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("flight recorder bundle must be a JSON object")
    return flight_bundle_from_mapping(value)


__all__ = [
    "AgentSimTraceProcessor",
    "FlightRecorder",
    "FlightRecorderBundle",
    "attach_to_openai_agents",
    "flight_bundle_from_mapping",
    "load_flight_bundle",
    "otlp_records",
]
