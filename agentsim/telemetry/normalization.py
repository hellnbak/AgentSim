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
    "record_id": ("event.id", "id", "EventRecordID", "_id"),
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
    "otel": {
        "timestamp": ("timeUnixNano", "observedTimeUnixNano"),
        "event_type": ("name",),
    },
    "agent_runtime": {"source": ("event_source",), "event_type": ("event_type",)},
}


def _get_path(value: Mapping[str, object], path: str) -> object:
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


def _timestamp(value: object) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        numeric = float(value)
        if numeric > 10**14:
            numeric /= 10**9
        elif numeric > 10**11:
            numeric /= 1000
        return datetime.fromtimestamp(numeric, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, str) and value.strip():
        candidate = value.strip()
        if candidate.isdigit():
            return _timestamp(int(candidate))
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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
    return NormalizedEvent(
        timestamp=_timestamp(timestamp),
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
        metadata={"redacted": True},
    )


def normalize_records(
    records: Iterable[Mapping[str, object]], *, collector: str = "jsonl", synthetic: bool = False
) -> tuple[NormalizedEvent, ...]:
    return tuple(
        normalize_record(record, collector=collector, synthetic=synthetic) for record in records
    )
