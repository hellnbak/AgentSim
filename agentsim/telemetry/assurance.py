"""Trust and correlation checks for normalized defensive telemetry."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Mapping, Sequence

from agentsim.models.telemetry import NormalizedEvent


_AGENT_SOURCES = frozenset({"agent_runtime", "mcp"})
_CONTENT_TERMS = (
    "argument",
    "completion",
    "credential",
    "document",
    "instruction",
    "message",
    "password",
    "payload",
    "prompt",
    "reasoning",
    "response",
    "result",
    "secret",
    "text",
)
_SAFE_CONTENT_SUFFIXES = ("_present", "_recorded", "_count", "_fingerprint", "_valid")
_SEVERITY_PENALTY = {"low": 2, "medium": 6, "high": 14, "critical": 30}


@dataclass(frozen=True)
class AssuranceFinding:
    code: str
    severity: str
    title: str
    detail: str
    count: int
    event_indexes: tuple[int, ...]
    remediation: str

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "count": self.count,
            "event_indexes": list(self.event_indexes),
            "remediation": self.remediation,
        }


@dataclass(frozen=True)
class TelemetryAssuranceReport:
    status: str
    score: int
    record_count: int
    trace_count: int
    metrics: Mapping[str, object]
    findings: tuple[AssuranceFinding, ...]

    def to_dict(self) -> dict[str, object]:
        counts = {severity: 0 for severity in ("critical", "high", "medium", "low")}
        for finding in self.findings:
            counts[finding.severity] += 1
        return {
            "schema_version": "1.0",
            "kind": "telemetry-assurance-report",
            "status": self.status,
            "score": self.score,
            "record_count": self.record_count,
            "trace_count": self.trace_count,
            "finding_counts": counts,
            "metrics": dict(self.metrics),
            "findings": [finding.to_dict() for finding in self.findings],
            "content_values_recorded": any(
                finding.code == "raw_content_exposed" for finding in self.findings
            ),
        }


class _Findings:
    def __init__(self) -> None:
        self._items: dict[str, dict[str, object]] = {}

    def add(
        self,
        code: str,
        severity: str,
        title: str,
        detail: str,
        remediation: str,
        index: int | None = None,
    ) -> None:
        item = self._items.setdefault(
            code,
            {
                "severity": severity,
                "title": title,
                "detail": detail,
                "remediation": remediation,
                "count": 0,
                "event_indexes": [],
            },
        )
        item["count"] = int(item["count"]) + 1
        indexes = item["event_indexes"]
        if index is not None and isinstance(indexes, list) and len(indexes) < 25:
            indexes.append(index)

    def values(self) -> tuple[AssuranceFinding, ...]:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings = [
            AssuranceFinding(
                code,
                str(value["severity"]),
                str(value["title"]),
                str(value["detail"]),
                int(value["count"]),
                tuple(value["event_indexes"]),  # type: ignore[arg-type]
                str(value["remediation"]),
            )
            for code, value in self._items.items()
        ]
        return tuple(sorted(findings, key=lambda item: (order[item.severity], item.code)))


def _timestamp(value: str) -> float | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _many(value: object) -> tuple[str, ...]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return tuple(str(item) for item in value if item not in (None, ""))
    return (str(value),) if value not in (None, "") else ()


def _content_field(name: str) -> bool:
    lowered = name.casefold()
    return any(term in lowered for term in _CONTENT_TERMS) and not lowered.endswith(
        _SAFE_CONTENT_SUFFIXES
    )


def assess_telemetry(events: Iterable[NormalizedEvent]) -> TelemetryAssuranceReport:
    """Assess whether normalized evidence is safe and correlation-ready."""

    values = tuple(events)
    findings = _Findings()
    if not values:
        findings.add(
            "empty_export",
            "critical",
            "Telemetry export is empty",
            "No records are available for detection or correlation.",
            "Verify the export window, dataset, permissions, and collector profile.",
        )

    identities: dict[str, int] = {}
    trace_ids: set[str] = set()
    timestamps: list[float | None] = []
    causal_edge_count = 0
    broken_edge_count = 0
    agent_event_count = 0
    agent_identity_complete = 0

    for index, event in enumerate(values):
        parsed_timestamp = _timestamp(event.timestamp)
        timestamps.append(parsed_timestamp)
        if "timestamp_valid" not in event.metadata:
            findings.add(
                "timestamp_provenance_unknown",
                "medium",
                "Timestamp provenance is unknown",
                "The event has a timestamp but does not say whether it came from the source or a fallback.",
                "Normalize the record with a v1.3 collector that records timestamp presence and validity.",
                index,
            )
        elif parsed_timestamp is None or event.metadata.get("timestamp_valid") is False:
            findings.add(
                "invalid_or_substituted_timestamp",
                "high",
                "Timestamp was invalid or substituted",
                "At least one event cannot preserve trustworthy temporal ordering.",
                "Fix the source timestamp mapping and retain a valid ISO 8601 or epoch value.",
                index,
            )
        elif event.metadata.get("timestamp_present") is False:
            findings.add(
                "missing_source_timestamp",
                "high",
                "Source timestamp is missing",
                "Collector time was substituted for a missing source timestamp.",
                "Export the original event timestamp and map it in the collector profile.",
                index,
            )

        if event.metadata.get("redacted") is not True:
            findings.add(
                "redaction_provenance_unknown",
                "medium",
                "Redaction provenance is unknown",
                "The normalized event does not attest that the content-safe projection ran.",
                "Pass evidence through a bounded AgentSim collector before detection evaluation.",
                index,
            )

        record_id = event.source_record_id
        if not record_id:
            findings.add(
                "missing_event_id",
                "high",
                "Stable event identity is missing",
                "An event cannot be referenced reliably by causal or investigative workflows.",
                "Map the source event or span ID into source_record_id.",
                index,
            )
        elif record_id in identities:
            findings.add(
                "duplicate_event_id",
                "high",
                "Duplicate event identity detected",
                "Two or more records share a source event ID, making causal joins ambiguous.",
                "Preserve a globally unique event/span ID or qualify it with its source.",
                index,
            )
        else:
            identities[record_id] = index

        trace_id = event.get("trace_id")
        if trace_id not in (None, ""):
            trace_ids.add(str(trace_id))
        is_agent = event.source in _AGENT_SOURCES or event.event_type.startswith(
            ("agent.", "gen_ai.", "mcp.")
        )
        if is_agent:
            agent_event_count += 1
            missing = [
                field
                for field in ("trace_id", "session_id", "agent_id")
                if event.get(field) in (None, "")
            ]
            if not missing:
                agent_identity_complete += 1
            else:
                findings.add(
                    "missing_agent_correlation_identity",
                    "high",
                    "Agent correlation identity is incomplete",
                    "Agent events are missing trace_id, session_id, or agent_id.",
                    "Instrument stable trace, session, and agent identifiers at every lifecycle checkpoint.",
                    index,
                )
            generated = event.metadata.get("generated_identity_fields", ())
            if isinstance(generated, Sequence) and not isinstance(generated, (str, bytes)) and generated:
                findings.add(
                    "generated_agent_identity",
                    "medium",
                    "Agent identity was generated during normalization",
                    "One or more source identity fields were absent and replaced with deterministic fallbacks.",
                    "Emit native event_id, trace_id, session_id, and agent_id values from the runtime.",
                    index,
                )

        field_names = set(event.fields) | set(event.available_fields)
        if event.metadata.get("content_recorded") is True or any(
            _content_field(name) for name in field_names
        ):
            findings.add(
                "raw_content_exposed",
                "critical",
                "Raw content may be present in defensive telemetry",
                "A prompt, result, credential, message, or similar content field crossed the redaction boundary.",
                "Remove raw content at collection time and retain only bounded classifications, counts, and fingerprints.",
                index,
            )

    for index, event in enumerate(values):
        references = set(_many(event.get("caused_by_event_ids")))
        references.update(_many(event.get("parent_event_id")))
        for reference in references:
            causal_edge_count += 1
            parent_index = identities.get(reference)
            if parent_index is None:
                broken_edge_count += 1
                findings.add(
                    "broken_causal_link",
                    "high",
                    "Causal parent is absent",
                    "A parent_event_id or caused_by_event_ids reference does not resolve in the export.",
                    "Export the complete trace window or preserve links to an explicitly documented external root.",
                    index,
                )
                continue
            parent = values[parent_index]
            child_trace = event.get("trace_id")
            parent_trace = parent.get("trace_id")
            if child_trace and parent_trace and child_trace != parent_trace:
                findings.add(
                    "cross_trace_causal_link",
                    "critical",
                    "Causal link crosses trace boundaries",
                    "A child references a parent in a different trace, indicating identity collision or context loss.",
                    "Preserve trace context across delegation and reject reused event identifiers.",
                    index,
                )
            child_time, parent_time = timestamps[index], timestamps[parent_index]
            if child_time is not None and parent_time is not None and child_time < parent_time:
                findings.add(
                    "causal_time_inversion",
                    "high",
                    "Child event precedes its causal parent",
                    "Event timestamps contradict the recorded causal ordering.",
                    "Correct clock normalization or use source monotonic ordering metadata.",
                    index,
                )

    results = findings.values()
    score = max(0, 100 - sum(_SEVERITY_PENALTY[item.severity] for item in results))
    if any(item.severity == "critical" for item in results) or score < 60:
        status = "unusable"
    elif results:
        status = "degraded"
    else:
        status = "healthy"
    metrics: dict[str, object] = {
        "source_count": len({event.source for event in values}),
        "event_type_count": len({event.event_type for event in values}),
        "causal_edge_count": causal_edge_count,
        "broken_causal_edge_count": broken_edge_count,
        "causal_link_success_percent": round(
            100.0 * (causal_edge_count - broken_edge_count) / causal_edge_count, 2
        )
        if causal_edge_count
        else 100.0,
        "agent_event_count": agent_event_count,
        "agent_identity_coverage_percent": round(
            100.0 * agent_identity_complete / agent_event_count, 2
        )
        if agent_event_count
        else 100.0,
        "synthetic_record_count": sum(1 for event in values if event.synthetic),
    }
    return TelemetryAssuranceReport(status, score, len(values), len(trace_ids), metrics, results)


__all__ = ["AssuranceFinding", "TelemetryAssuranceReport", "assess_telemetry"]
