"""Content-safe detection feedback and alert-to-trace reconciliation."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Iterable, Mapping, Sequence

from agentsim.models.telemetry import NormalizedEvent
from agentsim.telemetry.investigation import investigate_telemetry


FEEDBACK_SCHEMA_VERSION = "1.0"
MAX_FEEDBACK_ALERTS = 5000
MAX_FEEDBACK_ANNOTATIONS = 10000
ALERT_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
ANNOTATION_DISPOSITIONS = frozenset(
    {
        "confirmed_true_positive",
        "false_positive",
        "benign_expected",
        "needs_review",
        "tuning_candidate",
        "accepted_risk",
    }
)
ANNOTATION_REASONS = frozenset(
    {
        "control_failure",
        "expected_behavior",
        "identity_mismatch",
        "visibility_gap",
        "duplicate",
        "insufficient_evidence",
        "policy_exception",
        "other_structured",
    }
)
AUTHOR_TYPES = frozenset({"human", "service", "agent"})
TARGET_TYPES = frozenset({"alert", "trace"})
_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
_SEVERITY_PENALTY = {"critical": 30, "high": 18, "medium": 8, "low": 3}


def _text(value: object, name: str, *, required: bool = True) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if len(value) > 512:
        raise ValueError(f"{name} exceeds 512 characters")
    return value


def _timestamp(value: object, name: str) -> str:
    selected = _text(value, name)
    try:
        parsed = datetime.fromisoformat(str(selected).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name} must be an ISO 8601 timestamp") from exc
    if "T" not in str(selected) or parsed.tzinfo is None:
        raise ValueError(f"{name} must include a time and UTC offset")
    return str(selected)


def _strings(value: object, name: str, *, limit: int = 50) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be an array")
    if len(value) > limit:
        raise ValueError(f"{name} is limited to {limit} values")
    return tuple(str(_text(item, f"{name} value")) for item in value)


@dataclass(frozen=True)
class DetectionAlert:
    alert_id: str
    rule_id: str
    detected_at: str
    severity: str
    trace_id: str | None = None
    source_record_ids: tuple[str, ...] = ()
    agent_id: str | None = None

    def __post_init__(self) -> None:
        _text(self.alert_id, "alert_id")
        _text(self.rule_id, "rule_id")
        _timestamp(self.detected_at, "detected_at")
        if self.severity not in ALERT_SEVERITIES:
            raise ValueError("alert severity must be low, medium, high, or critical")
        _text(self.trace_id, "trace_id", required=False)
        _text(self.agent_id, "agent_id", required=False)
        object.__setattr__(
            self, "source_record_ids", _strings(self.source_record_ids, "source_record_ids")
        )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class OperatorAnnotation:
    annotation_id: str
    target_type: str
    target_id: str
    disposition: str
    reason_code: str
    author_id: str
    author_type: str
    created_at: str
    evidence_ids: tuple[str, ...] = ()
    evidence_digest_match: bool | None = None

    def __post_init__(self) -> None:
        for name in ("annotation_id", "target_id", "author_id"):
            _text(getattr(self, name), name)
        if self.target_type not in TARGET_TYPES:
            raise ValueError("annotation target_type must be alert or trace")
        if self.disposition not in ANNOTATION_DISPOSITIONS:
            raise ValueError(f"unsupported annotation disposition: {self.disposition}")
        if self.reason_code not in ANNOTATION_REASONS:
            raise ValueError(f"unsupported annotation reason_code: {self.reason_code}")
        if self.author_type not in AUTHOR_TYPES:
            raise ValueError("annotation author_type must be human, service, or agent")
        _timestamp(self.created_at, "created_at")
        object.__setattr__(self, "evidence_ids", _strings(self.evidence_ids, "evidence_ids"))
        if self.evidence_digest_match is not None and not isinstance(
            self.evidence_digest_match, bool
        ):
            raise ValueError("evidence_digest_match must be a boolean or null")

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class AlertReconciliation:
    alert_id: str
    status: str
    trace_id: str | None
    candidate_trace_ids: tuple[str, ...]
    matched_event_ids: tuple[str, ...]
    reason_code: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class FeedbackConflict:
    conflict_id: str
    code: str
    severity: str
    target_type: str
    target_id: str
    trace_id: str | None
    annotation_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    remediation: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class FeedbackReport:
    status: str
    score: int
    alerts: tuple[DetectionAlert, ...]
    annotations: tuple[OperatorAnnotation, ...]
    reconciliations: tuple[AlertReconciliation, ...]
    conflicts: tuple[FeedbackConflict, ...]
    summary: Mapping[str, object]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": FEEDBACK_SCHEMA_VERSION,
            "kind": "detection-feedback-report",
            "status": self.status,
            "score": self.score,
            "summary": dict(self.summary),
            "alerts": [item.to_dict() for item in self.alerts],
            "annotations": [item.to_dict() for item in self.annotations],
            "reconciliations": [item.to_dict() for item in self.reconciliations],
            "conflicts": [item.to_dict() for item in self.conflicts],
            "content_values_recorded": False,
        }


def detection_alert_from_mapping(value: Mapping[str, object]) -> DetectionAlert:
    allowed = {
        "alert_id",
        "rule_id",
        "detected_at",
        "severity",
        "trace_id",
        "source_record_ids",
        "agent_id",
    }
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"unknown detection alert fields: {', '.join(unknown)}")
    return DetectionAlert(
        alert_id=str(_text(value.get("alert_id"), "alert_id")),
        rule_id=str(_text(value.get("rule_id"), "rule_id")),
        detected_at=_timestamp(value.get("detected_at"), "detected_at"),
        severity=str(value.get("severity", "")),
        trace_id=_text(value.get("trace_id"), "trace_id", required=False),
        source_record_ids=_strings(value.get("source_record_ids"), "source_record_ids"),
        agent_id=_text(value.get("agent_id"), "agent_id", required=False),
    )


def operator_annotation_from_mapping(value: Mapping[str, object]) -> OperatorAnnotation:
    allowed = {
        "annotation_id",
        "target_type",
        "target_id",
        "disposition",
        "reason_code",
        "author_id",
        "author_type",
        "created_at",
        "evidence_ids",
        "evidence_digest_match",
    }
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"unknown operator annotation fields: {', '.join(unknown)}")
    digest_match = value.get("evidence_digest_match")
    return OperatorAnnotation(
        annotation_id=str(_text(value.get("annotation_id"), "annotation_id")),
        target_type=str(value.get("target_type", "")),
        target_id=str(_text(value.get("target_id"), "target_id")),
        disposition=str(value.get("disposition", "")),
        reason_code=str(value.get("reason_code", "")),
        author_id=str(_text(value.get("author_id"), "author_id")),
        author_type=str(value.get("author_type", "")),
        created_at=_timestamp(value.get("created_at"), "created_at"),
        evidence_ids=_strings(value.get("evidence_ids"), "evidence_ids"),
        evidence_digest_match=digest_match,
    )


def parse_feedback_bundle(
    value: Mapping[str, object],
) -> tuple[tuple[DetectionAlert, ...], tuple[OperatorAnnotation, ...]]:
    allowed = {"schema_version", "alerts", "annotations"}
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"unknown feedback bundle fields: {', '.join(unknown)}")
    if value.get("schema_version") != FEEDBACK_SCHEMA_VERSION:
        raise ValueError(f"unsupported feedback schema: {value.get('schema_version')}")
    raw_alerts = value.get("alerts", ())
    raw_annotations = value.get("annotations", ())
    for name, items, limit in (
        ("alerts", raw_alerts, MAX_FEEDBACK_ALERTS),
        ("annotations", raw_annotations, MAX_FEEDBACK_ANNOTATIONS),
    ):
        if not isinstance(items, Sequence) or isinstance(items, (str, bytes, bytearray)):
            raise ValueError(f"feedback {name} must be an array")
        if len(items) > limit:
            raise ValueError(f"feedback {name} exceed the {limit} item limit")
    alerts = tuple(
        detection_alert_from_mapping(item)
        for item in raw_alerts
        if isinstance(item, Mapping)
    )
    annotations = tuple(
        operator_annotation_from_mapping(item)
        for item in raw_annotations
        if isinstance(item, Mapping)
    )
    if len(alerts) != len(raw_alerts) or len(annotations) != len(raw_annotations):
        raise ValueError("feedback alerts and annotations must be objects")
    if len({item.alert_id for item in alerts}) != len(alerts):
        raise ValueError("feedback alert_id values must be unique")
    if len({item.annotation_id for item in annotations}) != len(annotations):
        raise ValueError("feedback annotation_id values must be unique")
    return alerts, annotations


def _conflict(
    conflicts: list[FeedbackConflict],
    *,
    code: str,
    severity: str,
    target_type: str,
    target_id: str,
    trace_id: str | None = None,
    annotation_ids: Sequence[str] = (),
    evidence_ids: Sequence[str] = (),
    remediation: Sequence[str],
) -> None:
    conflicts.append(
        FeedbackConflict(
            conflict_id=f"FB-{len(conflicts) + 1:04d}",
            code=code,
            severity=severity,
            target_type=target_type,
            target_id=target_id,
            trace_id=trace_id,
            annotation_ids=tuple(annotation_ids),
            evidence_ids=tuple(evidence_ids),
            remediation=tuple(remediation),
        )
    )


def reconcile_detection_feedback(
    alerts: Iterable[DetectionAlert],
    events: Iterable[NormalizedEvent],
    annotations: Iterable[OperatorAnnotation] = (),
) -> FeedbackReport:
    """Join alerts and structured verdicts to content-safe trace evidence."""

    alert_values = tuple(alerts)
    annotation_values = tuple(annotations)
    event_values = tuple(events)
    if len(alert_values) > MAX_FEEDBACK_ALERTS:
        raise ValueError(f"feedback alerts exceed the {MAX_FEEDBACK_ALERTS} item limit")
    if len(annotation_values) > MAX_FEEDBACK_ANNOTATIONS:
        raise ValueError(
            f"feedback annotations exceed the {MAX_FEEDBACK_ANNOTATIONS} item limit"
        )
    if len({item.alert_id for item in alert_values}) != len(alert_values):
        raise ValueError("feedback alert_id values must be unique")
    if len({item.annotation_id for item in annotation_values}) != len(annotation_values):
        raise ValueError("feedback annotation_id values must be unique")

    traces: dict[str, list[NormalizedEvent]] = {}
    event_by_id: dict[str, NormalizedEvent] = {}
    for event in event_values:
        trace_id = str(event.get("trace_id") or "")
        if trace_id:
            traces.setdefault(trace_id, []).append(event)
        if event.source_record_id:
            event_by_id[event.source_record_id] = event

    reconciliations: list[AlertReconciliation] = []
    conflicts: list[FeedbackConflict] = []
    reconciled_by_alert: dict[str, AlertReconciliation] = {}
    for alert in alert_values:
        evidence_events = [
            event_by_id[item]
            for item in alert.source_record_ids
            if item in event_by_id
        ]
        evidence_traces = {
            str(event.get("trace_id"))
            for event in evidence_events
            if event.get("trace_id")
        }
        candidate_traces = set(evidence_traces)
        if alert.trace_id:
            candidate_traces.add(alert.trace_id)
        matched_trace: str | None = None
        if alert.trace_id and alert.trace_id in traces and not (
            evidence_traces - {alert.trace_id}
        ):
            status = "matched"
            matched_trace = alert.trace_id
            reason = "explicit_trace_match"
        elif not alert.trace_id and len(evidence_traces) == 1:
            status = "matched"
            matched_trace = next(iter(evidence_traces))
            reason = "evidence_trace_match"
        elif len(candidate_traces) > 1:
            status = "ambiguous"
            reason = "trace_evidence_conflict"
            _conflict(
                conflicts,
                code="alert_trace_evidence_conflict",
                severity="high",
                target_type="alert",
                target_id=alert.alert_id,
                trace_id=alert.trace_id,
                evidence_ids=alert.source_record_ids,
                remediation=(
                    "Require the alert trace identifier and every evidence record to resolve to one trace.",
                ),
            )
        else:
            status = "unmatched"
            reason = "trace_not_observed"
        matched_ids = tuple(
            event.source_record_id
            for event in evidence_events
            if event.source_record_id
            and (matched_trace is None or event.get("trace_id") == matched_trace)
        )
        reconciliation = AlertReconciliation(
            alert_id=alert.alert_id,
            status=status,
            trace_id=matched_trace,
            candidate_trace_ids=tuple(sorted(candidate_traces)),
            matched_event_ids=matched_ids,
            reason_code=reason,
        )
        reconciliations.append(reconciliation)
        reconciled_by_alert[alert.alert_id] = reconciliation

    investigation = investigate_telemetry(event_values)
    trace_severity = {
        str(item["trace_id"]): str(item.get("highest_severity", "none"))
        for item in investigation.traces
    }
    alert_ids = {item.alert_id for item in alert_values}
    trace_ids = set(traces)
    evidence_ids = set(event_by_id)
    annotations_by_target: dict[tuple[str, str], list[OperatorAnnotation]] = {}
    for annotation in annotation_values:
        annotations_by_target.setdefault(
            (annotation.target_type, annotation.target_id), []
        ).append(annotation)
        target_exists = (
            annotation.target_id in alert_ids
            if annotation.target_type == "alert"
            else annotation.target_id in trace_ids
        )
        if not target_exists:
            _conflict(
                conflicts,
                code="annotation_target_unresolved",
                severity="medium",
                target_type=annotation.target_type,
                target_id=annotation.target_id,
                annotation_ids=(annotation.annotation_id,),
                remediation=("Resolve the annotation target before using its disposition for tuning.",),
            )
        unresolved = tuple(item for item in annotation.evidence_ids if item not in evidence_ids)
        if unresolved:
            _conflict(
                conflicts,
                code="annotation_evidence_unresolved",
                severity="medium",
                target_type=annotation.target_type,
                target_id=annotation.target_id,
                annotation_ids=(annotation.annotation_id,),
                evidence_ids=unresolved,
                remediation=("Retain stable record identifiers for every annotation evidence reference.",),
            )
        if annotation.evidence_digest_match is False:
            _conflict(
                conflicts,
                code="annotation_evidence_digest_mismatch",
                severity="critical",
                target_type=annotation.target_type,
                target_id=annotation.target_id,
                annotation_ids=(annotation.annotation_id,),
                evidence_ids=annotation.evidence_ids,
                remediation=("Reject the annotation and re-bind it to the current evidence digest.",),
            )
        if annotation.author_type == "agent" and annotation.disposition != "needs_review":
            _conflict(
                conflicts,
                code="agent_authored_final_verdict",
                severity="high",
                target_type=annotation.target_type,
                target_id=annotation.target_id,
                annotation_ids=(annotation.annotation_id,),
                remediation=("Require an authenticated human reviewer for final alert dispositions.",),
            )

    negative = {"false_positive", "benign_expected"}
    positive = {"confirmed_true_positive"}
    for (target_type, target_id), values in annotations_by_target.items():
        dispositions = {item.disposition for item in values}
        if dispositions & negative and dispositions & positive:
            _conflict(
                conflicts,
                code="contradictory_operator_dispositions",
                severity="high",
                target_type=target_type,
                target_id=target_id,
                annotation_ids=tuple(item.annotation_id for item in values),
                remediation=("Resolve contradictory verdicts before changing a detection or suppression.",),
            )
        trace_id: str | None = None
        if target_type == "trace":
            trace_id = target_id
        elif target_id in reconciled_by_alert:
            trace_id = reconciled_by_alert[target_id].trace_id
        if trace_id and dispositions & negative and _SEVERITY_ORDER.get(
            trace_severity.get(trace_id, "none"), 0
        ) >= _SEVERITY_ORDER["high"]:
            _conflict(
                conflicts,
                code="high_risk_trace_dismissed",
                severity="high",
                target_type=target_type,
                target_id=target_id,
                trace_id=trace_id,
                annotation_ids=tuple(item.annotation_id for item in values),
                remediation=(
                    "Require secondary review before dismissing an alert attached to high-risk invariant failures.",
                ),
            )

    status_counts = {"matched": 0, "ambiguous": 0, "unmatched": 0}
    for item in reconciliations:
        status_counts[item.status] += 1
    verdicts = {name: 0 for name in sorted(ANNOTATION_DISPOSITIONS)}
    for annotation in annotation_values:
        verdicts[annotation.disposition] += 1
    annotated_alerts = {
        item.target_id
        for item in annotation_values
        if item.target_type == "alert" and item.target_id in alert_ids
    }
    alert_count = len(alert_values)
    conflict_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in conflicts:
        conflict_severity[item.severity] += 1
    highest = max(
        (item.severity for item in conflicts),
        key=lambda item: _SEVERITY_ORDER[item],
        default="none",
    )
    if highest == "critical":
        status = "critical"
    elif highest == "high" or status_counts["ambiguous"]:
        status = "elevated"
    elif conflicts or status_counts["unmatched"]:
        status = "review"
    else:
        status = "clean"
    score = max(
        0,
        100
        - sum(_SEVERITY_PENALTY[item.severity] for item in conflicts)
        - status_counts["ambiguous"] * 8
        - status_counts["unmatched"] * 3,
    )
    summary = {
        "alerts": alert_count,
        "annotations": len(annotation_values),
        "annotated_alerts": len(annotated_alerts),
        "matched": status_counts["matched"],
        "ambiguous": status_counts["ambiguous"],
        "unmatched": status_counts["unmatched"],
        "match_rate_percent": round(status_counts["matched"] * 100 / alert_count, 2)
        if alert_count
        else 100.0,
        "annotation_coverage_percent": round(len(annotated_alerts) * 100 / alert_count, 2)
        if alert_count
        else 100.0,
        "verdicts": verdicts,
        "conflicts": len(conflicts),
        "conflict_severity": conflict_severity,
    }
    return FeedbackReport(
        status=status,
        score=score,
        alerts=alert_values,
        annotations=annotation_values,
        reconciliations=tuple(reconciliations),
        conflicts=tuple(conflicts),
        summary=summary,
    )
