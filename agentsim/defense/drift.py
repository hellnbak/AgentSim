"""Detection tuning drift comparisons over malicious and benign baselines."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Mapping, Sequence


DRIFT_SCHEMA_VERSION = "1.0"
_SEVERITY_PENALTY = {"critical": 35, "high": 22, "medium": 10, "low": 4}


def _count(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a non-negative integer")
    selected = int(value)
    if selected < 0 or selected != value:
        raise ValueError(f"{name} must be a non-negative integer")
    return selected


def _optional_number(value: object, name: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be numeric or null")
    selected = float(value)
    if selected < 0:
        raise ValueError(f"{name} must be non-negative")
    return selected


@dataclass(frozen=True)
class DetectionSnapshot:
    snapshot_id: str
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    mean_checkpoints_to_detection: float | None = None
    reconciled_alerts: int = 0
    total_alerts: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot_id, str) or not self.snapshot_id.strip():
            raise ValueError("snapshot_id must be a non-empty string")
        if len(self.snapshot_id) > 512:
            raise ValueError("snapshot_id exceeds 512 characters")
        for name in (
            "true_positive",
            "false_positive",
            "true_negative",
            "false_negative",
            "reconciled_alerts",
            "total_alerts",
        ):
            _count(getattr(self, name), name)
        _optional_number(
            self.mean_checkpoints_to_detection, "mean_checkpoints_to_detection"
        )
        if self.reconciled_alerts > self.total_alerts:
            raise ValueError("reconciled_alerts cannot exceed total_alerts")

    @property
    def precision(self) -> float:
        denominator = self.true_positive + self.false_positive
        return self.true_positive / denominator if denominator else 1.0

    @property
    def recall(self) -> float:
        denominator = self.true_positive + self.false_negative
        return self.true_positive / denominator if denominator else 1.0

    @property
    def false_positive_rate(self) -> float:
        denominator = self.false_positive + self.true_negative
        return self.false_positive / denominator if denominator else 0.0

    @property
    def benign_rejection_rate(self) -> float:
        return 1.0 - self.false_positive_rate

    @property
    def reconciliation_rate(self) -> float:
        return self.reconciled_alerts / self.total_alerts if self.total_alerts else 1.0

    def to_dict(self) -> dict[str, object]:
        return {
            **asdict(self),
            "precision": round(self.precision, 6),
            "recall": round(self.recall, 6),
            "false_positive_rate": round(self.false_positive_rate, 6),
            "benign_rejection_rate": round(self.benign_rejection_rate, 6),
            "reconciliation_rate": round(self.reconciliation_rate, 6),
        }


@dataclass(frozen=True)
class DriftFinding:
    finding_id: str
    metric: str
    severity: str
    baseline: float
    candidate: float
    delta: float
    threshold: float
    remediation: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class DetectionDriftReport:
    status: str
    score: int
    baseline: DetectionSnapshot
    candidate: DetectionSnapshot
    findings: tuple[DriftFinding, ...]
    deltas: Mapping[str, float | None]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": DRIFT_SCHEMA_VERSION,
            "kind": "detection-drift-report",
            "status": self.status,
            "score": self.score,
            "baseline": self.baseline.to_dict(),
            "candidate": self.candidate.to_dict(),
            "deltas": dict(self.deltas),
            "findings": [item.to_dict() for item in self.findings],
            "content_values_recorded": False,
        }


def detection_snapshot_from_mapping(
    value: Mapping[str, object], *, default_id: str
) -> DetectionSnapshot:
    metrics = value.get("metrics", value)
    if not isinstance(metrics, Mapping):
        raise ValueError("detection snapshot metrics must be an object")
    snapshot_id = str(value.get("snapshot_id") or value.get("run_id") or default_id)
    counts = {
        name: _count(metrics.get(name, 0), name)
        for name in ("true_positive", "false_positive", "true_negative", "false_negative")
    }
    total_alerts = _count(
        metrics.get("total_alerts", metrics.get("alerts", 0)), "total_alerts"
    )
    reconciled_alerts = _count(
        metrics.get("reconciled_alerts", metrics.get("matched_alerts", total_alerts)),
        "reconciled_alerts",
    )
    if reconciled_alerts > total_alerts:
        raise ValueError("reconciled_alerts cannot exceed total_alerts")
    return DetectionSnapshot(
        snapshot_id=snapshot_id,
        **counts,
        mean_checkpoints_to_detection=_optional_number(
            metrics.get("mean_checkpoints_to_detection"),
            "mean_checkpoints_to_detection",
        ),
        reconciled_alerts=reconciled_alerts,
        total_alerts=total_alerts,
    )


def compare_detection_snapshots(
    baseline: DetectionSnapshot,
    candidate: DetectionSnapshot,
    *,
    max_recall_drop: float = 0.05,
    max_false_positive_rate_increase: float = 0.05,
    max_latency_increase: float = 1.0,
    max_reconciliation_drop: float = 0.05,
) -> DetectionDriftReport:
    thresholds = {
        "max_recall_drop": max_recall_drop,
        "max_false_positive_rate_increase": max_false_positive_rate_increase,
        "max_latency_increase": max_latency_increase,
        "max_reconciliation_drop": max_reconciliation_drop,
    }
    if any(
        isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0
        for value in thresholds.values()
    ):
        raise ValueError("drift thresholds must be non-negative numbers")
    findings: list[DriftFinding] = []

    def add(
        metric: str,
        severity: str,
        before: float,
        after: float,
        delta: float,
        threshold: float,
        remediation: Sequence[str],
    ) -> None:
        findings.append(
            DriftFinding(
                finding_id=f"DRIFT-{len(findings) + 1:04d}",
                metric=metric,
                severity=severity,
                baseline=round(before, 6),
                candidate=round(after, 6),
                delta=round(delta, 6),
                threshold=round(threshold, 6),
                remediation=tuple(remediation),
            )
        )

    recall_drop = baseline.recall - candidate.recall
    if recall_drop > max_recall_drop:
        add(
            "recall",
            "critical" if recall_drop >= 0.2 else "high",
            baseline.recall,
            candidate.recall,
            -recall_drop,
            max_recall_drop,
            ("Restore malicious baseline coverage before accepting the tuning change.",),
        )
    fpr_increase = candidate.false_positive_rate - baseline.false_positive_rate
    if fpr_increase > max_false_positive_rate_increase:
        add(
            "false_positive_rate",
            "critical" if fpr_increase >= 0.2 else "high",
            baseline.false_positive_rate,
            candidate.false_positive_rate,
            fpr_increase,
            max_false_positive_rate_increase,
            ("Retune against the benign baseline without widening malicious suppression.",),
        )
    reconciliation_drop = baseline.reconciliation_rate - candidate.reconciliation_rate
    if reconciliation_drop > max_reconciliation_drop:
        add(
            "reconciliation_rate",
            "high" if reconciliation_drop >= 0.2 else "medium",
            baseline.reconciliation_rate,
            candidate.reconciliation_rate,
            -reconciliation_drop,
            max_reconciliation_drop,
            ("Repair alert trace identifiers and evidence references before evaluating efficacy.",),
        )
    latency_delta: float | None = None
    if (
        baseline.mean_checkpoints_to_detection is not None
        and candidate.mean_checkpoints_to_detection is not None
    ):
        latency_delta = (
            candidate.mean_checkpoints_to_detection
            - baseline.mean_checkpoints_to_detection
        )
        if latency_delta > max_latency_increase:
            add(
                "mean_checkpoints_to_detection",
                "high" if latency_delta >= 5 else "medium",
                baseline.mean_checkpoints_to_detection,
                candidate.mean_checkpoints_to_detection,
                latency_delta,
                max_latency_increase,
                ("Review sequence and graph constraints that delayed the first malicious match.",),
            )

    if any(item.severity in {"critical", "high"} for item in findings):
        status = "regressed"
    elif findings:
        status = "review"
    else:
        status = "stable"
    score = max(0, 100 - sum(_SEVERITY_PENALTY[item.severity] for item in findings))
    deltas: dict[str, float | None] = {
        "precision": round(candidate.precision - baseline.precision, 6),
        "recall": round(candidate.recall - baseline.recall, 6),
        "false_positive_rate": round(fpr_increase, 6),
        "benign_rejection_rate": round(
            candidate.benign_rejection_rate - baseline.benign_rejection_rate, 6
        ),
        "reconciliation_rate": round(
            candidate.reconciliation_rate - baseline.reconciliation_rate, 6
        ),
        "mean_checkpoints_to_detection": round(latency_delta, 6)
        if latency_delta is not None
        else None,
    }
    return DetectionDriftReport(
        status=status,
        score=score,
        baseline=baseline,
        candidate=candidate,
        findings=tuple(findings),
        deltas=deltas,
    )
