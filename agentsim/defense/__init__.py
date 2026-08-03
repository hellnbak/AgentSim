"""Defensive recommendations, feedback, drift, regression, and scorecards."""

from .gaps import GapFinding, analyze_gaps
from .drift import (
    DetectionDriftReport,
    DetectionSnapshot,
    DriftFinding,
    compare_detection_snapshots,
    detection_snapshot_from_mapping,
)
from .feedback import (
    AlertReconciliation,
    DetectionAlert,
    FeedbackConflict,
    FeedbackReport,
    OperatorAnnotation,
    detection_alert_from_mapping,
    operator_annotation_from_mapping,
    parse_feedback_bundle,
    reconcile_detection_feedback,
)
from .detection_ci import (
    DetectionCiFinding,
    DetectionCiReport,
    DetectionCiTransition,
    compare_flight_bundles,
    evaluate_detection_ci,
)
from .recommendations import recommendations_for_action
from .regression import RegressionResult, run_regression
from .runbooks import generate_runbook, generate_runbooks
from .scorecard import DefenseScorecard, build_scorecard

__all__ = [
    "DefenseScorecard",
    "GapFinding",
    "AlertReconciliation",
    "DetectionAlert",
    "DetectionCiFinding",
    "DetectionCiReport",
    "DetectionCiTransition",
    "DetectionDriftReport",
    "DetectionSnapshot",
    "DriftFinding",
    "FeedbackConflict",
    "FeedbackReport",
    "OperatorAnnotation",
    "RegressionResult",
    "analyze_gaps",
    "compare_detection_snapshots",
    "compare_flight_bundles",
    "detection_alert_from_mapping",
    "detection_snapshot_from_mapping",
    "build_scorecard",
    "generate_runbook",
    "operator_annotation_from_mapping",
    "parse_feedback_bundle",
    "reconcile_detection_feedback",
    "generate_runbooks",
    "recommendations_for_action",
    "run_regression",
    "evaluate_detection_ci",
]
