"""Detection regression cases with explicit malicious and benign fixtures."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from agentsim.detection.ast import DetectionRule
from agentsim.detection.evaluator import DetectionEvaluation, evaluate_rule
from agentsim.models.telemetry import NormalizedEvent


@dataclass(frozen=True)
class RegressionResult:
    rule_id: str
    malicious_detected: bool
    benign_suppressed: bool
    malicious: DetectionEvaluation
    benign: DetectionEvaluation

    @property
    def passed(self) -> bool:
        return self.malicious_detected and self.benign_suppressed

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "passed": self.passed,
            "malicious_detected": self.malicious_detected,
            "benign_suppressed": self.benign_suppressed,
            "malicious": self.malicious.to_dict(),
            "benign": self.benign.to_dict(),
        }


def run_regression(
    rule: DetectionRule,
    malicious_events: Iterable[NormalizedEvent],
    benign_events: Iterable[NormalizedEvent],
) -> RegressionResult:
    malicious = evaluate_rule(rule, malicious_events)
    benign = evaluate_rule(rule, benign_events)
    return RegressionResult(rule.rule_id, malicious.matched, not benign.matched, malicious, benign)
