"""Stable, explainable defensive readiness scorecards."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from agentsim.defense.gaps import GapFinding


@dataclass(frozen=True)
class DefenseScorecard:
    total_abilities: int
    telemetry_coverage_percent: float
    detection_rate_percent: float
    cleanup_rate_percent: float
    open_findings: int
    score: float
    grade: str

    def to_dict(self) -> dict[str, object]:
        return self.__dict__.copy()


def build_scorecard(
    *,
    total_abilities: int,
    covered_abilities: int,
    evaluated_detections: int,
    detected_abilities: int,
    cleanup_attempts: int = 0,
    successful_cleanups: int = 0,
    findings: Iterable[GapFinding] = (),
) -> DefenseScorecard:
    telemetry = 100.0 if total_abilities == 0 else 100 * covered_abilities / total_abilities
    detection = (
        0.0 if evaluated_detections == 0 else 100 * detected_abilities / evaluated_detections
    )
    cleanup = 100.0 if cleanup_attempts == 0 else 100 * successful_cleanups / cleanup_attempts
    selected = tuple(findings)
    penalty = min(20.0, 5 * sum(item.severity == "high" for item in selected))
    score = round(max(0.0, 0.4 * telemetry + 0.4 * detection + 0.2 * cleanup - penalty), 1)
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    return DefenseScorecard(
        total_abilities,
        round(telemetry, 1),
        round(detection, 1),
        round(cleanup, 1),
        len(selected),
        score,
        grade,
    )
