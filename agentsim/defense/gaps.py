"""Evidence-backed defensive gap analysis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from agentsim.detection.coverage import CoverageReport
from agentsim.detection.evaluator import DetectionEvaluation
from agentsim.models.ability import AbilityDefinition


@dataclass(frozen=True)
class GapFinding:
    finding_id: str
    ability_id: str
    category: str
    severity: str
    title: str
    evidence: Mapping[str, object]
    remediation: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "ability_id": self.ability_id,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "evidence": dict(self.evidence),
            "remediation": list(self.remediation),
        }


def analyze_gaps(
    abilities: Mapping[str, AbilityDefinition],
    coverage: Iterable[CoverageReport],
    evaluations: Mapping[str, DetectionEvaluation] | None = None,
) -> tuple[GapFinding, ...]:
    """Turn explicit telemetry and detection evidence into prioritized findings."""

    evaluation_map = evaluations or {}
    findings: list[GapFinding] = []
    for report in coverage:
        ability = abilities[report.ability_id]
        for requirement in report.requirements:
            if requirement.matching_events == 0:
                findings.append(
                    GapFinding(
                        f"{ability.ability_id}:missing-source:{requirement.source}",
                        ability.ability_id,
                        "telemetry_source",
                        "high",
                        f"No {requirement.source} telemetry observed",
                        {"source": requirement.source, "matching_events": 0},
                        tuple(ability.defenses),
                    )
                )
            elif requirement.missing_fields:
                findings.append(
                    GapFinding(
                        f"{ability.ability_id}:missing-fields:{requirement.source}",
                        ability.ability_id,
                        "telemetry_fields",
                        "medium",
                        f"Required {requirement.source} fields are unavailable",
                        {
                            "source": requirement.source,
                            "missing_fields": list(requirement.missing_fields),
                            "matching_events": requirement.matching_events,
                        },
                        tuple(ability.defenses),
                    )
                )
        evaluation = evaluation_map.get(ability.ability_id)
        if evaluation is not None and not evaluation.matched:
            findings.append(
                GapFinding(
                    f"{ability.ability_id}:detection-miss",
                    ability.ability_id,
                    "detection",
                    "high" if ability.risk == "high" else "medium",
                    "Detection rule did not match the supplied telemetry",
                    {"rule_id": evaluation.rule_id, "match_count": evaluation.match_count},
                    tuple(ability.defenses),
                )
            )
    return tuple(findings)
