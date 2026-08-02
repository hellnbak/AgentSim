"""Turn collected events into explicit detected, missed, or visibility-gap outcomes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from agentsim.models.ability import AbilityDefinition
from agentsim.models.telemetry import NormalizedEvent

from .coverage import analyze_coverage
from .evaluator import evaluate_rule
from .generator import generate_candidate


@dataclass(frozen=True)
class LiveDetectionOutcome:
    ability_id: str
    status: str
    matched: bool
    coverage_percent: float
    evidence_event_count: int
    missing_fields: tuple[str, ...]
    rule_id: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "ability_id": self.ability_id,
            "status": self.status,
            "matched": self.matched,
            "coverage_percent": self.coverage_percent,
            "evidence_event_count": self.evidence_event_count,
            "missing_fields": list(self.missing_fields),
            "rule_id": self.rule_id,
            "candidate_requires_human_review": True,
        }


def evaluate_live_ability(
    ability: AbilityDefinition, events: Sequence[NormalizedEvent]
) -> LiveDetectionOutcome:
    candidate = generate_candidate(ability)
    evaluation = evaluate_rule(candidate.rule, events)
    coverage = analyze_coverage(ability, events)
    missing = tuple(
        sorted({field for requirement in coverage.requirements for field in requirement.missing_fields})
    )
    if evaluation.matched:
        status = "detected"
    elif coverage.coverage_percent == 100.0:
        status = "missed"
    else:
        status = "visibility_gap"
    return LiveDetectionOutcome(
        ability.ability_id,
        status,
        evaluation.matched,
        coverage.coverage_percent,
        len(evaluation.matched_indices),
        missing,
        candidate.rule.rule_id,
    )


def evaluate_live_registry(
    abilities: Mapping[str, AbilityDefinition] | Iterable[AbilityDefinition],
    events: Sequence[NormalizedEvent],
) -> tuple[LiveDetectionOutcome, ...]:
    values = abilities.values() if isinstance(abilities, Mapping) else abilities
    return tuple(evaluate_live_ability(ability, events) for ability in sorted(values, key=lambda item: item.ability_id))
