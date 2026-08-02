"""Generate transparent draft detections from reviewed ability content."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Mapping

from agentsim.content.catalog import resolve_command_sequence
from agentsim.detection.ast import DetectionRule, MatchNode, Predicate, ThresholdNode
from agentsim.models.ability import AbilityDefinition


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")


@dataclass(frozen=True)
class CandidateDetection:
    ability_id: str
    rule: DetectionRule
    process_names: tuple[str, ...]
    data_sources: tuple[str, ...]
    confidence: str
    limitations: tuple[str, ...]
    benign_controls: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        from agentsim.detection.ast import rule_to_dict

        return {
            "ability_id": self.ability_id,
            "rule": rule_to_dict(self.rule),
            "process_names": list(self.process_names),
            "data_sources": list(self.data_sources),
            "confidence": self.confidence,
            "limitations": list(self.limitations),
            "benign_controls": list(self.benign_controls),
            "status": "candidate_requires_human_review",
        }


def _process_names(ability: AbilityDefinition) -> tuple[str, ...]:
    names: set[str] = set()
    for platform in ability.platforms:
        try:
            sequences = resolve_command_sequence(ability.execution.command_ref, platform)
        except ValueError:
            continue
        for argv in sequences:
            if argv:
                names.add(argv[0].rsplit("/", 1)[-1].rsplit("\\", 1)[-1].casefold())
    return tuple(sorted(names))


def generate_candidate(ability: AbilityDefinition) -> CandidateDetection:
    """Create a bounded draft; generated rules are never promoted automatically."""

    names = _process_names(ability)
    source = str(ability.expected_telemetry[0].get("source", "process_creation"))
    predicates = [Predicate("source", "eq", source)]
    if names:
        predicates.append(Predicate("process_name", "in", names))
    base = MatchNode(tuple(predicates))
    count = 2 if len(names) > 1 else 1
    rule = DetectionRule(
        rule_id=f"agentsim.candidate.{_slug(ability.ability_id)}",
        name=f"Candidate: {ability.name}",
        description=(
            "Human-review draft generated from AgentSim's reviewed command catalog and telemetry "
            "contract. Validate against production baselines before deployment."
        ),
        severity=ability.risk,
        group_by=("host_id", "user_id"),
        mappings=tuple(
            sorted({item for values in ability.mappings.values() for item in values})
        ),
        expression=ThresholdNode(base, count=count, window_seconds=300),
        metadata={"ability_id": ability.ability_id, "generated": True, "status": "draft"},
    )
    return CandidateDetection(
        ability_id=ability.ability_id,
        rule=rule,
        process_names=names,
        data_sources=tuple(
            sorted({str(item.get("source", "unknown")) for item in ability.expected_telemetry})
        ),
        confidence="medium" if names else "low",
        limitations=(
            "Process-name matching alone is not sufficient for production alerting.",
            "Thresholds and allowlists require environment-specific tuning.",
            "The draft has not been promoted or deployed by AgentSim.",
        ),
        benign_controls=ability.benign_controls,
    )


def generate_candidates(
    abilities: Mapping[str, AbilityDefinition] | Iterable[AbilityDefinition],
) -> tuple[CandidateDetection, ...]:
    values = abilities.values() if isinstance(abilities, Mapping) else abilities
    return tuple(generate_candidate(ability) for ability in sorted(values, key=lambda item: item.ability_id))
