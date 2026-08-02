"""Telemetry coverage analysis for ability validation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from agentsim.models.ability import AbilityDefinition
from agentsim.models.telemetry import NormalizedEvent


@dataclass(frozen=True)
class TelemetryRequirementCoverage:
    source: str
    required_fields: tuple[str, ...]
    observed_fields: tuple[str, ...]
    missing_fields: tuple[str, ...]
    matching_events: int

    @property
    def covered(self) -> bool:
        return self.matching_events > 0 and not self.missing_fields

    def to_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "required_fields": list(self.required_fields),
            "observed_fields": list(self.observed_fields),
            "missing_fields": list(self.missing_fields),
            "matching_events": self.matching_events,
            "covered": self.covered,
        }


@dataclass(frozen=True)
class CoverageReport:
    ability_id: str
    requirements: tuple[TelemetryRequirementCoverage, ...]
    objectives: tuple[str, ...]

    @property
    def coverage_percent(self) -> float:
        if not self.requirements:
            return 100.0
        return round(
            100 * sum(requirement.covered for requirement in self.requirements) / len(self.requirements),
            1,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "ability_id": self.ability_id,
            "coverage_percent": self.coverage_percent,
            "requirements": [item.to_dict() for item in self.requirements],
            "objectives": list(self.objectives),
        }


def _expected(value: Mapping[str, object]) -> tuple[str, tuple[str, ...]]:
    source = str(value.get("source", "unknown"))
    raw_fields = value.get("required_fields", ())
    fields = tuple(str(field) for field in raw_fields) if isinstance(raw_fields, (list, tuple)) else ()
    return source, fields


def analyze_coverage(
    ability: AbilityDefinition, events: Iterable[NormalizedEvent]
) -> CoverageReport:
    values = tuple(events)
    requirements: list[TelemetryRequirementCoverage] = []
    for expected in ability.expected_telemetry:
        source, required_fields = _expected(expected)
        matching = tuple(
            event
            for event in values
            if event.source.casefold() == source.casefold()
            or event.event_type.casefold() == source.casefold()
        )
        observed = tuple(sorted({field for event in matching for field in event.available_fields}))
        missing = tuple(field for field in required_fields if field not in observed)
        requirements.append(
            TelemetryRequirementCoverage(source, required_fields, observed, missing, len(matching))
        )
    return CoverageReport(ability.ability_id, tuple(requirements), ability.detection_objectives)


def analyze_registry_coverage(
    abilities: Mapping[str, AbilityDefinition], events: Iterable[NormalizedEvent]
) -> tuple[CoverageReport, ...]:
    values = tuple(events)
    return tuple(analyze_coverage(abilities[key], values) for key in sorted(abilities))
