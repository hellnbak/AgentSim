"""Generate concise defensive runbooks from findings and reviewed content."""

from __future__ import annotations

from typing import Iterable, Mapping

from agentsim.defense.gaps import GapFinding
from agentsim.models.ability import AbilityDefinition


def generate_runbook(
    ability: AbilityDefinition, findings: Iterable[GapFinding]
) -> dict[str, object]:
    selected = tuple(finding for finding in findings if finding.ability_id == ability.ability_id)
    return {
        "schema_version": "1.0",
        "ability_id": ability.ability_id,
        "title": f"Defensive validation runbook: {ability.name}",
        "scope": "Telemetry and detection validation; no response action is executed.",
        "triage": [
            "Confirm the event belongs to an authorized AgentSim run using run_id and ability_id.",
            "Review the complete causal chain, principal, target, and approval context.",
            "Compare against documented benign controls before escalating.",
        ],
        "expected_telemetry": [dict(item) for item in ability.expected_telemetry],
        "detection_objectives": list(ability.detection_objectives),
        "benign_controls": list(ability.benign_controls),
        "recommended_controls": list(ability.defenses),
        "open_findings": [finding.to_dict() for finding in selected],
        "regression_command": f"agentsim defense regress --ability {ability.ability_id}",
    }


def generate_runbooks(
    abilities: Mapping[str, AbilityDefinition], findings: Iterable[GapFinding]
) -> tuple[dict[str, object], ...]:
    selected = tuple(findings)
    return tuple(generate_runbook(abilities[key], selected) for key in sorted(abilities))
