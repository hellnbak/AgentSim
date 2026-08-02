"""Evidence-backed defense recommendations from ability metadata."""

from __future__ import annotations

from agentsim.models.ability import AbilityDefinition


def recommendations_for_action(
    ability: AbilityDefinition, detection_status: str
) -> tuple[dict[str, object], ...]:
    priority = "high" if detection_status == "missed" else "medium"
    return tuple(
        {
            "recommendation_id": defense,
            "priority": priority,
            "owner": "detection-engineering",
            "ability_id": ability.ability_id,
            "evidence": {
                "detection_status": detection_status,
                "expected_telemetry": [
                    entry.get("source") for entry in ability.expected_telemetry
                ],
            },
            "regression_test": f"agentsim ability run {ability.ability_id} --mode simulate",
        }
        for defense in ability.defenses
    )
