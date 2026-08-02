"""Directed campaign models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence


@dataclass(frozen=True)
class CampaignStep:
    """One ability node in a directed campaign."""

    step_id: str
    ability_id: str
    depends_on: tuple[str, ...] = ()
    on_failure: str = "stop"


@dataclass(frozen=True)
class CampaignDefinition:
    """An ordered or dependency-directed group of abilities."""

    campaign_id: str
    name: str
    description: str
    objective: str
    target_profile: str
    steps: tuple[CampaignStep, ...]
    required_telemetry: tuple[str, ...]
    stop_conditions: tuple[str, ...]
    authorization_required: bool = True
    pack_id: str = "agentsim.custom"
    metadata: Mapping[str, object] = field(default_factory=dict)

    @property
    def ability_ids(self) -> tuple[str, ...]:
        return tuple(step.ability_id for step in self.steps)
