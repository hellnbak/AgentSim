"""Non-executing deterministic provider used by default."""

from __future__ import annotations

from agentsim.models.ability import AbilityDefinition
from agentsim.models.target import TargetProfile
from agentsim.safety.resource_limits import RunLimits

from .base import ExecutionProvider, ProviderResult


class SimulationExecutionProvider(ExecutionProvider):
    name = "simulate"

    def prepare(self, ability: AbilityDefinition, target: TargetProfile) -> None:
        del ability, target

    def execute(
        self,
        ability: AbilityDefinition,
        target: TargetProfile,
        limits: RunLimits,
    ) -> ProviderResult:
        del ability, target, limits
        return ProviderResult(status="simulated", attempted=False, executed=False)

    def cleanup(
        self,
        ability: AbilityDefinition,
        target: TargetProfile,
        limits: RunLimits,
    ) -> ProviderResult:
        del ability, target, limits
        return ProviderResult(status="verified_noop", attempted=False, executed=False)
