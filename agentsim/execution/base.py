"""ExecutionProvider interface and redacted provider results."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from agentsim.models.ability import AbilityDefinition
from agentsim.models.target import TargetProfile
from agentsim.safety.resource_limits import RunLimits


@dataclass(frozen=True)
class ProviderResult:
    status: str
    attempted: bool
    executed: bool
    return_codes: tuple[int, ...] = ()
    output_digest: str | None = None
    output_bytes: int = 0
    error: str | None = None


class ExecutionProvider(ABC):
    """Prepare, execute, and clean one reviewed ability."""

    name: str

    @abstractmethod
    def prepare(self, ability: AbilityDefinition, target: TargetProfile) -> None:
        raise NotImplementedError

    @abstractmethod
    def execute(
        self,
        ability: AbilityDefinition,
        target: TargetProfile,
        limits: RunLimits,
    ) -> ProviderResult:
        raise NotImplementedError

    @abstractmethod
    def cleanup(
        self,
        ability: AbilityDefinition,
        target: TargetProfile,
        limits: RunLimits,
    ) -> ProviderResult:
        raise NotImplementedError
