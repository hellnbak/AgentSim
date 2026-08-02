"""Ability-pack models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence


@dataclass(frozen=True)
class ExecutionSpec:
    """Gated execution metadata for one reviewed ability."""

    supported_providers: tuple[str, ...]
    default_provider: str
    requires_elevation: bool
    network_access: str
    timeout_seconds: int
    command_ref: str
    cleanup_ref: str | None
    state_changes: bool = False


@dataclass(frozen=True)
class AbilityDefinition:
    """A single bounded adversary behavior with defensive expectations."""

    ability_id: str
    name: str
    description: str
    risk: str
    platforms: tuple[str, ...]
    mappings: Mapping[str, Sequence[str]]
    execution: ExecutionSpec
    allowed_target_types: tuple[str, ...]
    production_allowed: bool
    expected_telemetry: tuple[Mapping[str, object], ...]
    detection_objectives: tuple[str, ...]
    benign_controls: tuple[str, ...]
    defenses: tuple[str, ...]
    pack_id: str = "agentsim.custom"
    metadata: Mapping[str, object] = field(default_factory=dict)
