"""Central authorization and safety policy engine."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from agentsim.models.ability import AbilityDefinition
from agentsim.models.target import TargetProfile

from .authorization import AuthorizationManifest
from .target_scope import target_is_allowed


MODE_PROVIDER = {"simulate": "simulate", "emulate": "local", "lab": "docker"}


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    reason: str
    provider: str


class SafetyPolicy:
    """Enforce authority, target, execution, network, and cleanup boundaries."""

    def authorize(
        self,
        ability: AbilityDefinition,
        *,
        mode: str,
        target: TargetProfile,
        manifest: AuthorizationManifest,
        run_allows_network: bool = False,
        now: datetime | None = None,
    ) -> AuthorizationDecision:
        provider = MODE_PROVIDER.get(mode, "")
        if not provider:
            return AuthorizationDecision(False, "unsupported execution mode", provider)
        if manifest.expired(now):
            return AuthorizationDecision(False, "authorization manifest has expired", provider)
        if mode not in manifest.allowed_modes:
            return AuthorizationDecision(False, "execution mode is outside authorization scope", provider)
        if not target_is_allowed(target, manifest.allowed_targets):
            return AuthorizationDecision(False, "target is outside the authorization allowlist", provider)
        if "*" not in manifest.allowed_ability_ids and ability.ability_id not in manifest.allowed_ability_ids:
            return AuthorizationDecision(False, "ability is outside authorization scope", provider)
        if provider not in ability.execution.supported_providers:
            return AuthorizationDecision(False, "ability does not support the selected provider", provider)
        if provider == "local" and target.target_type != "localhost":
            return AuthorizationDecision(
                False, "local provider requires an explicit localhost target", provider
            )
        if provider == "docker" and target.target_type != "container":
            return AuthorizationDecision(
                False, "docker provider requires an explicit container target", provider
            )
        if target.target_type not in ability.allowed_target_types and mode != "simulate":
            return AuthorizationDecision(False, "ability does not allow this target type", provider)
        if target.environment == "production" and not ability.production_allowed:
            return AuthorizationDecision(False, "ability is locked out of production targets", provider)
        if ability.execution.requires_elevation:
            return AuthorizationDecision(False, "elevated abilities are not supported by the public core", provider)
        if mode != "simulate" and ability.execution.network_access == "required" and not (
            run_allows_network and manifest.allow_network
        ):
            return AuthorizationDecision(False, "network access requires ability, run, and manifest approval", provider)
        if ability.execution.state_changes and not ability.execution.cleanup_ref:
            return AuthorizationDecision(False, "state-changing ability has no cleanup reference", provider)
        return AuthorizationDecision(True, "authorized by scoped manifest", provider)
