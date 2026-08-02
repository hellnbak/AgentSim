"""Pre-execution campaign planning and authorization preview."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Mapping

from agentsim.models.ability import AbilityDefinition
from agentsim.models.campaign import CampaignDefinition
from agentsim.models.target import TargetProfile
from agentsim.safety.authorization import AuthorizationManifest
from agentsim.safety.policy import SafetyPolicy


@dataclass(frozen=True)
class PlannedAction:
    step_id: str
    ability_id: str
    name: str
    risk: str
    provider: str
    authorized: bool
    authorization_reason: str
    command_ref: str
    cleanup_ref: str | None
    expected_telemetry: tuple[str, ...]
    defenses: tuple[str, ...]


@dataclass(frozen=True)
class CampaignPlan:
    campaign_id: str
    mode: str
    target_uri: str
    authorized: bool
    actions: tuple[PlannedAction, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "campaign_id": self.campaign_id,
            "mode": self.mode,
            "target_uri": self.target_uri,
            "authorized": self.authorized,
            "actions": [action.__dict__ for action in self.actions],
        }


def plan_campaign(
    campaign: CampaignDefinition,
    abilities: Mapping[str, AbilityDefinition],
    *,
    mode: str,
    target: TargetProfile,
    manifest: AuthorizationManifest,
    allow_network: bool = False,
    policy: SafetyPolicy | None = None,
    now: datetime | None = None,
) -> CampaignPlan:
    if len(campaign.steps) > manifest.max_actions:
        raise ValueError("campaign exceeds the authorization action limit")
    selected_policy = policy or SafetyPolicy()
    actions: list[PlannedAction] = []
    for step in campaign.steps:
        ability = abilities.get(step.ability_id)
        if ability is None:
            raise ValueError(
                f"campaign {campaign.campaign_id} references unknown ability: {step.ability_id}"
            )
        decision = selected_policy.authorize(
            ability,
            mode=mode,
            target=target,
            manifest=manifest,
            run_allows_network=allow_network,
            now=now,
        )
        telemetry = tuple(
            str(item.get("source"))
            for item in ability.expected_telemetry
            if item.get("source")
        )
        actions.append(
            PlannedAction(
                step_id=step.step_id,
                ability_id=ability.ability_id,
                name=ability.name,
                risk=ability.risk,
                provider=decision.provider,
                authorized=decision.allowed,
                authorization_reason=decision.reason,
                command_ref=ability.execution.command_ref,
                cleanup_ref=ability.execution.cleanup_ref,
                expected_telemetry=telemetry,
                defenses=ability.defenses,
            )
        )
    return CampaignPlan(
        campaign_id=campaign.campaign_id,
        mode=mode,
        target_uri=target.uri,
        authorized=all(action.authorized for action in actions),
        actions=tuple(actions),
    )
