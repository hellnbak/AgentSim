"""Stable Python entry points for v0.4 ability and campaign workflows."""

from __future__ import annotations

from pathlib import Path
from typing import Mapping, Sequence

from agentsim.content import load_ability_registry, load_campaign_registry
from agentsim.models.result import CampaignRunResult
from agentsim.models.target import TargetProfile
from agentsim.orchestration.planner import CampaignPlan, plan_campaign
from agentsim.orchestration.runner import CampaignRunner
from agentsim.safety.authorization import AuthorizationManifest


def plan(
    campaign_id: str,
    *,
    manifest: AuthorizationManifest,
    target_uri: str,
    mode: str = "simulate",
    allow_network: bool = False,
    ability_packs: Sequence[str | Path] = (),
    campaign_packs: Sequence[str | Path] = (),
) -> CampaignPlan:
    abilities = load_ability_registry(ability_packs)
    campaigns = load_campaign_registry(campaign_packs)
    try:
        campaign = campaigns[campaign_id]
    except KeyError as exc:
        raise ValueError(f"unknown campaign: {campaign_id}") from exc
    return plan_campaign(
        campaign,
        abilities,
        mode=mode,
        target=TargetProfile.from_uri(target_uri),
        manifest=manifest,
        allow_network=allow_network,
    )


def run_campaign(
    campaign_id: str,
    *,
    manifest: AuthorizationManifest,
    target_uri: str,
    output_directory: str | Path,
    database_path: str | Path = "agent_sim_runs.db",
    mode: str = "simulate",
    allow_network: bool = False,
    detection_results: Mapping[str, bool] | None = None,
    ability_packs: Sequence[str | Path] = (),
    campaign_packs: Sequence[str | Path] = (),
) -> CampaignRunResult:
    abilities = load_ability_registry(ability_packs)
    campaigns = load_campaign_registry(campaign_packs)
    try:
        campaign = campaigns[campaign_id]
    except KeyError as exc:
        raise ValueError(f"unknown campaign: {campaign_id}") from exc
    return CampaignRunner(abilities, database_path=database_path).run(
        campaign,
        mode=mode,
        target=TargetProfile.from_uri(target_uri),
        manifest=manifest,
        output_directory=output_directory,
        allow_network=allow_network,
        detection_results=detection_results,
    )
