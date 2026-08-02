"""Stable Python entry points for AgentSim v1 workflows."""

from __future__ import annotations

from pathlib import Path
from typing import Mapping, Sequence

from agentsim.content import load_ability_registry, load_campaign_registry
from agentsim.defense import analyze_gaps, generate_runbook
from agentsim.detection import analyze_coverage, evaluate_rule, generate_candidate
from agentsim.detection.ast import DetectionRule
from agentsim.external import ExternalPlan, build_external_plan
from agentsim.lab import LabResult, run_fixture, run_lab_suite
from agentsim.models.telemetry import NormalizedEvent
from agentsim.models.result import CampaignRunResult
from agentsim.models.target import TargetProfile
from agentsim.orchestration.planner import CampaignPlan, plan_campaign
from agentsim.orchestration.runner import CampaignRunner
from agentsim.safety.authorization import AuthorizationManifest
from agentsim.telemetry.collectors import collector_for


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


def collect_telemetry(path: str | Path, *, collector: str = "jsonl") -> tuple[NormalizedEvent, ...]:
    return collector_for(collector).collect(path)


def validate_detection(
    rule: DetectionRule, events: Sequence[NormalizedEvent]
) -> dict[str, object]:
    return evaluate_rule(rule, events).to_dict()


def candidate_detection(
    ability_id: str, *, ability_packs: Sequence[str | Path] = ()
) -> dict[str, object]:
    abilities = load_ability_registry(ability_packs)
    try:
        ability = abilities[ability_id]
    except KeyError as exc:
        raise ValueError(f"unknown ability: {ability_id}") from exc
    return generate_candidate(ability).to_dict()


def defense_analysis(
    ability_id: str,
    events: Sequence[NormalizedEvent],
    *,
    ability_packs: Sequence[str | Path] = (),
) -> dict[str, object]:
    abilities = load_ability_registry(ability_packs)
    try:
        ability = abilities[ability_id]
    except KeyError as exc:
        raise ValueError(f"unknown ability: {ability_id}") from exc
    coverage = analyze_coverage(ability, events)
    findings = analyze_gaps(abilities, (coverage,))
    return {
        "coverage": coverage.to_dict(),
        "findings": [finding.to_dict() for finding in findings],
        "runbook": generate_runbook(ability, findings),
    }


def run_agentic_lab(fixture_id: str = "all") -> tuple[LabResult, ...]:
    return run_lab_suite() if fixture_id == "all" else (run_fixture(fixture_id),)


def external_plan(adapter: str, **parameters: str) -> ExternalPlan:
    return build_external_plan(adapter, **parameters)
