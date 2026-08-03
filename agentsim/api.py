"""Stable Python entry points for AgentSim v1 workflows."""

from __future__ import annotations

from pathlib import Path
from typing import Mapping, Sequence

from agentsim.content import (
    load_ability_registry,
    load_campaign_registry,
    review_community_pack_file,
)
from agentsim.defense import (
    DetectionAlert,
    DetectionSnapshot,
    OperatorAnnotation,
    analyze_gaps,
    compare_detection_snapshots,
    compare_flight_bundles,
    generate_runbook,
    reconcile_detection_feedback,
)
from agentsim.detection import (
    analyze_coverage,
    evaluate_live_registry,
    evaluate_rule,
    generate_candidate,
    load_detection_pack,
    sweep_detection_pack,
)
from agentsim.detection.ast import DetectionRule
from agentsim.external import ExternalPlan, build_external_plan
from agentsim.lab import (
    LabResult,
    ReferenceLabRun,
    run_fixture,
    run_lab_suite,
    run_reference_fixture,
    run_reference_suite,
    review_lab_artifact_file,
)
from agentsim.models.agent_trace import AgentTraceEvent
from agentsim.models.telemetry import NormalizedEvent
from agentsim.models.result import CampaignRunResult
from agentsim.models.target import TargetProfile
from agentsim.orchestration.planner import CampaignPlan, plan_campaign
from agentsim.orchestration.runner import CampaignRunner
from agentsim.safety.authorization import AuthorizationManifest
from agentsim.telemetry.collectors import collector_for
from agentsim.telemetry.agent_contract import agent_trace_from_record
from agentsim.telemetry.assurance import assess_telemetry
from agentsim.telemetry.investigation import investigate_telemetry
from agentsim.telemetry.flight_recorder import FlightRecorderBundle
from agentsim.telemetry.mappings import (
    agent_trace_from_portable_record,
    map_agent_trace,
    mapping_catalog,
)
from agentsim.telemetry.conformance import run_fixture_conformance
from agentsim.telemetry.connectors import (
    LiveQueryResult,
    QueryPlan,
    QuerySpec,
    QueryTransport,
    build_query_plan,
    execute_query_plan,
)


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


def normalize_agent_telemetry(
    record: Mapping[str, object], *, collector: str = "agent_runtime"
) -> AgentTraceEvent:
    return agent_trace_from_record(record, collector=collector)


def portable_mapping_catalog() -> dict[str, object]:
    """Describe pinned OTel, ECS, and OCSF mappings and extension fields."""

    return mapping_catalog()


def map_agent_telemetry(
    record: AgentTraceEvent | Mapping[str, object],
    *,
    output_profile: str,
    input_profile: str = "canonical",
) -> dict[str, object]:
    """Convert one content-safe agent event to a portable mapping profile."""

    event = (
        record
        if isinstance(record, AgentTraceEvent)
        else agent_trace_from_record(record, collector="agent_runtime")
        if input_profile == "canonical"
        else agent_trace_from_portable_record(record, profile=input_profile)
    )
    return map_agent_trace(event, output_profile).to_dict()


def cross_runtime_conformance(fixture_id: str) -> dict[str, object]:
    """Round-trip a fixed reference fixture through every portable profile."""

    return run_fixture_conformance(fixture_id).to_dict()


def community_pack_review(
    path: str | Path,
    *,
    trust_store_paths: Sequence[str | Path] = (),
) -> dict[str, object]:
    """Verify pack structure, provenance, checksum, signature, and safety."""

    return review_community_pack_file(path, trust_store_paths=trust_store_paths).to_dict()


def lab_artifact_review(
    reference_path: str | Path,
    *,
    lab_root: str | Path | None = None,
) -> dict[str, object]:
    """Review an artifact reference and hash its local file without executing it."""

    return review_lab_artifact_file(reference_path, lab_root=lab_root).to_dict()


def telemetry_assurance(events: Sequence[NormalizedEvent]) -> dict[str, object]:
    """Assess content safety and correlation readiness without reading payload values."""

    return assess_telemetry(events).to_dict()


def telemetry_investigation(events: Sequence[NormalizedEvent]) -> dict[str, object]:
    """Reconstruct a bounded multi-agent graph and evaluate defensive invariants."""

    return investigate_telemetry(events).to_dict()


def detection_feedback_reconciliation(
    alerts: Sequence[DetectionAlert],
    events: Sequence[NormalizedEvent],
    annotations: Sequence[OperatorAnnotation] = (),
) -> dict[str, object]:
    """Join structured alert feedback to traces without accepting analyst free text."""

    return reconcile_detection_feedback(alerts, events, annotations).to_dict()


def detection_drift(
    baseline: DetectionSnapshot,
    candidate: DetectionSnapshot,
    *,
    max_recall_drop: float = 0.05,
    max_false_positive_rate_increase: float = 0.05,
    max_latency_increase: float = 1.0,
    max_reconciliation_drop: float = 0.05,
) -> dict[str, object]:
    """Compare malicious/benign detection metrics using explicit drift gates."""

    return compare_detection_snapshots(
        baseline,
        candidate,
        max_recall_drop=max_recall_drop,
        max_false_positive_rate_increase=max_false_positive_rate_increase,
        max_latency_increase=max_latency_increase,
        max_reconciliation_drop=max_reconciliation_drop,
    ).to_dict()


def detection_ci(
    baseline: FlightRecorderBundle,
    candidate: FlightRecorderBundle,
    *,
    pack_path: str | Path | None = None,
    expected_classification: str | None = None,
    max_assurance_drop: int = 5,
    min_event_retention: float = 0.8,
) -> dict[str, object]:
    """Gate an agent-runtime candidate against a content-safe flight baseline."""

    return compare_flight_bundles(
        baseline,
        candidate,
        pack=load_detection_pack(pack_path),
        expected_classification=expected_classification,
        max_assurance_drop=max_assurance_drop,
        min_event_retention=min_event_retention,
    ).to_dict()


def detection_pack_sweep(
    events: Sequence[NormalizedEvent], *, pack_path: str | Path | None = None
) -> dict[str, object]:
    """Evaluate reusable detection content without scenario answer keys."""

    return sweep_detection_pack(load_detection_pack(pack_path), events).to_dict()


def build_live_query(specification: QuerySpec) -> QueryPlan:
    return build_query_plan(specification)


def execute_live_query(
    plan: QueryPlan,
    *,
    allow_network: bool = False,
    transport: QueryTransport | None = None,
    environ: Mapping[str, str] | None = None,
) -> LiveQueryResult:
    return execute_query_plan(
        plan,
        allow_network=allow_network,
        transport=transport,
        environ=environ,
    )


def evaluate_live_telemetry(
    ability_ids: Sequence[str],
    events: Sequence[NormalizedEvent],
    *,
    ability_packs: Sequence[str | Path] = (),
) -> tuple[dict[str, object], ...]:
    abilities = load_ability_registry(ability_packs)
    unknown = sorted(set(ability_ids) - set(abilities))
    if unknown:
        raise ValueError(f"unknown abilities: {', '.join(unknown)}")
    outcomes = evaluate_live_registry(
        {ability_id: abilities[ability_id] for ability_id in ability_ids}, events
    )
    return tuple(outcome.to_dict() for outcome in outcomes)


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


def run_reference_agent_lab(fixture_id: str = "all") -> tuple[ReferenceLabRun, ...]:
    return (
        run_reference_suite()
        if fixture_id == "all"
        else (run_reference_fixture(fixture_id),)
    )


def external_plan(adapter: str, **parameters: str) -> ExternalPlan:
    return build_external_plan(adapter, **parameters)
