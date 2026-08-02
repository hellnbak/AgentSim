"""AgentSim v1 CLI with backwards-compatible legacy flags."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Mapping, Sequence

from agentsim import __version__
from agentsim.content import load_ability_registry, load_campaign_registry
from agentsim.defense import analyze_gaps, generate_runbook, run_regression
from agentsim.detection import (
    analyze_coverage,
    evaluate_live_registry,
    evaluate_rule,
    generate_candidate,
    load_detection_pack,
    load_rule,
    sweep_detection_pack,
)
from agentsim.detection.renderers import FORMATS, render_candidate, write_candidate_bundle
from agentsim.external import adapter_names, build_external_plan
from agentsim.lab import (
    list_fixtures,
    run_fixture,
    run_lab_suite,
    run_reference_fixture,
    run_reference_suite,
)
from agentsim.lab.server import serve_reference_lab
from agentsim.models.campaign import CampaignDefinition, CampaignStep
from agentsim.models.target import TargetProfile
from agentsim.orchestration.planner import plan_campaign
from agentsim.orchestration.runner import CampaignRunner
from agentsim.plugins import discover_plugins
from agentsim.reporting.attack_flow import export_campaign, import_campaign
from agentsim.safety.authorization import load_authorization_manifest
from agentsim.storage import RunStore
from agentsim.telemetry.collectors import COLLECTOR_NAMES, collector_for
from agentsim.telemetry.assurance import assess_telemetry
from agentsim.telemetry.connectors import CONNECTOR_NAMES, QuerySpec, build_query_plan, execute_query_plan


FOUNDATION_COMMANDS = {
    "ability",
    "campaign",
    "history",
    "telemetry",
    "detection",
    "defense",
    "lab",
    "external",
    "attack-flow",
    "plugin",
}


def _add_content_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--ability-pack", action="append", default=[], metavar="PATH")
    parser.add_argument("--campaign-pack", action="append", default=[], metavar="PATH")


def _add_run_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--authorization", required=True, metavar="PATH")
    parser.add_argument("--target", required=True, metavar="URI")
    parser.add_argument("--mode", choices=("simulate", "emulate", "lab"), default="simulate")
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--output-dir", default="agent_sim_campaign_runs", metavar="PATH")
    parser.add_argument("--database", default="agent_sim_runs.db", metavar="PATH")
    parser.add_argument("--detection-results", metavar="PATH")
    _add_content_options(parser)


def build_foundation_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentsim",
        description="Detection-first adversary emulation for endpoints, cloud, and agentic AI.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    ability = commands.add_parser("ability", help="Inspect or run reviewed ability content.")
    ability_commands = ability.add_subparsers(dest="ability_command", required=True)
    ability_list = ability_commands.add_parser("list", help="List reviewed abilities.")
    ability_list.add_argument("--ability-pack", action="append", default=[], metavar="PATH")
    ability_run = ability_commands.add_parser("run", help="Run one ability as a gated campaign.")
    ability_run.add_argument("ability_id")
    _add_run_options(ability_run)

    campaign = commands.add_parser("campaign", help="Plan and run directed campaigns.")
    campaign_commands = campaign.add_subparsers(dest="campaign_command", required=True)
    campaign_list = campaign_commands.add_parser("list", help="List campaigns.")
    _add_content_options(campaign_list)
    campaign_plan = campaign_commands.add_parser("plan", help="Preview authorization decisions.")
    campaign_plan.add_argument("campaign_id")
    _add_run_options(campaign_plan)
    campaign_run = campaign_commands.add_parser("run", help="Run a gated campaign.")
    campaign_run.add_argument("campaign_id")
    _add_run_options(campaign_run)
    campaign_history = campaign_commands.add_parser("history", help="Show persisted run history.")
    campaign_history.add_argument("--database", default="agent_sim_runs.db", metavar="PATH")
    campaign_history.add_argument("--limit", type=int, default=25)

    history = commands.add_parser("history", help="Alias for campaign history.")
    history.add_argument("--database", default="agent_sim_runs.db", metavar="PATH")
    history.add_argument("--limit", type=int, default=25)

    telemetry = commands.add_parser("telemetry", help="Normalize exports or query a SIEM read-only.")
    telemetry_commands = telemetry.add_subparsers(dest="telemetry_command", required=True)
    telemetry_inspect = telemetry_commands.add_parser("inspect", help="Summarize a telemetry export.")
    telemetry_inspect.add_argument("path")
    telemetry_inspect.add_argument("--collector", choices=COLLECTOR_NAMES, default="jsonl")
    telemetry_doctor = telemetry_commands.add_parser(
        "doctor", help="Assess redaction, identity, timestamp, and causal-link integrity."
    )
    telemetry_doctor.add_argument("path")
    telemetry_doctor.add_argument("--collector", choices=COLLECTOR_NAMES, default="jsonl")
    telemetry_doctor.add_argument("--output")
    telemetry_doctor.add_argument(
        "--fail-on", choices=("never", "degraded", "unusable"), default="unusable"
    )
    telemetry_query = telemetry_commands.add_parser(
        "query", help="Plan or explicitly execute an exact-target, read-only SIEM query."
    )
    telemetry_query.add_argument("connector", choices=CONNECTOR_NAMES)
    telemetry_query.add_argument("--base-url", required=True)
    telemetry_query.add_argument("--dataset", required=True)
    telemetry_query.add_argument("--target", required=True)
    telemetry_query.add_argument("--since", required=True)
    telemetry_query.add_argument("--until", required=True)
    telemetry_query.add_argument("--limit", type=int, default=1000)
    telemetry_query.add_argument("--target-field")
    telemetry_query.add_argument("--credential-env")
    telemetry_query.add_argument("--execute", action="store_true")
    telemetry_query.add_argument("--allow-network", action="store_true")
    telemetry_query.add_argument("--ability", action="append", default=[])
    telemetry_query.add_argument("--run-id", help="Link outcomes to an existing campaign run.")
    telemetry_query.add_argument("--ability-pack", action="append", default=[], metavar="PATH")
    telemetry_query.add_argument("--include-events", action="store_true")
    telemetry_query.add_argument("--output")
    telemetry_query.add_argument("--database", default="agent_sim_runs.db", metavar="PATH")
    telemetry_history = telemetry_commands.add_parser(
        "query-history", help="Show redacted live-query audit history."
    )
    telemetry_history.add_argument("--database", default="agent_sim_runs.db", metavar="PATH")
    telemetry_history.add_argument("--limit", type=int, default=25)

    detection = commands.add_parser("detection", help="Evaluate and generate detection rules.")
    detection_commands = detection.add_subparsers(dest="detection_command", required=True)
    detection_evaluate = detection_commands.add_parser("evaluate", help="Evaluate a detection AST rule.")
    detection_evaluate.add_argument("rule")
    detection_evaluate.add_argument("telemetry")
    detection_evaluate.add_argument("--collector", choices=COLLECTOR_NAMES, default="jsonl")
    detection_sweep = detection_commands.add_parser(
        "sweep", help="Run an answer-key-free detection pack across normalized evidence."
    )
    detection_sweep.add_argument("telemetry")
    detection_sweep.add_argument("--collector", choices=COLLECTOR_NAMES, default="jsonl")
    detection_sweep.add_argument("--pack")
    detection_sweep.add_argument("--output")
    detection_sweep.add_argument("--fail-on-visibility-gap", action="store_true")
    detection_generate = detection_commands.add_parser("generate", help="Generate a candidate detection.")
    detection_generate.add_argument("ability_id")
    detection_generate.add_argument("--format", choices=FORMATS)
    detection_generate.add_argument("--output-dir")
    detection_generate.add_argument("--ability-pack", action="append", default=[], metavar="PATH")

    defense = commands.add_parser("defense", help="Analyze visibility and run detection regression.")
    defense_commands = defense.add_subparsers(dest="defense_command", required=True)
    defense_analyze = defense_commands.add_parser("analyze", help="Find telemetry gaps for one ability.")
    defense_analyze.add_argument("ability_id")
    defense_analyze.add_argument("telemetry")
    defense_analyze.add_argument("--collector", choices=COLLECTOR_NAMES, default="jsonl")
    defense_analyze.add_argument("--ability-pack", action="append", default=[], metavar="PATH")
    defense_regress = defense_commands.add_parser("regress", help="Test malicious and benign fixtures.")
    defense_regress.add_argument("rule")
    defense_regress.add_argument("--malicious", required=True)
    defense_regress.add_argument("--benign", required=True)
    defense_regress.add_argument("--collector", choices=COLLECTOR_NAMES, default="jsonl")

    lab = commands.add_parser("lab", help="Run in-memory or instrumented reference-agent fixtures.")
    lab_commands = lab.add_subparsers(dest="lab_command", required=True)
    lab_commands.add_parser("list", help="List agentic lab fixtures.")
    lab_run = lab_commands.add_parser("run", help="Run one fixture or the complete suite.")
    lab_run.add_argument("fixture_id", nargs="?", default="all")
    lab_run.add_argument("--output")
    lab_reference = lab_commands.add_parser(
        "reference", help="Run the instrumented reference agent with fixed synthetic tools."
    )
    lab_reference.add_argument("fixture_id", nargs="?", default="all")
    lab_reference.add_argument("--output")
    lab_serve = lab_commands.add_parser(
        "serve", help="Serve the synthetic reference lab on an explicitly allowed loopback socket."
    )
    lab_serve.add_argument("--host", default="127.0.0.1")
    lab_serve.add_argument("--port", type=int, default=8765)
    lab_serve.add_argument("--allow-loopback", action="store_true")

    external = commands.add_parser("external", help="Build version-pinned external provider plans.")
    external_commands = external.add_subparsers(dest="external_command", required=True)
    external_commands.add_parser("list", help="List external provider adapters.")
    external_plan = external_commands.add_parser("plan", help="Create a non-executing provider plan.")
    external_plan.add_argument("adapter", choices=adapter_names())
    external_plan.add_argument("--provider-version", required=True)
    external_plan.add_argument("--target", required=True)
    external_plan.add_argument("--technique-id")
    external_plan.add_argument("--test-guid")
    external_plan.add_argument("--adversary-id")
    external_plan.add_argument("--server-url")
    external_plan.add_argument("--output")

    attack_flow = commands.add_parser("attack-flow", help="Import or export Attack Flow STIX 2.1.")
    attack_flow_commands = attack_flow.add_subparsers(dest="attack_flow_command", required=True)
    attack_flow_export = attack_flow_commands.add_parser("export", help="Export a built-in campaign.")
    attack_flow_export.add_argument("campaign_id")
    attack_flow_export.add_argument("--output", required=True)
    _add_content_options(attack_flow_export)
    attack_flow_import = attack_flow_commands.add_parser("import", help="Map an Attack Flow to abilities.")
    attack_flow_import.add_argument("path")
    attack_flow_import.add_argument("--output", required=True)
    attack_flow_import.add_argument("--ability-pack", action="append", default=[], metavar="PATH")

    plugin = commands.add_parser("plugin", help="Inspect installed v1 plugin entry points.")
    plugin_commands = plugin.add_subparsers(dest="plugin_command", required=True)
    plugin_commands.add_parser("list", help="List plugins without importing their code.")
    return parser


def _load_detection_results(path: str | None) -> Mapping[str, bool] | None:
    if path is None:
        return None
    candidate = Path(path)
    if not candidate.is_file():
        raise FileNotFoundError(f"detection-results file does not exist: {candidate}")
    value = json.loads(candidate.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or any(
        not isinstance(key, str) or not isinstance(result, bool)
        for key, result in value.items()
    ):
        raise ValueError("detection-results must be an object mapping ability IDs to booleans")
    return value


def _resolve_content(args: argparse.Namespace):
    abilities = load_ability_registry(args.ability_pack)
    campaigns = load_campaign_registry(args.campaign_pack)
    return abilities, campaigns


def _emit_json(value: object, path: str | None = None) -> None:
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if path:
        Path(path).write_text(rendered, encoding="utf-8")
        print(path)
    else:
        print(rendered, end="")


def _campaign_value(campaign: CampaignDefinition) -> dict[str, object]:
    return {
        "id": campaign.campaign_id,
        "name": campaign.name,
        "description": campaign.description,
        "objective": campaign.objective,
        "target_profile": campaign.target_profile,
        "authorization_required": campaign.authorization_required,
        "steps": [
            {
                "id": step.step_id,
                "ability_id": step.ability_id,
                "depends_on": list(step.depends_on),
                "on_failure": step.on_failure,
            }
            for step in campaign.steps
        ],
        "required_telemetry": list(campaign.required_telemetry),
        "stop_conditions": list(campaign.stop_conditions),
        "metadata": dict(campaign.metadata),
    }


def _run_v1(args: argparse.Namespace) -> int | None:
    if args.command == "telemetry" and args.telemetry_command == "inspect":
        events = collector_for(args.collector).collect(args.path)
        _emit_json(
            {
                "schema_version": "1.0",
                "collector": args.collector,
                "record_count": len(events),
                "sources": sorted({event.source for event in events}),
                "event_types": sorted({event.event_type for event in events}),
                "available_fields": sorted(
                    {field for event in events for field in event.available_fields}
                ),
                "sensitive_values_recorded": False,
            }
        )
        return 0
    if args.command == "telemetry" and args.telemetry_command == "doctor":
        report = assess_telemetry(collector_for(args.collector).collect(args.path))
        _emit_json(report.to_dict(), args.output)
        if args.fail_on == "never":
            return 0
        if args.fail_on == "degraded":
            return 0 if report.status == "healthy" else 1
        return 1 if report.status == "unusable" else 0
    if args.command == "telemetry" and args.telemetry_command == "query-history":
        _emit_json(RunStore(args.database).telemetry_query_history(args.limit))
        return 0
    if args.command == "telemetry" and args.telemetry_command == "query":
        spec = QuerySpec(
            connector=args.connector,
            base_url=args.base_url,
            dataset=args.dataset,
            target=args.target,
            since=args.since,
            until=args.until,
            limit=args.limit,
            target_field=args.target_field,
            credential_env=args.credential_env,
        )
        plan = build_query_plan(spec)
        if not args.execute:
            _emit_json(plan.to_dict(), args.output)
            return 0
        result = execute_query_plan(plan, allow_network=args.allow_network)
        store = RunStore(args.database)
        selected_ability_ids = list(args.ability)
        if args.run_id:
            selected_ability_ids.extend(store.ability_ids_for_run(args.run_id))
        selected_ability_ids = sorted(set(selected_ability_ids))
        outcomes = ()
        if selected_ability_ids:
            abilities = load_ability_registry(args.ability_pack)
            unknown = sorted(set(selected_ability_ids) - set(abilities))
            if unknown:
                raise ValueError(f"unknown abilities: {', '.join(unknown)}")
            outcomes = evaluate_live_registry(
                {ability_id: abilities[ability_id] for ability_id in selected_ability_ids},
                result.events,
            )
        query_id = uuid.uuid4().hex
        value = {
            "query_id": query_id,
            "campaign_run_id": args.run_id,
            **result.to_dict(include_events=args.include_events),
            "detection_outcomes": [outcome.to_dict() for outcome in outcomes],
        }
        audit = {
            key: item for key, item in value.items() if key not in {"events"}
        }
        store.record_telemetry_query(query_id, audit, run_id=args.run_id)
        if args.run_id:
            outcome_values = [outcome.to_dict() for outcome in outcomes]
            for outcome in outcomes:
                store.append_detection(
                    args.run_id,
                    rule_id=outcome.rule_id,
                    ability_id=outcome.ability_id,
                    matched=outcome.matched,
                    evaluation=outcome.to_dict(),
                )
            store.apply_detection_outcomes(args.run_id, outcome_values)
        _emit_json(value, args.output)
        if args.run_id and args.output:
            output_path = Path(args.output)
            store.record_artifact(
                args.run_id,
                artifact_type=f"live_detection_{query_id}",
                path=str(output_path.resolve()),
                sha256=hashlib.sha256(output_path.read_bytes()).hexdigest(),
                metadata={"connector": args.connector, "query_id": query_id},
            )
        return 0 if all(outcome.status == "detected" for outcome in outcomes) else 1
    if args.command == "detection" and args.detection_command == "evaluate":
        result = evaluate_rule(
            load_rule(args.rule), collector_for(args.collector).collect(args.telemetry)
        )
        _emit_json(result.to_dict())
        return 0 if result.matched else 1
    if args.command == "detection" and args.detection_command == "sweep":
        report = sweep_detection_pack(
            load_detection_pack(args.pack),
            collector_for(args.collector).collect(args.telemetry),
        )
        value = report.to_dict()
        _emit_json(value, args.output)
        if args.fail_on_visibility_gap and value["summary"]["visibility_gap"]:
            return 1
        return 0
    if args.command == "detection" and args.detection_command == "generate":
        abilities = load_ability_registry(args.ability_pack)
        if args.ability_id not in abilities:
            raise ValueError(f"unknown ability: {args.ability_id}")
        candidate = generate_candidate(abilities[args.ability_id])
        if args.output_dir:
            print(write_candidate_bundle(candidate, args.output_dir))
        elif args.format:
            print(render_candidate(candidate, args.format), end="")
        else:
            _emit_json(candidate.to_dict())
        return 0
    if args.command == "defense" and args.defense_command == "analyze":
        abilities = load_ability_registry(args.ability_pack)
        if args.ability_id not in abilities:
            raise ValueError(f"unknown ability: {args.ability_id}")
        ability = abilities[args.ability_id]
        events = collector_for(args.collector).collect(args.telemetry)
        coverage = analyze_coverage(ability, events)
        findings = analyze_gaps(abilities, (coverage,))
        _emit_json(
            {
                "coverage": coverage.to_dict(),
                "findings": [finding.to_dict() for finding in findings],
                "runbook": generate_runbook(ability, findings),
            }
        )
        return 0 if not findings else 1
    if args.command == "defense" and args.defense_command == "regress":
        collector = collector_for(args.collector)
        result = run_regression(
            load_rule(args.rule), collector.collect(args.malicious), collector.collect(args.benign)
        )
        _emit_json(result.to_dict())
        return 0 if result.passed else 1
    if args.command == "lab" and args.lab_command == "list":
        _emit_json(
            [
                {
                    "fixture_id": fixture.fixture_id,
                    "name": fixture.name,
                    "attack_class": fixture.attack_class,
                    "control": fixture.control,
                    "atlas_techniques": list(fixture.atlas_techniques),
                    "owasp_risks": list(fixture.owasp_risks),
                }
                for fixture in list_fixtures()
            ]
        )
        return 0
    if args.command == "lab" and args.lab_command == "run":
        results = run_lab_suite() if args.fixture_id == "all" else (run_fixture(args.fixture_id),)
        value = {
            "schema_version": "1.0",
            "passed": all(result.passed for result in results),
            "results": [result.to_dict() for result in results],
        }
        _emit_json(value, args.output)
        return 0 if value["passed"] else 1
    if args.command == "lab" and args.lab_command == "reference":
        results = (
            run_reference_suite()
            if args.fixture_id == "all"
            else (run_reference_fixture(args.fixture_id),)
        )
        value = {
            "schema_version": "1.0",
            "kind": "agentsim-reference-agent-lab-suite",
            "passed": all(result.passed for result in results),
            "fixture_count": len(results),
            "results": [result.to_dict() for result in results],
        }
        _emit_json(value, args.output)
        return 0 if value["passed"] else 1
    if args.command == "lab" and args.lab_command == "serve":
        serve_reference_lab(
            args.host,
            args.port,
            allow_loopback=args.allow_loopback,
        )
        return 0
    if args.command == "external" and args.external_command == "list":
        _emit_json(
            {
                "adapters": list(adapter_names()),
                "execution_supported_by_core": False,
                "executor_plugin_group": "agentsim.external_executors",
            }
        )
        return 0
    if args.command == "external" and args.external_command == "plan":
        common = {"provider_version": args.provider_version, "target_uri": args.target}
        if args.adapter == "atomic-red-team":
            if not args.technique_id or not args.test_guid:
                raise ValueError("Atomic plans require --technique-id and --test-guid")
            parameters = {**common, "technique_id": args.technique_id, "test_guid": args.test_guid}
        elif args.adapter == "stratus-red-team":
            if not args.technique_id:
                raise ValueError("Stratus plans require --technique-id")
            parameters = {**common, "technique_id": args.technique_id}
        else:
            if not args.adversary_id or not args.server_url:
                raise ValueError("CALDERA plans require --adversary-id and --server-url")
            parameters = {
                **common,
                "adversary_id": args.adversary_id,
                "server_url": args.server_url,
            }
        plan = build_external_plan(args.adapter, **parameters)
        _emit_json(plan.to_dict(), args.output)
        return 0
    if args.command == "attack-flow" and args.attack_flow_command == "export":
        abilities, campaigns = _resolve_content(args)
        if args.campaign_id not in campaigns:
            raise ValueError(f"unknown campaign: {args.campaign_id}")
        _emit_json(export_campaign(campaigns[args.campaign_id], abilities), args.output)
        return 0
    if args.command == "attack-flow" and args.attack_flow_command == "import":
        abilities = load_ability_registry(args.ability_pack)
        value = json.loads(Path(args.path).read_text(encoding="utf-8"))
        if not isinstance(value, Mapping):
            raise ValueError("Attack Flow input must be a JSON object")
        result = import_campaign(value, abilities)
        _emit_json(
            {
                "schema_version": "1.0",
                "kind": "campaign-import-draft",
                "campaign": _campaign_value(result.campaign),
                "warnings": list(result.warnings),
                "status": "requires_review_and_pack_signature",
            },
            args.output,
        )
        return 0
    if args.command == "plugin" and args.plugin_command == "list":
        _emit_json(
            {
                "api_version": "1.0",
                "plugins": [item.to_dict() for item in discover_plugins()],
            }
        )
        return 0
    return None


def _run_foundation(args: argparse.Namespace) -> int:
    v1_result = _run_v1(args)
    if v1_result is not None:
        return v1_result
    if args.command == "ability" and args.ability_command == "list":
        for ability in load_ability_registry(args.ability_pack).values():
            mappings = ", ".join(ability.mappings.get("mitre_attack", ()))
            print(f"{ability.ability_id}\t{ability.name}\t{ability.risk}\t{mappings}")
        return 0
    if args.command == "campaign" and args.campaign_command == "list":
        abilities, campaigns = _resolve_content(args)
        for campaign in campaigns.values():
            missing = [ability for ability in campaign.ability_ids if ability not in abilities]
            suffix = f" [missing: {', '.join(missing)}]" if missing else ""
            print(f"{campaign.campaign_id}\t{campaign.name}\t{len(campaign.steps)} abilities{suffix}")
        return 0
    if args.command == "history" or (
        args.command == "campaign" and args.campaign_command == "history"
    ):
        print(json.dumps(RunStore(args.database).history(args.limit), indent=2, sort_keys=True))
        return 0

    abilities, campaigns = _resolve_content(args)
    if args.command == "ability":
        ability = abilities.get(args.ability_id)
        if ability is None:
            raise ValueError(f"unknown ability: {args.ability_id}")
        selected_campaign = CampaignDefinition(
            campaign_id=f"single-{ability.ability_id}",
            name=f"Single ability: {ability.name}",
            description="CLI-generated single-ability regression campaign.",
            objective="Run one reviewed ability through the complete lifecycle.",
            target_profile="explicit",
            steps=(CampaignStep("ability", ability.ability_id),),
            required_telemetry=tuple(
                str(item.get("source")) for item in ability.expected_telemetry if item.get("source")
            ),
            stop_conditions=("authorization_denied", "cleanup_failed", "kill_switch"),
            pack_id="agentsim.cli",
        )
        operation = "run"
    else:
        selected_campaign = campaigns.get(args.campaign_id)
        if selected_campaign is None:
            raise ValueError(f"unknown campaign: {args.campaign_id}")
        operation = args.campaign_command
    manifest = load_authorization_manifest(args.authorization)
    target = TargetProfile.from_uri(args.target)
    if operation == "plan":
        result = plan_campaign(
            selected_campaign,
            abilities,
            mode=args.mode,
            target=target,
            manifest=manifest,
            allow_network=args.allow_network,
        )
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return 0 if result.authorized else 2
    result = CampaignRunner(abilities, database_path=args.database, log_callback=print).run(
        selected_campaign,
        mode=args.mode,
        target=target,
        manifest=manifest,
        output_directory=args.output_dir,
        allow_network=args.allow_network,
        detection_results=_load_detection_results(args.detection_results),
    )
    print(
        json.dumps(
            {
                "run_id": result.run_id,
                "status": result.status,
                "summary": result.summary,
                "bundle_path": str(result.bundle_path),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if result.status == "completed" else 1


def main(argv: Sequence[str] | None = None) -> int:
    selected = list(sys.argv[1:] if argv is None else argv)
    if not selected or selected[0] not in FOUNDATION_COMMANDS:
        if selected == ["--version"]:
            print(f"agentsim {__version__}")
            return 0
        from core import main as legacy_main

        return legacy_main(selected)
    parser = build_foundation_parser()
    args = parser.parse_args(selected)
    try:
        return _run_foundation(args)
    except (FileNotFoundError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
