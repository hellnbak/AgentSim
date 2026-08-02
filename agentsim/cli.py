"""AgentSim v0.4 CLI with backwards-compatible legacy flags."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Mapping, Sequence

from agentsim import __version__
from agentsim.content import load_ability_registry, load_campaign_registry
from agentsim.models.campaign import CampaignDefinition, CampaignStep
from agentsim.models.target import TargetProfile
from agentsim.orchestration.planner import plan_campaign
from agentsim.orchestration.runner import CampaignRunner
from agentsim.safety.authorization import load_authorization_manifest
from agentsim.storage import RunStore


FOUNDATION_COMMANDS = {"ability", "campaign", "history"}


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


def _run_foundation(args: argparse.Namespace) -> int:
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
