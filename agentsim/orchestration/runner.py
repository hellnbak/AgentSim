"""Closed-loop campaign runner with lifecycle-v3 evidence and cleanup."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping

from agentsim.defense.recommendations import recommendations_for_action
from agentsim.defense.scorecard import build_scorecard
from agentsim.detection.generator import generate_candidates
from agentsim.execution import provider_for_name
from agentsim.models.ability import AbilityDefinition
from agentsim.models.campaign import CampaignDefinition
from agentsim.models.event import ActionLifecycleEvent
from agentsim.models.result import ActionResult, CampaignRunResult
from agentsim.models.target import TargetProfile
from agentsim.reporting.bundle import write_evidence_bundle
from agentsim.reporting.attack_flow import export_campaign
from agentsim.safety.authorization import AuthorizationManifest
from agentsim.safety.policy import MODE_PROVIDER, SafetyPolicy
from agentsim.safety.resource_limits import RunLimits
from agentsim.storage import RunStore
from agentsim.telemetry.ground_truth import append_event

from .planner import plan_campaign


Clock = Callable[[], datetime]
LogCallback = Callable[[str], None]


def _timestamp(clock: Clock) -> str:
    value = clock()
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


class CampaignRunner:
    """Plan, authorize, run, clean, verify, persist, and report a campaign."""

    def __init__(
        self,
        abilities: Mapping[str, AbilityDefinition],
        *,
        database_path: str | Path = "agent_sim_runs.db",
        policy: SafetyPolicy | None = None,
        clock: Clock | None = None,
        log_callback: LogCallback | None = None,
    ) -> None:
        self.abilities = dict(abilities)
        self.database_path = Path(database_path)
        self.policy = policy or SafetyPolicy()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.log = log_callback or (lambda _message: None)

    def run(
        self,
        campaign: CampaignDefinition,
        *,
        mode: str,
        target: TargetProfile,
        manifest: AuthorizationManifest,
        output_directory: str | Path,
        allow_network: bool = False,
        detection_results: Mapping[str, bool] | None = None,
        run_id: str | None = None,
        limits: RunLimits | None = None,
    ) -> CampaignRunResult:
        provider_name = MODE_PROVIDER.get(mode)
        if provider_name is None:
            raise ValueError("mode must be simulate, emulate, or lab")
        plan = plan_campaign(
            campaign,
            self.abilities,
            mode=mode,
            target=target,
            manifest=manifest,
            allow_network=allow_network,
            policy=self.policy,
            now=self.clock(),
        )
        selected_run_id = run_id or uuid.uuid4().hex
        output_root = Path(output_directory)
        output_root.mkdir(parents=True, exist_ok=True)
        run_directory = output_root / selected_run_id
        run_directory.mkdir(exist_ok=False)
        manifest_path = run_directory / "run-manifest.json"
        timeline_path = run_directory / "action-lifecycle.jsonl"
        report_path = run_directory / "campaign-report.json"
        bundle_path = run_directory / "evidence.zip"
        scorecard_path = run_directory / "defense-scorecard.json"
        runbooks_path = run_directory / "defense-runbooks.json"
        candidates_path = run_directory / "detection-candidates.json"
        attack_flow_path = run_directory / "attack-flow.json"
        started_at = _timestamp(self.clock)
        manifest_value: dict[str, object] = {
            "schema_version": "1.0",
            "run_id": selected_run_id,
            "campaign_id": campaign.campaign_id,
            "campaign_pack_id": campaign.pack_id,
            "mode": mode,
            "provider": provider_name,
            "target_uri": target.uri,
            "target_environment": target.environment,
            "authorization_id": manifest.manifest_id,
            "authorization": manifest.to_dict(),
            "started_at": started_at,
            "allow_network": allow_network,
            "ability_ids": list(campaign.ability_ids),
            "plan": plan.to_dict(),
        }
        canonical_manifest = json.dumps(
            manifest_value, sort_keys=True, separators=(",", ":")
        )
        manifest_sha256 = hashlib.sha256(canonical_manifest.encode("utf-8")).hexdigest()
        manifest_value["manifest_sha256"] = manifest_sha256
        manifest_path.write_text(
            json.dumps(manifest_value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        timeline_path.touch(exist_ok=False)
        store = RunStore(self.database_path)
        store.create_run(manifest_value, manifest_sha256)
        selected_limits = limits or RunLimits(manifest)
        provider = provider_for_name(provider_name)
        detection_map = dict(detection_results or {})
        actions: list[ActionResult] = []
        recommendations: list[dict[str, object]] = []
        sequence = 0

        def emit(
            *,
            ability: AbilityDefinition,
            action_id: str,
            state: str,
            outcome: str,
            message: str,
            parent_event_id: str | None,
            attributes: Mapping[str, object] | None = None,
        ) -> str:
            nonlocal sequence
            sequence += 1
            event_id = f"{selected_run_id}:{sequence:05d}"
            telemetry = tuple(
                str(item.get("source"))
                for item in ability.expected_telemetry
                if item.get("source")
            )
            event = ActionLifecycleEvent(
                timestamp=_timestamp(self.clock),
                event_id=event_id,
                parent_event_id=parent_event_id,
                run_id=selected_run_id,
                campaign_id=campaign.campaign_id,
                ability_id=ability.ability_id,
                action_id=action_id,
                sequence=sequence,
                lifecycle_state=state,
                provider=provider_name,
                target_uri=target.uri,
                authorization_id=manifest.manifest_id,
                outcome=outcome,
                message=message,
                attack_mappings=tuple(ability.mappings.get("mitre_attack", ())),
                atlas_mappings=tuple(ability.mappings.get("mitre_atlas", ())),
                expected_telemetry=telemetry,
                attributes=dict(attributes or {}),
            ).to_dict()
            append_event(timeline_path, event)
            store.append_event(event)
            return event_id

        stop_campaign = False
        for action_index, step in enumerate(campaign.steps, 1):
            if stop_campaign:
                break
            ability = self.abilities[step.ability_id]
            action_id = f"{selected_run_id}:{step.step_id}"
            action_started = time.monotonic()
            parent_id = emit(
                ability=ability,
                action_id=action_id,
                state="planned",
                outcome="planned",
                message=f"Planned reviewed ability {ability.name}.",
                parent_event_id=None,
                attributes={"step_id": step.step_id, "action_index": action_index},
            )
            decision = self.policy.authorize(
                ability,
                mode=mode,
                target=target,
                manifest=manifest,
                run_allows_network=allow_network,
                now=self.clock(),
            )
            if not decision.allowed:
                parent_id = emit(
                    ability=ability,
                    action_id=action_id,
                    state="denied",
                    outcome="prevented",
                    message=decision.reason,
                    parent_event_id=parent_id,
                )
                emit(
                    ability=ability,
                    action_id=action_id,
                    state="prevented",
                    outcome="prevented",
                    message="Safety policy prevented the ability before preparation.",
                    parent_event_id=parent_id,
                )
                result = ActionResult(
                    action_id=action_id,
                    ability_id=ability.ability_id,
                    status="prevented",
                    authorized=False,
                    attempted=False,
                    executed=False,
                    observed=True,
                    detection_status="not_applicable",
                    cleanup_status="not_required",
                    duration_ms=int((time.monotonic() - action_started) * 1000),
                    error=decision.reason,
                    defenses=ability.defenses,
                )
                actions.append(result)
                store.append_action(selected_run_id, asdict(result))
                stop_campaign = step.on_failure == "stop"
                continue

            parent_id = emit(
                ability=ability,
                action_id=action_id,
                state="authorized",
                outcome="allowed",
                message=decision.reason,
                parent_event_id=parent_id,
            )
            provider_result = None
            cleanup_status = "not_started"
            error: str | None = None
            action_cancelled = False
            try:
                selected_limits.before_action()
                provider.prepare(ability, target)
                parent_id = emit(
                    ability=ability,
                    action_id=action_id,
                    state="prepared",
                    outcome="ready",
                    message="Provider prerequisites and reviewed command reference validated.",
                    parent_event_id=parent_id,
                    attributes={"command_ref": ability.execution.command_ref},
                )
                parent_id = emit(
                    ability=ability,
                    action_id=action_id,
                    state="attempted",
                    outcome="simulated" if mode == "simulate" else "attempted",
                    message=(
                        "Simulation provider recorded intent without starting a process."
                        if mode == "simulate"
                        else "Provider started the reviewed static command sequence."
                    ),
                    parent_event_id=parent_id,
                    attributes={"execution_attempted": mode != "simulate"},
                )
                provider_result = provider.execute(ability, target, selected_limits)
                execution_state = (
                    "simulated"
                    if provider_result.status == "simulated"
                    else "executed"
                    if provider_result.executed and provider_result.status == "executed"
                    else "failed"
                )
                parent_id = emit(
                    ability=ability,
                    action_id=action_id,
                    state=execution_state,
                    outcome=provider_result.status,
                    message=(
                        "Ability behavior was safely simulated."
                        if execution_state == "simulated"
                        else "Reviewed ability execution completed."
                        if execution_state == "executed"
                        else "Reviewed ability execution did not complete successfully."
                    ),
                    parent_event_id=parent_id,
                    attributes={
                        "executed": provider_result.executed,
                        "return_codes": list(provider_result.return_codes),
                        "output_digest": provider_result.output_digest,
                        "output_bytes": provider_result.output_bytes,
                        "sensitive_output_recorded": False,
                    },
                )
                parent_id = emit(
                    ability=ability,
                    action_id=action_id,
                    state="observed",
                    outcome="observed",
                    message="Ground truth recorded the provider outcome and expected telemetry markers.",
                    parent_event_id=parent_id,
                )
                detected = detection_map.get(ability.ability_id)
                detection_status = (
                    "detected" if detected is True else "missed" if detected is False else "not_evaluated"
                )
                detection_state = (
                    "detected" if detected is True else "missed" if detected is False else "detection_pending"
                )
                parent_id = emit(
                    ability=ability,
                    action_id=action_id,
                    state=detection_state,
                    outcome=detection_status,
                    message=(
                        "Provided detection result matched this ability."
                        if detected is True
                        else "Provided detection result did not match this ability."
                        if detected is False
                        else "No external detection result was supplied; validation remains pending."
                    ),
                    parent_event_id=parent_id,
                    attributes={"detection_objectives": list(ability.detection_objectives)},
                )
                recommendations.extend(recommendations_for_action(ability, detection_status))
            except (OSError, RuntimeError, ValueError) as exc:
                error = str(exc)
                action_cancelled = selected_limits.cancelled()
                detection_status = "not_evaluated"
                parent_id = emit(
                    ability=ability,
                    action_id=action_id,
                    state="cancelled" if action_cancelled else "failed",
                    outcome="cancelled" if action_cancelled else "failed",
                    message=(
                        "The run kill switch cancelled the action."
                        if action_cancelled
                        else "Provider preparation or execution failed within the safety boundary."
                    ),
                    parent_event_id=parent_id,
                    attributes={"error": error},
                )
            finally:
                parent_id = emit(
                    ability=ability,
                    action_id=action_id,
                    state="cleanup_started",
                    outcome="cleanup",
                    message="Cleanup verification started.",
                    parent_event_id=parent_id,
                )
                try:
                    cleanup_result = provider.cleanup(ability, target, selected_limits)
                    cleanup_ok = cleanup_result.status in {"verified_noop", "executed"}
                    cleanup_status = "cleaned" if cleanup_ok else "cleanup_failed"
                    parent_id = emit(
                        ability=ability,
                        action_id=action_id,
                        state=cleanup_status,
                        outcome=cleanup_result.status,
                        message=(
                            "Cleanup completed or the read-only no-op cleanup was verified."
                            if cleanup_ok
                            else "Cleanup did not complete successfully."
                        ),
                        parent_event_id=parent_id,
                        attributes={"cleanup_ref": ability.execution.cleanup_ref},
                    )
                except (OSError, RuntimeError, ValueError) as exc:
                    cleanup_status = "cleanup_failed"
                    error = error or str(exc)
                    parent_id = emit(
                        ability=ability,
                        action_id=action_id,
                        state="cleanup_failed",
                        outcome="failed",
                        message="Cleanup attempt failed.",
                        parent_event_id=parent_id,
                        attributes={"error": str(exc)},
                    )

            provider_succeeded = provider_result is not None and provider_result.status in {
                "simulated",
                "executed",
            }
            verified = provider_succeeded and cleanup_status == "cleaned" and error is None
            emit(
                ability=ability,
                action_id=action_id,
                state="verified" if verified else "cancelled" if action_cancelled else "failed",
                outcome="passed" if verified else "cancelled" if action_cancelled else "failed",
                message=(
                    "Ability lifecycle and cleanup evidence were verified."
                    if verified
                    else "The cancelled action completed its cleanup path."
                    if action_cancelled
                    else "Ability lifecycle requires review."
                ),
                parent_event_id=parent_id,
            )
            status = (
                "simulated"
                if verified and mode == "simulate"
                else "completed"
                if verified
                else "cancelled"
                if action_cancelled
                else "failed"
            )
            result = ActionResult(
                action_id=action_id,
                ability_id=ability.ability_id,
                status=status,
                authorized=True,
                attempted=bool(provider_result and provider_result.attempted),
                executed=bool(provider_result and provider_result.executed),
                observed=provider_result is not None,
                detection_status=detection_status,
                cleanup_status=cleanup_status,
                duration_ms=int((time.monotonic() - action_started) * 1000),
                output_digest=provider_result.output_digest if provider_result else None,
                error=error or (provider_result.error if provider_result else None),
                defenses=ability.defenses,
            )
            actions.append(result)
            store.append_action(selected_run_id, asdict(result))
            if action_cancelled or (not verified and step.on_failure == "stop"):
                stop_campaign = True

        failed_count = sum(
            action.status in {"failed", "prevented", "cancelled"} for action in actions
        )
        status = (
            "cancelled"
            if selected_limits.cancelled()
            else "completed"
            if not failed_count and len(actions) == len(campaign.steps)
            else "completed_with_gaps"
        )
        summary = {
            "planned_actions": len(campaign.steps),
            "completed_actions": len(actions),
            "verified_actions": sum(action.status in {"simulated", "completed"} for action in actions),
            "failed_or_prevented_actions": failed_count,
            "executed_actions": sum(action.executed for action in actions),
            "simulated_actions": sum(action.status == "simulated" for action in actions),
            "detections": sum(action.detection_status == "detected" for action in actions),
            "misses": sum(action.detection_status == "missed" for action in actions),
            "pending_detection_results": sum(
                action.detection_status == "not_evaluated" for action in actions
            ),
            "cleanup_failures": sum(action.cleanup_status == "cleanup_failed" for action in actions),
        }
        finished_at = _timestamp(self.clock)
        report = {
            "schema_version": "1.0",
            "run_id": selected_run_id,
            "campaign_id": campaign.campaign_id,
            "status": status,
            "started_at": started_at,
            "finished_at": finished_at,
            "manifest_sha256": manifest_sha256,
            "summary": summary,
            "actions": [asdict(action) for action in actions],
            "defense_recommendations": recommendations,
        }
        evaluated_detections = summary["detections"] + summary["misses"]
        scorecard = build_scorecard(
            total_abilities=len(actions),
            covered_abilities=0,
            evaluated_detections=evaluated_detections,
            detected_abilities=summary["detections"],
            cleanup_attempts=len(actions),
            successful_cleanups=sum(action.cleanup_status == "cleaned" for action in actions),
        ).to_dict()
        scorecard["telemetry_status"] = "not_collected"
        scorecard["detection_status"] = (
            "evaluated" if evaluated_detections else "not_evaluated"
        )
        report["defense_scorecard"] = scorecard
        report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        scorecard_path.write_text(
            json.dumps(scorecard, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        runbooks_path.write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "run_id": selected_run_id,
                    "recommendations": recommendations,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        candidates_path.write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "status": "candidates_require_human_review",
                    "candidates": [
                        item.to_dict()
                        for item in generate_candidates(
                            {ability_id: self.abilities[ability_id] for ability_id in campaign.ability_ids}
                        )
                    ],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        attack_flow_path.write_text(
            json.dumps(export_campaign(campaign, self.abilities), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        extra_artifacts = {
            "defense-scorecard.json": scorecard_path,
            "defense-runbooks.json": runbooks_path,
            "detection-candidates.json": candidates_path,
            "attack-flow.json": attack_flow_path,
        }
        write_evidence_bundle(
            bundle_path,
            manifest_path=manifest_path,
            timeline_path=timeline_path,
            report_path=report_path,
            artifacts=extra_artifacts,
        )
        for artifact_type, artifact_path in {
            "manifest": manifest_path,
            "timeline": timeline_path,
            "report": report_path,
            "scorecard": scorecard_path,
            "runbooks": runbooks_path,
            "detection_candidates": candidates_path,
            "attack_flow": attack_flow_path,
            "bundle": bundle_path,
        }.items():
            store.record_artifact(
                selected_run_id,
                artifact_type=artifact_type,
                path=str(artifact_path),
                sha256=hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
            )
        store.finish_run(
            selected_run_id,
            finished_at=finished_at,
            status=status,
            summary=summary,
        )
        self.log(
            f"[+] Campaign {campaign.campaign_id} {status}: "
            f"{summary['verified_actions']}/{summary['planned_actions']} verified."
        )
        return CampaignRunResult(
            run_id=selected_run_id,
            campaign_id=campaign.campaign_id,
            mode=mode,
            provider=provider_name,
            target_uri=target.uri,
            status=status,
            actions=tuple(actions),
            manifest_path=manifest_path,
            timeline_path=timeline_path,
            report_path=report_path,
            bundle_path=bundle_path,
            summary=summary,
        )
