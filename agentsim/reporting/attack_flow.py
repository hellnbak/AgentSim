"""Attack Flow STIX 2.1 import and export for directed AgentSim campaigns."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping, Sequence

from agentsim.models.ability import AbilityDefinition
from agentsim.models.campaign import CampaignDefinition, CampaignStep


ATTACK_FLOW_EXTENSION_ID = "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4"
_NAMESPACE = uuid.UUID("41be779e-776b-4c4d-bd0e-c394741f1263")


def _stix_id(kind: str, value: str) -> str:
    return f"{kind}--{uuid.uuid5(_NAMESPACE, value)}"


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _extension() -> dict[str, object]:
    return {ATTACK_FLOW_EXTENSION_ID: {"extension_type": "new-sdo"}}


def export_campaign(
    campaign: CampaignDefinition, abilities: Mapping[str, AbilityDefinition]
) -> dict[str, object]:
    """Export a campaign as a STIX 2.1 Attack Flow emulation plan."""

    timestamp = _timestamp()
    identity_id = _stix_id("identity", "agentsim")
    action_ids = {
        step.step_id: _stix_id("attack-action", f"{campaign.campaign_id}:{step.step_id}")
        for step in campaign.steps
    }
    dependants: dict[str, list[str]] = {step.step_id: [] for step in campaign.steps}
    for step in campaign.steps:
        for dependency in step.depends_on:
            if dependency in dependants:
                dependants[dependency].append(action_ids[step.step_id])
    actions: list[dict[str, object]] = []
    for step in campaign.steps:
        ability = abilities[step.ability_id]
        attack_ids = tuple(ability.mappings.get("mitre_attack", ()))
        action: dict[str, object] = {
            "type": "attack-action",
            "spec_version": "2.1",
            "id": action_ids[step.step_id],
            "created_by_ref": identity_id,
            "created": timestamp,
            "modified": timestamp,
            "name": ability.name,
            "description": f"AgentSim ability {ability.ability_id}: {ability.description}",
            "extensions": _extension(),
            "external_references": [
                {"source_name": "agentsim-ability", "external_id": ability.ability_id}
            ],
        }
        if attack_ids:
            action["technique_id"] = attack_ids[0]
        if dependants[step.step_id]:
            action["effect_refs"] = dependants[step.step_id]
        actions.append(action)
    roots = [
        action_ids[step.step_id]
        for step in campaign.steps
        if not step.depends_on or not any(dep in action_ids for dep in step.depends_on)
    ]
    objects: list[dict[str, object]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": timestamp,
            "modified": timestamp,
            "name": "AgentSim",
            "identity_class": "system",
        },
        {
            "type": "attack-flow",
            "spec_version": "2.1",
            "id": _stix_id("attack-flow", campaign.campaign_id),
            "created_by_ref": identity_id,
            "created": timestamp,
            "modified": timestamp,
            "name": campaign.name,
            "description": campaign.description,
            "scope": "emulation-plan",
            "start_refs": roots,
            "extensions": _extension(),
            "external_references": [
                {"source_name": "agentsim-campaign", "external_id": campaign.campaign_id}
            ],
        },
        *actions,
    ]
    return {"type": "bundle", "id": _stix_id("bundle", campaign.campaign_id), "objects": objects}


@dataclass(frozen=True)
class AttackFlowImport:
    campaign: CampaignDefinition
    warnings: tuple[str, ...]


def _external_id(action: Mapping[str, object]) -> str | None:
    references = action.get("external_references", ())
    if not isinstance(references, Sequence) or isinstance(references, (str, bytes)):
        return None
    for reference in references:
        if isinstance(reference, Mapping) and reference.get("source_name") == "agentsim-ability":
            value = reference.get("external_id")
            return str(value) if value else None
    return None


def import_campaign(
    bundle: Mapping[str, object], abilities: Mapping[str, AbilityDefinition]
) -> AttackFlowImport:
    """Import Attack Flow actions that map to reviewed AgentSim abilities."""

    if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ValueError("Attack Flow input must be a STIX bundle")
    objects = [item for item in bundle["objects"] if isinstance(item, Mapping)]
    flows = [item for item in objects if item.get("type") == "attack-flow"]
    if len(flows) != 1:
        raise ValueError("Attack Flow bundle must contain exactly one attack-flow object")
    flow = flows[0]
    actions = {
        str(item["id"]): item
        for item in objects
        if item.get("type") == "attack-action" and item.get("id")
    }
    action_order = {action_id: index for index, action_id in enumerate(actions)}
    ability_by_technique: dict[str, str] = {}
    for ability in abilities.values():
        for technique in ability.mappings.get("mitre_attack", ()):
            ability_by_technique.setdefault(str(technique), ability.ability_id)
    action_to_ability: dict[str, str] = {}
    warnings: list[str] = []
    for action_id, action in actions.items():
        ability_id = _external_id(action) or ability_by_technique.get(
            str(action.get("technique_id", ""))
        )
        if ability_id in abilities:
            action_to_ability[action_id] = str(ability_id)
        else:
            warnings.append(f"Skipped unmapped Attack Flow action: {action.get('name', action_id)}")
    if not action_to_ability:
        raise ValueError("Attack Flow contains no actions mapped to reviewed AgentSim abilities")
    incoming: dict[str, set[str]] = {action_id: set() for action_id in action_to_ability}
    for source_id, action in actions.items():
        effects = action.get("effect_refs", ())
        if isinstance(effects, list):
            for target_id in effects:
                if source_id in action_to_ability and str(target_id) in incoming:
                    incoming[str(target_id)].add(source_id)
    ordered: list[str] = []
    remaining = set(action_to_ability)
    while remaining:
        ready = sorted(
            (item for item in remaining if not (incoming[item] & remaining)),
            key=lambda item: action_order[item],
        )
        if not ready:
            raise ValueError("Attack Flow action graph contains a cycle")
        selected = ready[0]
        ordered.append(selected)
        remaining.remove(selected)
    step_ids = {
        action_id: f"step-{index:03d}" for index, action_id in enumerate(ordered, 1)
    }
    steps = tuple(
        CampaignStep(
            step_id=step_ids[action_id],
            ability_id=action_to_ability[action_id],
            depends_on=tuple(step_ids[item] for item in sorted(incoming[action_id])),
            on_failure="stop",
        )
        for action_id in ordered
    )
    external = next(
        (
            str(ref.get("external_id"))
            for ref in flow.get("external_references", ())
            if isinstance(ref, Mapping) and ref.get("source_name") == "agentsim-campaign"
        ),
        None,
    )
    name = str(flow.get("name", "Imported Attack Flow"))
    campaign_id = external or re.sub(r"[^a-z0-9]+", "-", name.casefold()).strip("-") or "imported-flow"
    required = tuple(
        sorted(
            {
                str(item.get("source"))
                for step in steps
                for item in abilities[step.ability_id].expected_telemetry
                if item.get("source")
            }
        )
    )
    return AttackFlowImport(
        CampaignDefinition(
            campaign_id=campaign_id,
            name=name,
            description=str(flow.get("description", "Imported Attack Flow emulation plan.")),
            objective="Validate the imported Attack Flow using reviewed AgentSim abilities.",
            target_profile="explicit-authorized-target",
            steps=steps,
            required_telemetry=required,
            stop_conditions=(
                "authorization_denied",
                "resource_limit_reached",
                "cleanup_failed",
                "kill_switch",
            ),
            metadata={"attack_flow_id": flow.get("id"), "imported": True},
        ),
        tuple(warnings),
    )
