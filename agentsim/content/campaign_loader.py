"""Strict directed campaign-pack loading and dependency validation."""

from __future__ import annotations

import json
import re
from importlib import resources
from pathlib import Path
from typing import Mapping, Sequence

from agentsim.models.campaign import CampaignDefinition, CampaignStep

from .integrity import verify_integrity


_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,127}$")
_PACK_FIELDS = {"schema_version", "kind", "pack_id", "integrity", "campaigns"}
_CAMPAIGN_FIELDS = {
    "id",
    "name",
    "description",
    "objective",
    "target_profile",
    "authorization_required",
    "steps",
    "required_telemetry",
    "stop_conditions",
    "metadata",
}
_STEP_FIELDS = {"id", "ability_id", "depends_on", "on_failure"}


def _string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context} must be a non-empty string")
    return value


def _strings(value: object, context: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or (not value and not allow_empty):
        raise ValueError(f"{context} must be an array")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError(f"{context} must contain non-empty strings")
    return tuple(value)


def _reject_unknown_fields(
    value: Mapping[str, object], allowed: set[str], context: str
) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"{context} contains unsupported fields: {', '.join(unknown)}")


def parse_campaign_pack(value: object, source: str) -> dict[str, CampaignDefinition]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{source} must be an object")
    if value.get("schema_version") != "1.0" or value.get("kind") != "campaign-pack":
        raise ValueError(f"{source} must be a campaign-pack with schema_version 1.0")
    _reject_unknown_fields(value, _PACK_FIELDS, source)
    pack_id = _string(value.get("pack_id"), f"{source}.pack_id")
    verify_integrity(value, "campaigns")
    campaigns = value.get("campaigns")
    if not isinstance(campaigns, list) or not campaigns:
        raise ValueError(f"{source}.campaigns must be a non-empty array")
    parsed: dict[str, CampaignDefinition] = {}
    for index, raw in enumerate(campaigns):
        context = f"{source}.campaigns[{index}]"
        if not isinstance(raw, Mapping):
            raise ValueError(f"{context} must be an object")
        _reject_unknown_fields(raw, _CAMPAIGN_FIELDS, context)
        campaign_id = _string(raw.get("id"), f"{context}.id")
        if not _ID_PATTERN.fullmatch(campaign_id):
            raise ValueError(f"{context}.id has an invalid format")
        raw_steps = raw.get("steps")
        if not isinstance(raw_steps, list) or not raw_steps:
            raise ValueError(f"{context}.steps must be a non-empty array")
        steps: list[CampaignStep] = []
        seen: set[str] = set()
        for step_index, step_value in enumerate(raw_steps):
            step_context = f"{context}.steps[{step_index}]"
            if not isinstance(step_value, Mapping):
                raise ValueError(f"{step_context} must be an object")
            _reject_unknown_fields(step_value, _STEP_FIELDS, step_context)
            step_id = _string(step_value.get("id"), f"{step_context}.id")
            if step_id in seen:
                raise ValueError(f"duplicate campaign step ID: {step_id}")
            depends_on = _strings(
                step_value.get("depends_on", []), f"{step_context}.depends_on", allow_empty=True
            )
            unknown_dependencies = [dependency for dependency in depends_on if dependency not in seen]
            if unknown_dependencies:
                raise ValueError(
                    f"{step_context} depends on unknown or later steps: {', '.join(unknown_dependencies)}"
                )
            on_failure = _string(step_value.get("on_failure", "stop"), f"{step_context}.on_failure")
            if on_failure not in {"stop", "continue"}:
                raise ValueError(f"{step_context}.on_failure must be stop or continue")
            steps.append(
                CampaignStep(
                    step_id=step_id,
                    ability_id=_string(step_value.get("ability_id"), f"{step_context}.ability_id"),
                    depends_on=depends_on,
                    on_failure=on_failure,
                )
            )
            seen.add(step_id)
        if campaign_id in parsed:
            raise ValueError(f"duplicate campaign ID in pack: {campaign_id}")
        parsed[campaign_id] = CampaignDefinition(
            campaign_id=campaign_id,
            name=_string(raw.get("name"), f"{context}.name"),
            description=_string(raw.get("description"), f"{context}.description"),
            objective=_string(raw.get("objective"), f"{context}.objective"),
            target_profile=_string(raw.get("target_profile", "synthetic"), f"{context}.target_profile"),
            steps=tuple(steps),
            required_telemetry=_strings(
                raw.get("required_telemetry", []), f"{context}.required_telemetry", allow_empty=True
            ),
            stop_conditions=_strings(
                raw.get("stop_conditions", ["authorization_denied", "cleanup_failed"]),
                f"{context}.stop_conditions",
            ),
            authorization_required=raw.get("authorization_required") is not False,
            pack_id=pack_id,
            metadata=dict(raw.get("metadata", {})) if isinstance(raw.get("metadata", {}), Mapping) else {},
        )
    return parsed


def load_campaign_registry(
    pack_paths: Sequence[str | Path] = (), *, include_builtin: bool = True
) -> dict[str, CampaignDefinition]:
    sources: list[tuple[object, str]] = []
    if include_builtin:
        root = resources.files("agentsim.content.campaigns")
        sources.extend(
            (resource, f"builtin:{resource.name}")
            for resource in sorted(root.iterdir(), key=lambda entry: entry.name)
            if resource.name.endswith(".json")
        )
    for raw in pack_paths:
        path = Path(raw).expanduser()
        if path.is_dir():
            files = sorted(path.glob("*.json"))
            if not files:
                raise ValueError(f"campaign-pack directory contains no JSON files: {path}")
            sources.extend((file, str(file)) for file in files)
        elif path.is_file():
            sources.append((path, str(path)))
        else:
            raise FileNotFoundError(f"campaign pack does not exist: {path}")
    registry: dict[str, CampaignDefinition] = {}
    for resource, source in sources:
        try:
            if isinstance(resource, Path):
                value = json.loads(resource.read_text(encoding="utf-8"))
            else:
                with resource.open("r", encoding="utf-8") as input_file:  # type: ignore[attr-defined]
                    value = json.load(input_file)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid campaign-pack JSON in {source}: {exc}") from exc
        for campaign_id, definition in parse_campaign_pack(value, source).items():
            if campaign_id in registry:
                raise ValueError(f"duplicate campaign ID across packs: {campaign_id}")
            registry[campaign_id] = definition
    if not registry:
        raise ValueError("at least one campaign pack is required")
    return dict(sorted(registry.items()))
