"""Strict ability-pack loading with executable-content separation."""

from __future__ import annotations

import json
import re
from importlib import resources
from pathlib import Path
from typing import Mapping, Sequence

from agentsim.models.ability import AbilityDefinition, ExecutionSpec

from .integrity import verify_integrity
from .provenance import parse_provenance


_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,127}$")
_RISKS = {"low", "medium", "high"}
_PROVIDERS = {"simulate", "local", "docker"}
_PACK_FIELDS = {"schema_version", "kind", "pack_id", "integrity", "provenance", "abilities"}
_ABILITY_FIELDS = {
    "id",
    "name",
    "description",
    "risk",
    "platforms",
    "mappings",
    "execution",
    "target_constraints",
    "expected_telemetry",
    "validation",
    "defenses",
    "metadata",
}
_EXECUTION_FIELDS = {
    "supported_providers",
    "default_provider",
    "requires_elevation",
    "network_access",
    "timeout_seconds",
    "command_ref",
    "cleanup_ref",
    "state_changes",
}
_TARGET_FIELDS = {"allowed_target_types", "production_allowed"}
_VALIDATION_FIELDS = {"detection_objectives", "benign_controls"}


def _string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context} must be a non-empty string")
    return value


def _strings(value: object, context: str) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)) or not value:
        raise ValueError(f"{context} must be a non-empty array")
    items = tuple(_string(item, context) for item in value)
    return items


def _mapping(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{context} must be an object")
    return value


def _reject_unknown_fields(
    value: Mapping[str, object], allowed: set[str], context: str
) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"{context} contains unsupported fields: {', '.join(unknown)}")


def parse_ability_pack(
    value: object,
    source: str,
    *,
    trusted_keys: Mapping[str, object] | None = None,
) -> dict[str, AbilityDefinition]:
    pack = _mapping(value, source)
    if pack.get("schema_version") != "1.0" or pack.get("kind") != "ability-pack":
        raise ValueError(f"{source} must be an ability-pack with schema_version 1.0")
    _reject_unknown_fields(pack, _PACK_FIELDS, source)
    pack_id = _string(pack.get("pack_id"), f"{source}.pack_id")
    verify_integrity(pack, "abilities", trusted_keys=trusted_keys)
    if pack.get("provenance") is not None:
        parse_provenance(pack.get("provenance"))
    raw_abilities = pack.get("abilities")
    if not isinstance(raw_abilities, list) or not raw_abilities:
        raise ValueError(f"{source}.abilities must be a non-empty array")
    parsed: dict[str, AbilityDefinition] = {}
    for index, raw in enumerate(raw_abilities):
        context = f"{source}.abilities[{index}]"
        item = _mapping(raw, context)
        _reject_unknown_fields(item, _ABILITY_FIELDS, context)
        ability_id = _string(item.get("id"), f"{context}.id")
        if not _ID_PATTERN.fullmatch(ability_id):
            raise ValueError(f"{context}.id has an invalid format")
        if ability_id in parsed:
            raise ValueError(f"duplicate ability ID in pack: {ability_id}")
        risk = _string(item.get("risk"), f"{context}.risk")
        if risk not in _RISKS:
            raise ValueError(f"{context}.risk must be low, medium, or high")
        execution = _mapping(item.get("execution"), f"{context}.execution")
        _reject_unknown_fields(execution, _EXECUTION_FIELDS, f"{context}.execution")
        providers = _strings(
            execution.get("supported_providers"), f"{context}.execution.supported_providers"
        )
        if any(provider not in _PROVIDERS for provider in providers):
            raise ValueError(f"{context} contains an unsupported provider")
        default_provider = _string(
            execution.get("default_provider"), f"{context}.execution.default_provider"
        )
        if default_provider not in providers:
            raise ValueError(f"{context}.execution.default_provider must be supported")
        command_ref = _string(execution.get("command_ref"), f"{context}.execution.command_ref")
        if not command_ref.startswith("catalog://"):
            raise ValueError(f"{context}.execution.command_ref must use catalog://")
        cleanup_ref = execution.get("cleanup_ref")
        if cleanup_ref is not None and (
            not isinstance(cleanup_ref, str) or not cleanup_ref.startswith("catalog://")
        ):
            raise ValueError(f"{context}.execution.cleanup_ref must use catalog://")
        state_changes = execution.get("state_changes") is True
        if state_changes and not cleanup_ref:
            raise ValueError(f"{context} changes state but has no cleanup_ref")
        network_access = _string(
            execution.get("network_access", "denied"), f"{context}.execution.network_access"
        )
        if network_access not in {"denied", "required"}:
            raise ValueError(f"{context}.execution.network_access must be denied or required")
        timeout = execution.get("timeout_seconds", 30)
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 600:
            raise ValueError(f"{context}.execution.timeout_seconds must be between 1 and 600")
        target_constraints = _mapping(
            item.get("target_constraints"), f"{context}.target_constraints"
        )
        _reject_unknown_fields(
            target_constraints, _TARGET_FIELDS, f"{context}.target_constraints"
        )
        expected = item.get("expected_telemetry")
        if not isinstance(expected, list) or not expected:
            raise ValueError(f"{context}.expected_telemetry must be a non-empty array")
        expected_telemetry = tuple(
            dict(_mapping(entry, f"{context}.expected_telemetry")) for entry in expected
        )
        validation = _mapping(item.get("validation"), f"{context}.validation")
        _reject_unknown_fields(validation, _VALIDATION_FIELDS, f"{context}.validation")
        mappings = _mapping(item.get("mappings", {}), f"{context}.mappings")
        parsed[ability_id] = AbilityDefinition(
            ability_id=ability_id,
            name=_string(item.get("name"), f"{context}.name"),
            description=_string(item.get("description"), f"{context}.description"),
            risk=risk,
            platforms=_strings(item.get("platforms"), f"{context}.platforms"),
            mappings={str(key): _strings(mapping, f"{context}.mappings.{key}") for key, mapping in mappings.items()},
            execution=ExecutionSpec(
                supported_providers=providers,
                default_provider=default_provider,
                requires_elevation=execution.get("requires_elevation") is True,
                network_access=network_access,
                timeout_seconds=timeout,
                command_ref=command_ref,
                cleanup_ref=str(cleanup_ref) if cleanup_ref is not None else None,
                state_changes=state_changes,
            ),
            allowed_target_types=_strings(
                target_constraints.get("allowed_target_types"),
                f"{context}.target_constraints.allowed_target_types",
            ),
            production_allowed=target_constraints.get("production_allowed") is True,
            expected_telemetry=expected_telemetry,
            detection_objectives=_strings(
                validation.get("detection_objectives"),
                f"{context}.validation.detection_objectives",
            ),
            benign_controls=_strings(
                validation.get("benign_controls"), f"{context}.validation.benign_controls"
            ),
            defenses=_strings(item.get("defenses"), f"{context}.defenses"),
            pack_id=pack_id,
            metadata=dict(_mapping(item.get("metadata", {}), f"{context}.metadata")),
        )
    return parsed


def _load_path(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid ability-pack JSON in {path}: {exc}") from exc


def load_ability_registry(
    pack_paths: Sequence[str | Path] = (),
    *,
    include_builtin: bool = True,
    trusted_keys: Mapping[str, object] | None = None,
) -> dict[str, AbilityDefinition]:
    sources: list[tuple[object, str]] = []
    if include_builtin:
        root = resources.files("agentsim.content.packs")
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
                raise ValueError(f"ability-pack directory contains no JSON files: {path}")
            sources.extend((file, str(file)) for file in files)
        elif path.is_file():
            sources.append((path, str(path)))
        else:
            raise FileNotFoundError(f"ability pack does not exist: {path}")
    registry: dict[str, AbilityDefinition] = {}
    for resource, source in sources:
        if isinstance(resource, Path):
            value = _load_path(resource)
        else:
            try:
                with resource.open("r", encoding="utf-8") as input_file:  # type: ignore[attr-defined]
                    value = json.load(input_file)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid ability-pack JSON in {source}: {exc}") from exc
        for ability_id, definition in parse_ability_pack(
            value, source, trusted_keys=trusted_keys
        ).items():
            if ability_id in registry:
                raise ValueError(f"duplicate ability ID across packs: {ability_id}")
            registry[ability_id] = definition
    if not registry:
        raise ValueError("at least one ability pack is required")
    return dict(sorted(registry.items()))
