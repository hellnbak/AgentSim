"""Declarative, simulation-only agentic attack scenarios and benchmarking.

Scenario mode records synthetic proposed actions and policy decisions. It never
invokes an agent tool, reads a real credential, starts a process, or opens a
network connection. Built-in and third-party packs are validated against that
safety contract before use.
"""

from __future__ import annotations

import json
import random
import re
import statistics
import time
import uuid
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence


SCHEMA_VERSION = "2.0"
SUPPORTED_SCHEMA_VERSIONS = {"1.0", SCHEMA_VERSION}
PACK_SCHEMA_VERSION = "1.0"
VALIDATION_SCHEMA_VERSION = "2.0"
COVERAGE_SCHEMA_VERSION = "1.0"
DEFAULT_GROUND_TRUTH_PATH = "agent_sim_events.jsonl"
DEFAULT_VALIDATION_PATH = "agent_sim_validation.json"
DEFAULT_JUNIT_PATH = "agent_sim_junit.xml"
DEFAULT_SARIF_PATH = "agent_sim_results.sarif"
DEFAULT_OTEL_PATH = "agent_sim_otel.jsonl"
DEFAULT_COVERAGE_PATH = "agent_sim_coverage.json"
DEFAULT_BUNDLE_PATH = "agent_sim_evidence.zip"
VALID_VARIANTS = ("malicious", "benign", "both")
LAB_ARTIFACT_REFERENCE_PATTERN = re.compile(
    r"^lab-artifact://[a-z0-9][a-z0-9._-]{2,127}$"
)

LogCallback = Callable[[str], None]
StopCallback = Callable[[], bool]
Clock = Callable[[], datetime]
Event = Mapping[str, object]

ACTION_EVENT_TYPES = {
    "agent.approval.granted",
    "agent.configuration.requested",
    "agent.delegation.accepted",
    "agent.delegation.requested",
    "agent.memory.written",
    "agent.network.requested",
    "agent.tool.requested",
}
FORBIDDEN_DETECTOR_FIELDS = {
    "expected_detection",
    "mappings",
    "message",
    "scenario_id",
    "scenario_name",
    "scenario_variant",
}
SAFE_URI_PREFIXES = (
    "synthetic://",
    "http://127.0.0.1:",
    "http://localhost:",
)


@dataclass(frozen=True)
class ScenarioStep:
    """One observable checkpoint in a synthetic agent workflow."""

    event_type: str
    stage: str
    message: str
    input_trust: str = "not_applicable"
    tool_name: str | None = None
    tool_action: str | None = None
    tool_risk: str = "none"
    policy_decision: str = "not_applicable"
    outcome: str = "observed"
    session_id: str = "session-1"
    conversation_id: str = "conversation-1"
    agent_id: str = "primary-agent"
    agent_instance_id: str = "primary-agent-1"
    principal_id: str = "synthetic-user"
    delegation_id: str | None = None
    data_lineage_id: str | None = None
    taint_labels: tuple[str, ...] = ()
    policy_id: str = "agentsim-default"
    policy_version: str = "1.0"
    approval_id: str | None = None
    caused_by_sequences: tuple[int, ...] = ()
    attributes: Mapping[str, object] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "ScenarioStep":
        fields = {
            key: value[key]
            for key in (
                "event_type",
                "stage",
                "message",
                "input_trust",
                "tool_name",
                "tool_action",
                "tool_risk",
                "policy_decision",
                "outcome",
                "session_id",
                "conversation_id",
                "agent_id",
                "agent_instance_id",
                "principal_id",
                "delegation_id",
                "data_lineage_id",
                "policy_id",
                "policy_version",
                "approval_id",
            )
            if key in value
        }
        fields["taint_labels"] = tuple(value.get("taint_labels", ()))
        fields["caused_by_sequences"] = tuple(value.get("caused_by_sequences", ()))
        attributes = value.get("attributes", {})
        fields["attributes"] = dict(attributes) if isinstance(attributes, Mapping) else {}
        return cls(**fields)  # type: ignore[arg-type]


@dataclass(frozen=True)
class ScenarioDefinition:
    """A malicious workflow, benign twin, and observable detector definition."""

    scenario_id: str
    name: str
    description: str
    risk: str
    mappings: Mapping[str, Sequence[str]]
    detector: Mapping[str, object]
    malicious_steps: Sequence[ScenarioStep]
    benign_steps: Sequence[ScenarioStep]
    pack_id: str = "agentsim.custom"
    lab_artifact_ref: str | None = None

    def steps_for(self, variant: str) -> Sequence[ScenarioStep]:
        if variant == "malicious":
            return self.malicious_steps
        if variant == "benign":
            return self.benign_steps
        raise ValueError("variant must be malicious or benign")


@dataclass(frozen=True)
class ScenarioSuiteResult:
    """Artifacts and benchmark outcome from one scenario suite."""

    run_id: str
    ground_truth_path: Path
    validation_path: Path
    event_count: int
    trace_count: int
    check_count: int
    mutation_count: int
    passed: bool
    stopped: bool
    junit_path: Path | None = None
    sarif_path: Path | None = None
    otel_path: Path | None = None
    coverage_path: Path | None = None
    bundle_path: Path | None = None
    metrics: Mapping[str, object] = field(default_factory=dict)


def _require_mapping(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{context} must be an object")
    return value


def _require_nonempty_string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context} must be a non-empty string")
    return value


def _validate_condition(condition: Mapping[str, object], context: str) -> None:
    supported_keys = {
        "event_type",
        "equals",
        "not_equals",
        "contains",
        "gte",
        "exists",
    }
    unknown_keys = sorted(str(key) for key in condition if key not in supported_keys)
    if unknown_keys:
        raise ValueError(
            f"{context} uses unsupported detector keys: {', '.join(unknown_keys)}"
        )
    event_type = condition.get("event_type")
    if event_type is not None:
        _require_nonempty_string(event_type, f"{context}.event_type")
    for operator in ("equals", "not_equals", "contains", "gte", "exists"):
        values = condition.get(operator, {})
        if not isinstance(values, Mapping):
            raise ValueError(f"{context}.{operator} must be an object")
        for path in values:
            root = str(path).split(".", 1)[0]
            if root in FORBIDDEN_DETECTOR_FIELDS:
                raise ValueError(
                    f"{context} may not inspect ground-truth field: {path}"
                )


def _validate_step(step: Mapping[str, object], context: str) -> None:
    event_type = _require_nonempty_string(step.get("event_type"), f"{context}.event_type")
    if not event_type.startswith("agent."):
        raise ValueError(f"{context}.event_type must start with agent.")
    _require_nonempty_string(step.get("stage"), f"{context}.stage")
    _require_nonempty_string(step.get("message"), f"{context}.message")
    attributes = _require_mapping(step.get("attributes", {}), f"{context}.attributes")
    if event_type in ACTION_EVENT_TYPES and attributes.get("executed") is not False:
        raise ValueError(f"{context} action checkpoints must set attributes.executed=false")
    for key in ("destination", "resource", "source", "configuration_target"):
        uri = attributes.get(key)
        if isinstance(uri, str) and not uri.startswith(SAFE_URI_PREFIXES):
            raise ValueError(f"{context}.{key} must use a synthetic or loopback URI")
    if attributes.get("payload_recorded") is True:
        raise ValueError(f"{context} may not record a network payload")
    if attributes.get("token_recorded") is True:
        raise ValueError(f"{context} may not record a token")


def _event_like_step(step: ScenarioStep) -> dict[str, object]:
    return {
        "event_type": step.event_type,
        "stage": step.stage,
        "input_trust": step.input_trust,
        "tool_name": step.tool_name,
        "tool_action": step.tool_action,
        "tool_risk": step.tool_risk,
        "policy_decision": step.policy_decision,
        "outcome": step.outcome,
        "session_id": f"validation:{step.session_id}",
        "conversation_id": f"validation:{step.conversation_id}",
        "agent_id": step.agent_id,
        "agent_instance_id": f"validation:{step.agent_instance_id}",
        "principal_id": step.principal_id,
        "delegation_id": step.delegation_id,
        "data_lineage_id": step.data_lineage_id,
        "taint_labels": list(step.taint_labels),
        "policy_id": step.policy_id,
        "policy_version": step.policy_version,
        "approval_id": step.approval_id,
        "attributes": dict(step.attributes),
        "event_id": f"validation:{step.event_type}",
    }


def _get_path(value: Mapping[str, object], path: str) -> object:
    current: object = value
    for component in path.split("."):
        if not isinstance(current, Mapping) or component not in current:
            return None
        current = current[component]
    return current


def _condition_matches(event: Event, condition: Mapping[str, object]) -> bool:
    expected_type = condition.get("event_type")
    if expected_type is not None and event.get("event_type") != expected_type:
        return False
    for path, expected in _require_mapping(condition.get("equals", {}), "equals").items():
        if _get_path(event, str(path)) != expected:
            return False
    for path, expected in _require_mapping(
        condition.get("not_equals", {}), "not_equals"
    ).items():
        if _get_path(event, str(path)) == expected:
            return False
    for path, expected in _require_mapping(
        condition.get("contains", {}), "contains"
    ).items():
        observed = _get_path(event, str(path))
        if not isinstance(observed, (str, list, tuple, set)) or expected not in observed:
            return False
    for path, expected in _require_mapping(condition.get("gte", {}), "gte").items():
        observed = _get_path(event, str(path))
        if (
            isinstance(observed, bool)
            or not isinstance(observed, (int, float))
            or isinstance(expected, bool)
            or not isinstance(expected, (int, float))
            or observed < expected
        ):
            return False
    for path, expected in _require_mapping(
        condition.get("exists", {}), "exists"
    ).items():
        observed = _get_path(event, str(path))
        if bool(observed is not None) != bool(expected):
            return False
    return True


def detect_ordered_sequence(
    events: Sequence[Event], detector: Mapping[str, object]
) -> tuple[bool, list[str]]:
    """Evaluate an ordered semantic sequence without reading ground-truth labels."""

    conditions = detector.get("conditions", ())
    if not isinstance(conditions, Sequence) or isinstance(conditions, (str, bytes)):
        return False, []
    condition_index = 0
    signals: list[str] = []
    for event in events:
        if condition_index >= len(conditions):
            break
        condition = conditions[condition_index]
        if isinstance(condition, Mapping) and _condition_matches(event, condition):
            signals.append(str(event.get("event_id", "")))
            condition_index += 1
    return bool(conditions) and condition_index == len(conditions), signals


def _parse_pack(data: object, source: str) -> dict[str, ScenarioDefinition]:
    pack = _require_mapping(data, source)
    if pack.get("pack_schema_version") != PACK_SCHEMA_VERSION:
        raise ValueError(f"{source} uses an unsupported pack schema version")
    pack_id = _require_nonempty_string(pack.get("pack_id"), f"{source}.pack_id")
    raw_scenarios = pack.get("scenarios")
    if not isinstance(raw_scenarios, list) or not raw_scenarios:
        raise ValueError(f"{source}.scenarios must be a non-empty array")

    definitions: dict[str, ScenarioDefinition] = {}
    for scenario_index, raw_definition in enumerate(raw_scenarios):
        context = f"{source}.scenarios[{scenario_index}]"
        definition_data = _require_mapping(raw_definition, context)
        scenario_id = _require_nonempty_string(
            definition_data.get("scenario_id"), f"{context}.scenario_id"
        )
        if scenario_id in definitions:
            raise ValueError(f"duplicate scenario in {source}: {scenario_id}")
        risk = _require_nonempty_string(definition_data.get("risk"), f"{context}.risk")
        if risk not in {"low", "medium", "high", "critical"}:
            raise ValueError(f"{context}.risk is invalid")
        mappings_data = _require_mapping(
            definition_data.get("mappings"), f"{context}.mappings"
        )
        mappings: dict[str, tuple[str, ...]] = {}
        for framework, values in mappings_data.items():
            if not isinstance(values, list) or not all(
                isinstance(value, str) and value for value in values
            ):
                raise ValueError(f"{context}.mappings.{framework} must be strings")
            mappings[str(framework)] = tuple(values)
        detector = _require_mapping(
            definition_data.get("detector"), f"{context}.detector"
        )
        if detector.get("type") != "ordered_sequence":
            raise ValueError(f"{context}.detector.type must be ordered_sequence")
        raw_conditions = detector.get("conditions")
        if not isinstance(raw_conditions, list) or not raw_conditions:
            raise ValueError(f"{context}.detector.conditions must be non-empty")
        for condition_index, raw_condition in enumerate(raw_conditions):
            condition = _require_mapping(
                raw_condition, f"{context}.detector.conditions[{condition_index}]"
            )
            _validate_condition(
                condition, f"{context}.detector.conditions[{condition_index}]"
            )

        variants: dict[str, tuple[ScenarioStep, ...]] = {}
        for variant in ("malicious", "benign"):
            raw_steps = definition_data.get(f"{variant}_steps")
            if not isinstance(raw_steps, list) or not raw_steps:
                raise ValueError(f"{context}.{variant}_steps must be non-empty")
            steps: list[ScenarioStep] = []
            for step_index, raw_step in enumerate(raw_steps):
                step_data = _require_mapping(
                    raw_step, f"{context}.{variant}_steps[{step_index}]"
                )
                _validate_step(step_data, f"{context}.{variant}_steps[{step_index}]")
                steps.append(ScenarioStep.from_mapping(step_data))
            variants[variant] = tuple(steps)

        definition = ScenarioDefinition(
            scenario_id=scenario_id,
            name=_require_nonempty_string(
                definition_data.get("name"), f"{context}.name"
            ),
            description=_require_nonempty_string(
                definition_data.get("description"), f"{context}.description"
            ),
            risk=risk,
            mappings=mappings,
            detector=dict(detector),
            malicious_steps=variants["malicious"],
            benign_steps=variants["benign"],
            pack_id=pack_id,
            lab_artifact_ref=(
                _require_nonempty_string(
                    definition_data.get("lab_artifact_ref"),
                    f"{context}.lab_artifact_ref",
                )
                if definition_data.get("lab_artifact_ref") is not None
                else None
            ),
        )
        if (
            definition.lab_artifact_ref is not None
            and not LAB_ARTIFACT_REFERENCE_PATTERN.fullmatch(
                definition.lab_artifact_ref
            )
        ):
            raise ValueError(f"{context}.lab_artifact_ref has an invalid format")
        malicious_detected, _ = detect_ordered_sequence(
            [_event_like_step(step) for step in definition.malicious_steps],
            definition.detector,
        )
        benign_detected, _ = detect_ordered_sequence(
            [_event_like_step(step) for step in definition.benign_steps],
            definition.detector,
        )
        if not malicious_detected or benign_detected:
            raise ValueError(
                f"{context}.detector must detect malicious steps and reject benign steps"
            )
        definitions[scenario_id] = definition
    return definitions


def _load_json_resource(resource: object, source: str) -> object:
    try:
        with resource.open("r", encoding="utf-8") as input_file:  # type: ignore[attr-defined]
            return json.load(input_file)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in scenario pack {source}: {exc}") from exc


def load_scenario_registry(
    pack_paths: Sequence[str | Path] = (), *, include_builtin: bool = True
) -> dict[str, ScenarioDefinition]:
    """Load built-in and custom JSON scenario packs with collision checks."""

    sources: list[tuple[object, str]] = []
    if include_builtin:
        package_root = resources.files("agentsim_scenarios.packs")
        for resource in sorted(package_root.iterdir(), key=lambda item: item.name):
            if resource.name.endswith(".json"):
                sources.append((resource, f"builtin:{resource.name}"))
    for raw_path in pack_paths:
        candidate = Path(raw_path).expanduser()
        if candidate.is_dir():
            paths = sorted(candidate.glob("*.json"))
            if not paths:
                raise ValueError(f"scenario pack directory contains no JSON files: {candidate}")
            sources.extend((path, str(path)) for path in paths)
        elif candidate.is_file():
            sources.append((candidate, str(candidate)))
        else:
            raise FileNotFoundError(f"scenario pack does not exist: {candidate}")

    registry: dict[str, ScenarioDefinition] = {}
    for resource, source in sources:
        if isinstance(resource, Path):
            try:
                data = json.loads(resource.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON in scenario pack {source}: {exc}") from exc
        else:
            data = _load_json_resource(resource, source)
        for scenario_id, definition in _parse_pack(data, source).items():
            if scenario_id in registry:
                raise ValueError(f"duplicate scenario ID across packs: {scenario_id}")
            registry[scenario_id] = definition
    if not registry:
        raise ValueError("at least one scenario pack is required")
    return dict(sorted(registry.items()))


SCENARIOS = load_scenario_registry()


def _definition_detector(
    definition: ScenarioDefinition,
) -> Callable[[Sequence[Event]], tuple[bool, list[str]]]:
    return lambda events: detect_ordered_sequence(events, definition.detector)


DETECTORS = {
    scenario_id: _definition_detector(definition)
    for scenario_id, definition in SCENARIOS.items()
}


def list_scenarios(
    registry: Mapping[str, ScenarioDefinition] | None = None,
) -> tuple[ScenarioDefinition, ...]:
    """Return scenarios in stable display order."""

    selected = registry or SCENARIOS
    return tuple(selected[scenario_id] for scenario_id in sorted(selected))


def resolve_scenario_ids(
    value: str | Sequence[str],
    registry: Mapping[str, ScenarioDefinition] | None = None,
) -> tuple[str, ...]:
    """Validate a scenario selection and expand the special `all` value."""

    selected = registry or SCENARIOS
    values = (value,) if isinstance(value, str) else tuple(value)
    if values == ("all",):
        return tuple(sorted(selected))
    unknown = [scenario_id for scenario_id in values if scenario_id not in selected]
    if unknown:
        raise ValueError(f"unknown scenario: {', '.join(unknown)}")
    if not values:
        raise ValueError("at least one scenario is required")
    return values


def _timestamp(clock: Clock) -> str:
    value = clock()
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _variants(value: str) -> tuple[str, ...]:
    if value not in VALID_VARIANTS:
        raise ValueError(f"variant must be one of: {', '.join(VALID_VARIANTS)}")
    return ("malicious", "benign") if value == "both" else (value,)


def _pause(speed_ms: int, stop_callback: StopCallback) -> None:
    remaining = speed_ms / 1000.0
    while remaining > 0 and not stop_callback():
        interval = min(remaining, 0.1)
        time.sleep(interval)
        remaining -= interval


def _mutate_steps(
    steps: Sequence[ScenarioStep], mutation_index: int, rng: random.Random
) -> tuple[ScenarioStep, ...]:
    """Add semantic-preserving variation and benign noise to a trace."""

    mutated: list[ScenarioStep] = []
    alias_prefix = f"synthetic.variant{mutation_index}"
    for step in steps:
        attributes = dict(step.attributes)
        attributes["mutation_index"] = mutation_index
        attributes["telemetry_delay_ms"] = rng.randint(0, 750)
        tool_name = step.tool_name
        if tool_name:
            tool_name = f"{alias_prefix}.{tool_name.rsplit('.', 1)[-1]}"
        mutated.append(
            replace(
                step,
                message=f"Variant {mutation_index}: {step.message}",
                tool_name=tool_name,
                attributes=attributes,
            )
        )
    noise = ScenarioStep(
        event_type="agent.observation.noise",
        stage="observation",
        message="Synthetic benign background checkpoint inserted by the mutation engine.",
        input_trust="trusted",
        agent_id="background-agent",
        agent_instance_id="background-agent-1",
        attributes={
            "noise": True,
            "mutation_index": mutation_index,
            "content_recorded": False,
        },
    )
    insertion_index = rng.randint(0, len(mutated))
    mutated.insert(insertion_index, noise)
    return tuple(mutated)


def estimate_event_count(
    scenario_ids: str | Sequence[str],
    *,
    variant: str = "both",
    mutation_count: int = 0,
    registry: Mapping[str, ScenarioDefinition] | None = None,
) -> int:
    selected = registry or SCENARIOS
    if (
        isinstance(mutation_count, bool)
        or not isinstance(mutation_count, int)
        or not 0 <= mutation_count <= 100
    ):
        raise ValueError("mutation_count must be an integer between 0 and 100")
    variants = _variants(variant)
    base = 0
    traces = 0
    for scenario_id in resolve_scenario_ids(scenario_ids, selected):
        definition = selected[scenario_id]
        for selected_variant in variants:
            base += len(definition.steps_for(selected_variant))
            traces += 1
    return base * (mutation_count + 1) + traces * mutation_count


def _build_event(
    *,
    definition: ScenarioDefinition,
    variant: str,
    step: ScenarioStep,
    run_id: str,
    trace_id: str,
    sequence: int,
    parent_event_id: str | None,
    event_ids_by_sequence: Mapping[int, str],
    mutation_id: str | None,
    clock: Clock,
) -> dict[str, object]:
    event_id = f"{trace_id}:{sequence:03d}"
    explicit_causes = [
        event_ids_by_sequence[reference]
        for reference in step.caused_by_sequences
        if reference in event_ids_by_sequence
    ]
    causes = explicit_causes or ([parent_event_id] if parent_event_id else [])
    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp": _timestamp(clock),
        "event_id": event_id,
        "parent_event_id": parent_event_id,
        "caused_by_event_ids": causes,
        "run_id": run_id,
        "trace_id": trace_id,
        "session_id": f"{trace_id}:{step.session_id}",
        "conversation_id": f"{trace_id}:{step.conversation_id}",
        "agent_id": step.agent_id,
        "agent_instance_id": f"{trace_id}:{step.agent_instance_id}",
        "principal_id": step.principal_id,
        "delegation_id": step.delegation_id,
        "data_lineage_id": step.data_lineage_id,
        "taint_labels": list(step.taint_labels),
        "policy_id": step.policy_id,
        "policy_version": step.policy_version,
        "approval_id": step.approval_id,
        "mutation_id": mutation_id,
        "sequence": sequence,
        "producer": "AgentSim",
        "execution_mode": "simulation_only",
        "scenario_pack_id": definition.pack_id,
        "scenario_id": definition.scenario_id,
        "scenario_name": definition.name,
        "scenario_variant": variant,
        "scenario_risk": definition.risk,
        **(
            {"lab_artifact_ref": definition.lab_artifact_ref}
            if definition.lab_artifact_ref
            else {}
        ),
        "expected_detection": variant == "malicious",
        "stage": step.stage,
        "event_type": step.event_type,
        "message": step.message,
        "input_trust": step.input_trust,
        "tool_name": step.tool_name,
        "tool_action": step.tool_action,
        "tool_risk": step.tool_risk,
        "policy_decision": step.policy_decision,
        "outcome": step.outcome,
        "attributes": dict(step.attributes),
        "mappings": {
            framework: list(values)
            for framework, values in definition.mappings.items()
        },
    }


def _events_by_trace(events: Iterable[Event]) -> dict[str, list[Event]]:
    traces: dict[str, list[Event]] = {}
    for event in events:
        trace_id = str(event.get("trace_id", ""))
        traces.setdefault(trace_id, []).append(event)
    for trace in traces.values():
        trace.sort(key=lambda event: int(event.get("sequence", 0)))
    return traces


def _detector_field_paths(detector: Mapping[str, object]) -> list[str]:
    paths = {"event_type"}
    conditions = detector.get("conditions", ())
    if isinstance(conditions, Sequence) and not isinstance(conditions, (str, bytes)):
        for condition in conditions:
            if not isinstance(condition, Mapping):
                continue
            for operator in ("equals", "not_equals", "contains", "gte", "exists"):
                values = condition.get(operator, {})
                if isinstance(values, Mapping):
                    paths.update(str(path) for path in values)
    return sorted(paths)


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def validate_events(
    events: Sequence[Event],
    *,
    clock: Clock | None = None,
    registry: Mapping[str, ScenarioDefinition] | None = None,
) -> dict[str, object]:
    """Score malicious traces and benign twins without detector label leakage."""

    clock = clock or (lambda: datetime.now(timezone.utc))
    selected = registry or SCENARIOS
    results: list[dict[str, object]] = []
    detection_sequences: list[int] = []
    field_coverage: dict[str, dict[str, object]] = {}
    framework_coverage: dict[str, set[str]] = {}

    for trace in _events_by_trace(events).values():
        if not trace:
            continue
        scenario_id = str(trace[0].get("scenario_id", ""))
        definition = selected.get(scenario_id)
        if definition is None:
            detected, signals = False, []
            required_fields: list[str] = []
        else:
            detected, signals = detect_ordered_sequence(trace, definition.detector)
            required_fields = _detector_field_paths(definition.detector)
            observed = [
                path
                for path in required_fields
                if any(_get_path(event, path) is not None for event in trace)
            ]
            field_coverage[scenario_id] = {
                "required_fields": required_fields,
                "observed_fields": observed,
                "coverage": _ratio(len(observed), len(required_fields)),
            }
            for framework, mappings in definition.mappings.items():
                framework_coverage.setdefault(framework, set()).update(mappings)

        expected = bool(trace[0].get("expected_detection"))
        sequence_by_id = {
            str(event.get("event_id")): int(event.get("sequence", 0))
            for event in trace
        }
        detected_at = max((sequence_by_id.get(signal, 0) for signal in signals), default=0)
        if detected and detected_at:
            detection_sequences.append(detected_at)
        results.append(
            {
                "scenario_id": scenario_id,
                "scenario_name": trace[0].get("scenario_name"),
                "variant": trace[0].get("scenario_variant"),
                "mutation_id": trace[0].get("mutation_id"),
                "trace_id": trace[0].get("trace_id"),
                "expected_detected": expected,
                "detected": detected,
                "passed": detected == expected,
                "signal_event_ids": signals,
                "detected_at_sequence": detected_at or None,
                "trace_event_count": len(trace),
            }
        )

    true_positive = sum(
        1 for result in results if result["expected_detected"] and result["detected"]
    )
    false_negative = sum(
        1 for result in results if result["expected_detected"] and not result["detected"]
    )
    false_positive = sum(
        1 for result in results if not result["expected_detected"] and result["detected"]
    )
    true_negative = sum(
        1 for result in results if not result["expected_detected"] and not result["detected"]
    )
    passed_count = sum(1 for result in results if result["passed"])
    by_scenario: dict[str, dict[str, int]] = {}
    for result in results:
        bucket = by_scenario.setdefault(
            str(result["scenario_id"]), {"checks": 0, "passed": 0, "failed": 0}
        )
        bucket["checks"] += 1
        bucket["passed" if result["passed"] else "failed"] += 1
    mutated_results = [result for result in results if result["mutation_id"]]
    metrics = {
        "true_positive": true_positive,
        "false_positive": false_positive,
        "true_negative": true_negative,
        "false_negative": false_negative,
        "precision": _ratio(true_positive, true_positive + false_positive),
        "recall": _ratio(true_positive, true_positive + false_negative),
        "benign_rejection_rate": _ratio(true_negative, true_negative + false_positive),
        "accuracy": _ratio(true_positive + true_negative, len(results)),
        "mean_checkpoints_to_detection": round(
            statistics.mean(detection_sequences), 2
        )
        if detection_sequences
        else None,
        "max_checkpoints_to_detection": max(detection_sequences, default=None),
    }
    return {
        "schema_version": VALIDATION_SCHEMA_VERSION,
        "generated_at": _timestamp(clock),
        "summary": {
            "checks": len(results),
            "passed": passed_count,
            "failed": len(results) - passed_count,
            "all_passed": bool(results) and passed_count == len(results),
        },
        "metrics": metrics,
        "mutation_summary": {
            "checks": len(mutated_results),
            "passed": sum(1 for result in mutated_results if result["passed"]),
            "failed": sum(1 for result in mutated_results if not result["passed"]),
        },
        "by_scenario": by_scenario,
        "field_coverage": field_coverage,
        "framework_coverage": {
            framework: sorted(values)
            for framework, values in sorted(framework_coverage.items())
        },
        "results": results,
    }


def build_coverage_report(
    registry: Mapping[str, ScenarioDefinition] | None = None,
) -> dict[str, object]:
    selected = registry or SCENARIOS
    frameworks: dict[str, dict[str, list[str]]] = {}
    risk_counts: dict[str, int] = {}
    event_types: set[str] = set()
    agents: set[str] = set()
    for definition in selected.values():
        risk_counts[definition.risk] = risk_counts.get(definition.risk, 0) + 1
        for framework, mappings in definition.mappings.items():
            framework_bucket = frameworks.setdefault(framework, {})
            for mapping in mappings:
                framework_bucket.setdefault(mapping, []).append(definition.scenario_id)
        for step in (*definition.malicious_steps, *definition.benign_steps):
            event_types.add(step.event_type)
            agents.add(step.agent_id)
    return {
        "schema_version": COVERAGE_SCHEMA_VERSION,
        "scenario_count": len(selected),
        "risk_counts": dict(sorted(risk_counts.items())),
        "event_types": sorted(event_types),
        "agent_roles": sorted(agents),
        "frameworks": {
            framework: {
                mapping: sorted(scenario_ids)
                for mapping, scenario_ids in sorted(mappings.items())
            }
            for framework, mappings in sorted(frameworks.items())
        },
        "scenarios": [
            {
                "scenario_id": definition.scenario_id,
                "name": definition.name,
                "risk": definition.risk,
                "pack_id": definition.pack_id,
                "lab_artifact_ref": definition.lab_artifact_ref,
                "malicious_checkpoints": len(definition.malicious_steps),
                "benign_checkpoints": len(definition.benign_steps),
                "detector_fields": _detector_field_paths(definition.detector),
                "mappings": {
                    framework: list(values)
                    for framework, values in definition.mappings.items()
                },
            }
            for definition in list_scenarios(selected)
        ],
    }


def load_ground_truth(path: str | Path) -> list[dict[str, object]]:
    """Load and minimally validate AgentSim v1 or v2 JSONL ground truth."""

    events: list[dict[str, object]] = []
    with Path(path).open("r", encoding="utf-8") as input_file:
        for line_number, line in enumerate(input_file, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON on line {line_number}") from exc
            if (
                not isinstance(event, dict)
                or event.get("schema_version") not in SUPPORTED_SCHEMA_VERSIONS
            ):
                raise ValueError(f"invalid ground-truth event on line {line_number}")
            events.append(event)
    return events


def _write_json(path: Path, value: object) -> None:
    with path.open("w", encoding="utf-8") as output_file:
        json.dump(value, output_file, indent=2, sort_keys=True)
        output_file.write("\n")


def _write_junit(path: Path, validation: Mapping[str, object]) -> None:
    results = validation.get("results", ())
    results = results if isinstance(results, Sequence) else ()
    summary = _require_mapping(validation.get("summary", {}), "summary")
    suite = ET.Element(
        "testsuite",
        {
            "name": "AgentSim agent detection benchmark",
            "tests": str(summary.get("checks", 0)),
            "failures": str(summary.get("failed", 0)),
        },
    )
    for result in results:
        if not isinstance(result, Mapping):
            continue
        name = f"{result.get('scenario_id')}[{result.get('variant')}]"
        if result.get("mutation_id"):
            name += f"/{result.get('mutation_id')}"
        case = ET.SubElement(
            suite,
            "testcase",
            {"classname": "agentsim.scenarios", "name": name},
        )
        if not result.get("passed"):
            failure = ET.SubElement(case, "failure", {"message": "detection mismatch"})
            failure.text = json.dumps(dict(result), sort_keys=True)
    tree = ET.ElementTree(suite)
    ET.indent(tree, space="  ")
    tree.write(path, encoding="utf-8", xml_declaration=True)


def _write_sarif(path: Path, validation: Mapping[str, object]) -> None:
    raw_results = validation.get("results", ())
    raw_results = raw_results if isinstance(raw_results, Sequence) else ()
    failures = [
        result
        for result in raw_results
        if isinstance(result, Mapping) and not result.get("passed")
    ]
    scenario_ids = sorted(
        {str(result.get("scenario_id")) for result in failures if result.get("scenario_id")}
    )
    report = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AgentSim",
                        "semanticVersion": "0.3.0",
                        "rules": [
                            {
                                "id": scenario_id,
                                "name": scenario_id.replace("-", " ").title(),
                                "shortDescription": {
                                    "text": "AgentSim detection benchmark mismatch"
                                },
                            }
                            for scenario_id in scenario_ids
                        ],
                    }
                },
                "invocations": [
                    {"executionSuccessful": not failures, "toolExecutionNotifications": []}
                ],
                "results": [
                    {
                        "ruleId": result.get("scenario_id"),
                        "level": "error",
                        "message": {
                            "text": (
                                f"Expected detected={result.get('expected_detected')} but "
                                f"observed detected={result.get('detected')} for "
                                f"{result.get('trace_id')}"
                            )
                        },
                    }
                    for result in failures
                ],
            }
        ],
    }
    _write_json(path, report)


def _otel_attribute(key: str, value: object) -> dict[str, object]:
    if isinstance(value, bool):
        encoded = {"boolValue": value}
    elif isinstance(value, int):
        encoded = {"intValue": str(value)}
    elif isinstance(value, float):
        encoded = {"doubleValue": value}
    elif isinstance(value, (list, tuple)):
        encoded = {
            "arrayValue": {
                "values": [
                    _otel_attribute("item", item)["value"]  # type: ignore[index]
                    for item in value
                ]
            }
        }
    else:
        encoded = {"stringValue": "" if value is None else str(value)}
    return {"key": key, "value": encoded}


def _write_otel_jsonl(path: Path, events: Sequence[Event]) -> None:
    with path.open("w", encoding="utf-8") as output_file:
        for event in events:
            attributes = [
                _otel_attribute("event.name", event.get("event_type")),
                _otel_attribute("gen_ai.operation.name", event.get("stage")),
                _otel_attribute("gen_ai.tool.name", event.get("tool_name")),
                _otel_attribute("agentsim.run.id", event.get("run_id")),
                _otel_attribute("agentsim.trace.id", event.get("trace_id")),
                _otel_attribute("agentsim.agent.id", event.get("agent_id")),
                _otel_attribute("agentsim.session.id", event.get("session_id")),
                _otel_attribute("agentsim.input.trust", event.get("input_trust")),
                _otel_attribute("agentsim.tool.risk", event.get("tool_risk")),
                _otel_attribute("agentsim.policy.decision", event.get("policy_decision")),
                _otel_attribute("agentsim.execution_mode", "simulation_only"),
            ]
            record = {
                "timeUnixNano": str(
                    int(
                        datetime.fromisoformat(
                            str(event.get("timestamp", "")).replace("Z", "+00:00")
                        ).timestamp()
                        * 1_000_000_000
                    )
                ),
                "severityText": "WARN"
                if event.get("expected_detection")
                else "INFO",
                "body": {"stringValue": str(event.get("message", ""))},
                "attributes": attributes,
                "traceId": uuid.uuid5(
                    uuid.NAMESPACE_URL, str(event.get("trace_id", ""))
                ).hex,
                "spanId": uuid.uuid5(
                    uuid.NAMESPACE_URL, str(event.get("event_id", ""))
                ).hex[:16],
            }
            json.dump(record, output_file, separators=(",", ":"), sort_keys=True)
            output_file.write("\n")


def _artifact_path(value: str | Path | None) -> Path | None:
    return Path(value).expanduser() if value is not None else None


def _validate_artifact_parents(paths: Sequence[Path | None]) -> None:
    for artifact_path in paths:
        if artifact_path is not None and not artifact_path.parent.exists():
            raise FileNotFoundError(
                f"output directory does not exist: {artifact_path.parent}"
            )


def run_scenario_suite(
    scenario_ids: str | Sequence[str],
    *,
    variant: str = "both",
    ground_truth_path: str | Path = DEFAULT_GROUND_TRUTH_PATH,
    validation_path: str | Path = DEFAULT_VALIDATION_PATH,
    junit_path: str | Path | None = None,
    sarif_path: str | Path | None = None,
    otel_path: str | Path | None = None,
    coverage_path: str | Path | None = None,
    bundle_path: str | Path | None = None,
    mutation_count: int = 0,
    mutation_seed: int | None = None,
    speed_ms: int = 0,
    log_callback: LogCallback | None = None,
    stop_callback: StopCallback | None = None,
    run_id: str | None = None,
    clock: Clock | None = None,
    registry: Mapping[str, ScenarioDefinition] | None = None,
) -> ScenarioSuiteResult:
    """Run safe scenarios, mutations, scorecards, and portable exports."""

    if isinstance(speed_ms, bool) or not isinstance(speed_ms, int) or speed_ms < 0:
        raise ValueError("speed_ms must be an integer greater than or equal to 0")
    if (
        isinstance(mutation_count, bool)
        or not isinstance(mutation_count, int)
        or not 0 <= mutation_count <= 100
    ):
        raise ValueError("mutation_count must be an integer between 0 and 100")
    selected_registry = registry or SCENARIOS
    selected_ids = resolve_scenario_ids(scenario_ids, selected_registry)
    selected_variants = _variants(variant)
    output_path = Path(ground_truth_path).expanduser()
    report_path = Path(validation_path).expanduser()
    extra_paths = {
        "junit": _artifact_path(junit_path),
        "sarif": _artifact_path(sarif_path),
        "otel": _artifact_path(otel_path),
        "coverage": _artifact_path(coverage_path),
        "bundle": _artifact_path(bundle_path),
    }
    _validate_artifact_parents([output_path, report_path, *extra_paths.values()])

    log = log_callback or print
    should_stop = stop_callback or (lambda: False)
    clock = clock or (lambda: datetime.now(timezone.utc))
    suite_run_id = run_id or uuid.uuid4().hex
    rng = random.Random(mutation_seed)
    events: list[dict[str, object]] = []
    stopped = False
    trace_count = 0

    total_traces = len(selected_ids) * len(selected_variants) * (mutation_count + 1)
    log(
        f"[*] Starting safe agentic benchmark. Scenarios: {len(selected_ids)}; "
        f"traces: {total_traces}; mutations per control: {mutation_count}."
    )
    log("[*] Scenario mode is simulation-only; no tools or network calls execute.")

    try:
        for scenario_id in selected_ids:
            definition = selected_registry[scenario_id]
            for selected_variant in selected_variants:
                base_steps = definition.steps_for(selected_variant)
                for mutation_index in range(mutation_count + 1):
                    if should_stop():
                        stopped = True
                        break
                    mutation_id = (
                        f"mutation-{mutation_index:03d}" if mutation_index else None
                    )
                    steps = (
                        _mutate_steps(base_steps, mutation_index, rng)
                        if mutation_index
                        else tuple(base_steps)
                    )
                    trace_suffix = mutation_id or "baseline"
                    trace_id = (
                        f"{suite_run_id}:{scenario_id}:{selected_variant}:{trace_suffix}"
                    )
                    trace_count += 1
                    parent_event_id: str | None = None
                    event_ids_by_sequence: dict[int, str] = {}
                    log(
                        f"[SCENARIO] {definition.name} "
                        f"[{selected_variant}; {trace_suffix}]"
                    )
                    for sequence, step in enumerate(steps, start=1):
                        if should_stop():
                            stopped = True
                            break
                        event = _build_event(
                            definition=definition,
                            variant=selected_variant,
                            step=step,
                            run_id=suite_run_id,
                            trace_id=trace_id,
                            sequence=sequence,
                            parent_event_id=parent_event_id,
                            event_ids_by_sequence=event_ids_by_sequence,
                            mutation_id=mutation_id,
                            clock=clock,
                        )
                        events.append(event)
                        parent_event_id = str(event["event_id"])
                        event_ids_by_sequence[sequence] = parent_event_id
                        log(f"    [{step.stage}] {step.message}")
                        _pause(speed_ms, should_stop)
                    if stopped:
                        break
                if stopped:
                    break
            if stopped:
                break
    except KeyboardInterrupt:
        stopped = True

    with output_path.open("w", encoding="utf-8") as output_file:
        for event in events:
            json.dump(event, output_file, separators=(",", ":"), sort_keys=True)
            output_file.write("\n")

    validation = validate_events(events, clock=clock, registry=selected_registry)
    validation["run_id"] = suite_run_id
    validation["ground_truth_file"] = output_path.name
    validation["stopped"] = stopped
    validation["mutation_count"] = mutation_count
    _write_json(report_path, validation)

    if extra_paths["junit"]:
        _write_junit(extra_paths["junit"], validation)
    if extra_paths["sarif"]:
        _write_sarif(extra_paths["sarif"], validation)
    if extra_paths["otel"]:
        _write_otel_jsonl(extra_paths["otel"], events)
    if extra_paths["coverage"]:
        coverage = build_coverage_report(
            {scenario_id: selected_registry[scenario_id] for scenario_id in selected_ids}
        )
        coverage["generated_at"] = _timestamp(clock)
        _write_json(extra_paths["coverage"], coverage)
    if extra_paths["bundle"]:
        bundle_members = [output_path, report_path]
        bundle_members.extend(
            path
            for key, path in extra_paths.items()
            if key != "bundle" and path is not None and path.exists()
        )
        with zipfile.ZipFile(
            extra_paths["bundle"], "w", compression=zipfile.ZIP_DEFLATED
        ) as bundle:
            for artifact in bundle_members:
                bundle.write(artifact, arcname=artifact.name)

    summary = _require_mapping(validation["summary"], "summary")
    metrics = _require_mapping(validation["metrics"], "metrics")
    passed = bool(summary["all_passed"]) and not stopped
    log(f"[+] Ground-truth JSONL exported to '{output_path}'")
    log(f"[+] Benchmark report exported to '{report_path}'")
    if extra_paths["bundle"]:
        log(f"[+] Evidence bundle exported to '{extra_paths['bundle']}'")
    if stopped:
        log("[!] Scenario suite stopped; artifacts contain completed checkpoints.")
    elif passed:
        log(
            f"[+] Benchmark passed: {summary['passed']}/{summary['checks']} checks; "
            f"precision={metrics['precision']}; recall={metrics['recall']}."
        )
    else:
        log(f"[!] Benchmark failed: {summary['failed']}/{summary['checks']} checks.")

    return ScenarioSuiteResult(
        run_id=suite_run_id,
        ground_truth_path=output_path,
        validation_path=report_path,
        event_count=len(events),
        trace_count=trace_count,
        check_count=int(summary["checks"]),
        mutation_count=mutation_count,
        passed=passed,
        stopped=stopped,
        junit_path=extra_paths["junit"],
        sarif_path=extra_paths["sarif"],
        otel_path=extra_paths["otel"],
        coverage_path=extra_paths["coverage"],
        bundle_path=extra_paths["bundle"],
        metrics=dict(metrics),
    )
