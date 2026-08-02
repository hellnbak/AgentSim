"""Reusable, answer-key-free detection packs and evidence sweeps."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from agentsim.models.telemetry import NormalizedEvent

from .ast import (
    AllNode,
    AnyNode,
    CausalGraphNode,
    DetectionRule,
    Expression,
    MatchNode,
    NotNode,
    ParentChildNode,
    SequenceNode,
    ThresholdNode,
    parse_rule,
    rule_to_dict,
)
from .evaluator import DetectionEvaluation, evaluate_rule


PACK_SCHEMA_VERSION = "1.0"
BUILTIN_PACK_NAME = "agent_security_core.json"
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_PROHIBITED_KEYS = frozenset(
    {"expected_detection", "expected_detected", "ground_truth", "scenario_variant"}
)


def _expression_fields(expression: Expression) -> set[str]:
    if isinstance(expression, MatchNode):
        return {predicate.field for predicate in expression.predicates}
    if isinstance(expression, (AllNode, AnyNode)):
        return {field for child in expression.children for field in _expression_fields(child)}
    if isinstance(expression, NotNode):
        return _expression_fields(expression.child)
    if isinstance(expression, SequenceNode):
        return {field for step in expression.steps for field in _expression_fields(step)}
    if isinstance(expression, ThresholdNode):
        fields = _expression_fields(expression.child)
        if expression.distinct_field:
            fields.add(expression.distinct_field)
        return fields
    if isinstance(expression, ParentChildNode):
        return _expression_fields(expression.parent) | _expression_fields(expression.child) | {
            "process_id",
            "parent_process_id",
        }
    if isinstance(expression, CausalGraphNode):
        return (
            {field for step in expression.steps for field in _expression_fields(step)}
            | {expression.link_field, "source_record_id"}
        )
    raise TypeError(f"Unsupported expression: {type(expression).__name__}")


def _reject_answer_keys(value: object) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).casefold() in _PROHIBITED_KEYS:
                raise ValueError(f"detection packs must not contain answer-key field: {key}")
            _reject_answer_keys(item)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            _reject_answer_keys(item)


@dataclass(frozen=True)
class PackedDetection:
    rule: DetectionRule
    required_fields: tuple[str, ...]
    expected_sources: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            **rule_to_dict(self.rule),
            "required_fields": list(self.required_fields),
            "expected_sources": list(self.expected_sources),
        }


@dataclass(frozen=True)
class DetectionPack:
    pack_id: str
    name: str
    version: str
    description: str
    rules: tuple[PackedDetection, ...]
    metadata: Mapping[str, object]

    def to_dict(self) -> dict[str, object]:
        return {
            "pack_schema_version": PACK_SCHEMA_VERSION,
            "pack_id": self.pack_id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "rules": [item.to_dict() for item in self.rules],
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class DetectionSweepOutcome:
    rule_id: str
    name: str
    severity: str
    status: str
    field_coverage_percent: float
    missing_fields: tuple[str, ...]
    missing_sources: tuple[str, ...]
    evaluation: DetectionEvaluation

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "status": self.status,
            "field_coverage_percent": self.field_coverage_percent,
            "missing_fields": list(self.missing_fields),
            "missing_sources": list(self.missing_sources),
            "evaluation": self.evaluation.to_dict(),
        }


@dataclass(frozen=True)
class DetectionSweepReport:
    pack_id: str
    pack_version: str
    record_count: int
    outcomes: tuple[DetectionSweepOutcome, ...]

    def to_dict(self) -> dict[str, object]:
        counts = {"detected": 0, "not_detected": 0, "visibility_gap": 0}
        for outcome in self.outcomes:
            counts[outcome.status] += 1
        return {
            "schema_version": "1.0",
            "kind": "detection-sweep-report",
            "pack_id": self.pack_id,
            "pack_version": self.pack_version,
            "record_count": self.record_count,
            "summary": counts,
            "outcomes": [outcome.to_dict() for outcome in self.outcomes],
            "ground_truth_used": False,
        }


def parse_detection_pack(value: Mapping[str, object]) -> DetectionPack:
    _reject_answer_keys(value)
    if value.get("pack_schema_version") != PACK_SCHEMA_VERSION:
        raise ValueError(f"unsupported detection pack schema: {value.get('pack_schema_version')}")
    allowed = {"pack_schema_version", "pack_id", "name", "version", "description", "rules", "metadata"}
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"unknown detection pack fields: {', '.join(unknown)}")
    pack_id = str(value.get("pack_id", ""))
    if not _IDENTIFIER.fullmatch(pack_id):
        raise ValueError("detection pack_id must be a lowercase dotted identifier")
    rules_value = value.get("rules")
    if not isinstance(rules_value, Sequence) or isinstance(rules_value, (str, bytes)):
        raise ValueError("detection pack rules must be an array")
    if not rules_value or len(rules_value) > 500:
        raise ValueError("detection packs require 1 to 500 rules")
    packed: list[PackedDetection] = []
    identifiers: set[str] = set()
    for item in rules_value:
        if not isinstance(item, Mapping):
            raise ValueError("each packed detection must be an object")
        allowed_rule_fields = {
            "schema_version",
            "rule_id",
            "name",
            "description",
            "severity",
            "group_by",
            "mappings",
            "expression",
            "metadata",
            "required_fields",
            "expected_sources",
        }
        unknown_rule_fields = sorted(set(item) - allowed_rule_fields)
        if unknown_rule_fields:
            raise ValueError(
                f"unknown packed detection fields: {', '.join(unknown_rule_fields)}"
            )
        rule_value = {key: child for key, child in item.items() if key not in {"required_fields", "expected_sources"}}
        rule = parse_rule(rule_value)
        if rule.rule_id in identifiers:
            raise ValueError(f"duplicate detection rule_id: {rule.rule_id}")
        identifiers.add(rule.rule_id)
        required_value = item.get("required_fields", ())
        sources_value = item.get("expected_sources", ())
        if not isinstance(required_value, Sequence) or isinstance(required_value, (str, bytes)):
            raise ValueError(f"{rule.rule_id}.required_fields must be an array")
        if not isinstance(sources_value, Sequence) or isinstance(sources_value, (str, bytes)):
            raise ValueError(f"{rule.rule_id}.expected_sources must be an array")
        required = tuple(sorted({str(field) for field in required_value if str(field)}))
        expected_sources = tuple(sorted({str(source) for source in sources_value if str(source)}))
        derived = _expression_fields(rule.expression) | set(rule.group_by)
        missing_declarations = sorted(derived - set(required))
        if missing_declarations:
            raise ValueError(
                f"{rule.rule_id}.required_fields omits rule fields: {', '.join(missing_declarations)}"
            )
        packed.append(PackedDetection(rule, required, expected_sources))
    metadata = value.get("metadata", {})
    if not isinstance(metadata, Mapping):
        raise ValueError("detection pack metadata must be an object")
    name, version = str(value.get("name", "")), str(value.get("version", ""))
    if not name or not version:
        raise ValueError("detection packs require name and version")
    return DetectionPack(
        pack_id,
        name,
        version,
        str(value.get("description", "")),
        tuple(packed),
        dict(metadata),
    )


def load_detection_pack(path: str | Path | None = None) -> DetectionPack:
    if path is None:
        data = resources.files("agentsim.detection.pack_content").joinpath(BUILTIN_PACK_NAME).read_text(
            encoding="utf-8"
        )
    else:
        candidate = Path(path)
        if not candidate.is_file():
            raise FileNotFoundError(f"detection pack does not exist: {candidate}")
        if candidate.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("detection pack exceeds the 4 MiB limit")
        data = candidate.read_text(encoding="utf-8")
    value = json.loads(data)
    if not isinstance(value, Mapping):
        raise ValueError("detection pack must be a JSON object")
    return parse_detection_pack(value)


def sweep_detection_pack(
    pack: DetectionPack, events: Iterable[NormalizedEvent]
) -> DetectionSweepReport:
    values = tuple(events)
    available = {"timestamp", "source", "event_type", "source_record_id"}
    available.update(field for event in values for field in event.available_fields)
    available.update(field for event in values for field in event.fields)
    sources = {event.source for event in values}
    outcomes: list[DetectionSweepOutcome] = []
    for item in pack.rules:
        missing_fields = tuple(sorted(set(item.required_fields) - available))
        missing_sources = (
            item.expected_sources if item.expected_sources and not sources.intersection(item.expected_sources) else ()
        )
        evaluation = evaluate_rule(item.rule, values)
        coverage = round(
            100.0 * (len(item.required_fields) - len(missing_fields)) / len(item.required_fields),
            2,
        ) if item.required_fields else 100.0
        if evaluation.matched:
            status = "detected"
        elif missing_fields or missing_sources:
            status = "visibility_gap"
        else:
            status = "not_detected"
        outcomes.append(
            DetectionSweepOutcome(
                item.rule.rule_id,
                item.rule.name,
                item.rule.severity,
                status,
                coverage,
                missing_fields,
                missing_sources,
                evaluation,
            )
        )
    return DetectionSweepReport(pack.pack_id, pack.version, len(values), tuple(outcomes))


__all__ = [
    "DetectionPack",
    "DetectionSweepOutcome",
    "DetectionSweepReport",
    "PackedDetection",
    "load_detection_pack",
    "parse_detection_pack",
    "sweep_detection_pack",
]
