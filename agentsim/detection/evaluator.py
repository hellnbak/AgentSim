"""Deterministic, bounded evaluation of the AgentSim detection AST."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Mapping, Sequence

from agentsim.detection.ast import (
    AllNode,
    AnyNode,
    CausalGraphNode,
    DetectionRule,
    Expression,
    MatchNode,
    NotNode,
    ParentChildNode,
    Predicate,
    SequenceNode,
    ThresholdNode,
)
from agentsim.models.telemetry import NormalizedEvent


MAX_REGEX_LENGTH = 200


@dataclass(frozen=True)
class DetectionEvaluation:
    rule_id: str
    matched: bool
    match_count: int
    matched_indices: tuple[int, ...]
    group_matches: Mapping[str, tuple[int, ...]]
    evidence: tuple[Mapping[str, object], ...]
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "matched": self.matched,
            "match_count": self.match_count,
            "matched_indices": list(self.matched_indices),
            "group_matches": {key: list(value) for key, value in self.group_matches.items()},
            "evidence": [dict(item) for item in self.evidence],
            "warnings": list(self.warnings),
        }


def _timestamp(event: NormalizedEvent) -> float:
    try:
        parsed = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except ValueError:
        return 0.0


def _many(value: object) -> tuple[object, ...]:
    return tuple(value) if isinstance(value, (list, tuple, set, frozenset)) else (value,)


def _predicate_matches(event: NormalizedEvent, predicate: Predicate) -> bool:
    observed = event.get(predicate.field)
    expected = predicate.value
    if predicate.operator == "exists":
        return (observed is not None) is bool(expected if expected is not None else True)
    if predicate.operator == "eq":
        return observed == expected
    if predicate.operator == "ne":
        return observed != expected
    if predicate.operator == "in":
        return observed in _many(expected)
    if predicate.operator == "contains":
        if isinstance(observed, (list, tuple, set, frozenset)):
            return expected in observed
        return str(expected).casefold() in str(observed or "").casefold()
    if predicate.operator == "startswith":
        return str(observed or "").casefold().startswith(str(expected).casefold())
    if predicate.operator == "endswith":
        return str(observed or "").casefold().endswith(str(expected).casefold())
    if predicate.operator == "matches":
        pattern = str(expected)
        if len(pattern) > MAX_REGEX_LENGTH or any(character in pattern for character in "(){}"):
            return False
        if re.search(r"\\[1-9]|[*+?][*+?]", pattern):
            return False
        try:
            return re.search(pattern, str(observed or ""), flags=re.IGNORECASE) is not None
        except re.error:
            return False
    return False


def _matches(expression: Expression, events: Sequence[NormalizedEvent]) -> set[int]:
    if isinstance(expression, MatchNode):
        return {
            index
            for index, event in enumerate(events)
            if all(_predicate_matches(event, predicate) for predicate in expression.predicates)
        }
    if isinstance(expression, AllNode):
        if not expression.children:
            return set()
        values = [_matches(child, events) for child in expression.children]
        return set.intersection(*values)
    if isinstance(expression, AnyNode):
        values = [_matches(child, events) for child in expression.children]
        return set.union(*values) if values else set()
    if isinstance(expression, NotNode):
        return set(range(len(events))) - _matches(expression.child, events)
    if isinstance(expression, SequenceNode):
        step_matches = [_matches(step, events) for step in expression.steps]
        if not step_matches or any(not indexes for indexes in step_matches):
            return set()
        ordered = sorted(range(len(events)), key=lambda index: (_timestamp(events[index]), index))
        results: set[int] = set()
        for start_position, first in enumerate(ordered):
            if first not in step_matches[0]:
                continue
            chain = [first]
            cursor = start_position + 1
            for candidates in step_matches[1:]:
                while cursor < len(ordered) and ordered[cursor] not in candidates:
                    cursor += 1
                if cursor >= len(ordered):
                    break
                chain.append(ordered[cursor])
                cursor += 1
            if len(chain) == len(step_matches):
                span = _timestamp(events[chain[-1]]) - _timestamp(events[chain[0]])
                if 0 <= span <= expression.max_span_seconds:
                    results.update(chain)
        return results
    if isinstance(expression, ThresholdNode):
        candidates = sorted(_matches(expression.child, events), key=lambda index: _timestamp(events[index]))
        results: set[int] = set()
        for position, start in enumerate(candidates):
            window = [
                index
                for index in candidates[position:]
                if _timestamp(events[index]) - _timestamp(events[start]) <= expression.window_seconds
            ]
            if expression.distinct_field:
                values = {
                    events[index].get(expression.distinct_field)
                    for index in window
                    if events[index].get(expression.distinct_field) is not None
                }
                passed = len(values) >= expression.count
            else:
                passed = len(window) >= expression.count
            if passed:
                results.update(window)
        return results
    if isinstance(expression, ParentChildNode):
        parents = _matches(expression.parent, events)
        children = _matches(expression.child, events)
        results: set[int] = set()
        for parent in parents:
            parent_id = events[parent].get("process_id")
            if parent_id is None:
                continue
            for child in children:
                if events[child].get("parent_process_id") == parent_id:
                    results.update((parent, child))
        return results
    if isinstance(expression, CausalGraphNode):
        step_matches = [_matches(step, events) for step in expression.steps]
        if not step_matches:
            return set()
        event_ids = {index: events[index].source_record_id for index in range(len(events))}
        results: set[int] = set()
        for root in step_matches[0]:
            chain = [root]
            for candidates in step_matches[1:]:
                parent_id = event_ids.get(chain[-1])
                child = next(
                    (
                        index
                        for index in candidates
                        if parent_id is not None
                        and str(events[index].get(expression.link_field)) == str(parent_id)
                    ),
                    None,
                )
                if child is None:
                    break
                chain.append(child)
            if len(chain) == len(step_matches):
                results.update(chain)
        return results
    raise TypeError(f"Unsupported expression: {type(expression).__name__}")


def _group_key(event: NormalizedEvent, fields: Sequence[str]) -> str:
    return "|".join(f"{field}={event.get(field, '<missing>')}" for field in fields)


def evaluate_rule(rule: DetectionRule, events: Iterable[NormalizedEvent]) -> DetectionEvaluation:
    """Evaluate a rule without executing user code or contacting external systems."""

    values = tuple(events)
    grouped: dict[str, list[tuple[int, NormalizedEvent]]] = {}
    for index, event in enumerate(values):
        grouped.setdefault(_group_key(event, rule.group_by) if rule.group_by else "all", []).append(
            (index, event)
        )
    group_matches: dict[str, tuple[int, ...]] = {}
    for key, group in grouped.items():
        local_events = tuple(event for _, event in group)
        original_indices = tuple(index for index, _ in group)
        local_matches = _matches(rule.expression, local_events)
        if local_matches:
            group_matches[key] = tuple(sorted(original_indices[index] for index in local_matches))
    indices = tuple(sorted({index for matches in group_matches.values() for index in matches}))
    evidence = tuple(
        {
            "index": index,
            "timestamp": values[index].timestamp,
            "source": values[index].source,
            "event_type": values[index].event_type,
            "source_record_id": values[index].source_record_id,
            "synthetic": values[index].synthetic,
        }
        for index in indices[:100]
    )
    warnings = ("evidence_truncated",) if len(indices) > 100 else ()
    return DetectionEvaluation(
        rule_id=rule.rule_id,
        matched=bool(indices),
        match_count=len(indices),
        matched_indices=indices,
        group_matches=group_matches,
        evidence=evidence,
        warnings=warnings,
    )
