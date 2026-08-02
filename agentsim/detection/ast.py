"""A small, serializable detection AST used by the offline validation engine."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence, Union


OPERATORS = frozenset(
    {"eq", "ne", "in", "contains", "exists", "startswith", "endswith", "matches"}
)


@dataclass(frozen=True)
class Predicate:
    field: str
    operator: str
    value: object = None

    def __post_init__(self) -> None:
        if not self.field:
            raise ValueError("Detection predicate field must not be empty")
        if self.operator not in OPERATORS:
            raise ValueError(f"Unsupported detection operator: {self.operator}")


@dataclass(frozen=True)
class MatchNode:
    predicates: tuple[Predicate, ...]

    def __post_init__(self) -> None:
        if not self.predicates:
            raise ValueError("Match expression requires at least one predicate")


@dataclass(frozen=True)
class AllNode:
    children: tuple["Expression", ...]

    def __post_init__(self) -> None:
        if not self.children:
            raise ValueError("All expression requires at least one child")


@dataclass(frozen=True)
class AnyNode:
    children: tuple["Expression", ...]

    def __post_init__(self) -> None:
        if not self.children:
            raise ValueError("Any expression requires at least one child")


@dataclass(frozen=True)
class NotNode:
    child: "Expression"


@dataclass(frozen=True)
class SequenceNode:
    steps: tuple["Expression", ...]
    max_span_seconds: int = 300

    def __post_init__(self) -> None:
        if not self.steps or self.max_span_seconds < 1:
            raise ValueError("Sequence requires steps and a positive max span")


@dataclass(frozen=True)
class ThresholdNode:
    child: "Expression"
    count: int
    window_seconds: int = 300
    distinct_field: str | None = None

    def __post_init__(self) -> None:
        if self.count < 1 or self.window_seconds < 1:
            raise ValueError("Threshold count and window must be positive")


@dataclass(frozen=True)
class ParentChildNode:
    parent: "Expression"
    child: "Expression"


@dataclass(frozen=True)
class CausalGraphNode:
    steps: tuple["Expression", ...]
    link_field: str = "parent_event_id"

    def __post_init__(self) -> None:
        if not self.steps or not self.link_field:
            raise ValueError("Causal graph requires steps and a link field")


@dataclass(frozen=True)
class GraphPathNode:
    """Match ordered expressions connected by one or more causal link fields."""

    steps: tuple["Expression", ...]
    link_fields: tuple[str, ...] = ("parent_event_id", "caused_by_event_ids")
    max_depth: int = 6

    def __post_init__(self) -> None:
        if len(self.steps) < 2 or not self.link_fields or not 1 <= self.max_depth <= 50:
            raise ValueError("Graph path requires two steps, link fields, and depth 1 to 50")


@dataclass(frozen=True)
class GraphFanoutNode:
    """Match a causal root that reaches multiple distinct descendants."""

    root: "Expression"
    descendant: "Expression"
    count: int
    distinct_field: str
    link_fields: tuple[str, ...] = ("parent_event_id", "caused_by_event_ids")
    max_depth: int = 6

    def __post_init__(self) -> None:
        if self.count < 1 or not self.distinct_field or not self.link_fields:
            raise ValueError("Graph fan-out requires a positive count, distinct field, and link fields")
        if not 1 <= self.max_depth <= 50:
            raise ValueError("Graph fan-out depth must be between 1 and 50")


Expression = Union[
    MatchNode,
    AllNode,
    AnyNode,
    NotNode,
    SequenceNode,
    ThresholdNode,
    ParentChildNode,
    CausalGraphNode,
    GraphPathNode,
    GraphFanoutNode,
]


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    name: str
    expression: Expression
    severity: str = "medium"
    description: str = ""
    group_by: tuple[str, ...] = field(default_factory=tuple)
    mappings: tuple[str, ...] = field(default_factory=tuple)
    metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.rule_id or not self.name:
            raise ValueError("Detection rule requires an ID and name")
        if self.severity not in {"low", "medium", "high", "critical"}:
            raise ValueError("Detection severity must be low, medium, high, or critical")
        if any(not group for group in self.group_by):
            raise ValueError("Detection group fields must not be empty")


def expression_to_dict(expression: Expression) -> dict[str, object]:
    if isinstance(expression, MatchNode):
        return {
            "type": "match",
            "predicates": [
                {"field": item.field, "operator": item.operator, "value": item.value}
                for item in expression.predicates
            ],
        }
    if isinstance(expression, (AllNode, AnyNode)):
        return {
            "type": "all" if isinstance(expression, AllNode) else "any",
            "children": [expression_to_dict(item) for item in expression.children],
        }
    if isinstance(expression, NotNode):
        return {"type": "not", "child": expression_to_dict(expression.child)}
    if isinstance(expression, SequenceNode):
        return {
            "type": "sequence",
            "steps": [expression_to_dict(item) for item in expression.steps],
            "max_span_seconds": expression.max_span_seconds,
        }
    if isinstance(expression, ThresholdNode):
        return {
            "type": "threshold",
            "child": expression_to_dict(expression.child),
            "count": expression.count,
            "window_seconds": expression.window_seconds,
            "distinct_field": expression.distinct_field,
        }
    if isinstance(expression, ParentChildNode):
        return {
            "type": "parent_child",
            "parent": expression_to_dict(expression.parent),
            "child": expression_to_dict(expression.child),
        }
    if isinstance(expression, CausalGraphNode):
        return {
            "type": "causal_graph",
            "steps": [expression_to_dict(item) for item in expression.steps],
            "link_field": expression.link_field,
        }
    if isinstance(expression, GraphPathNode):
        return {
            "type": "graph_path",
            "steps": [expression_to_dict(item) for item in expression.steps],
            "link_fields": list(expression.link_fields),
            "max_depth": expression.max_depth,
        }
    if isinstance(expression, GraphFanoutNode):
        return {
            "type": "graph_fanout",
            "root": expression_to_dict(expression.root),
            "descendant": expression_to_dict(expression.descendant),
            "count": expression.count,
            "distinct_field": expression.distinct_field,
            "link_fields": list(expression.link_fields),
            "max_depth": expression.max_depth,
        }
    raise TypeError(f"Unsupported expression: {type(expression).__name__}")


def parse_expression(data: Mapping[str, object]) -> Expression:
    kind = str(data.get("type", ""))
    if kind == "match":
        values = data.get("predicates", ())
        if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
            raise ValueError("match.predicates must be a list")
        if not values:
            raise ValueError("match.predicates must not be empty")
        predicates: list[Predicate] = []
        for value in values:
            if not isinstance(value, Mapping):
                raise ValueError("Each predicate must be an object")
            predicates.append(
                Predicate(str(value["field"]), str(value.get("operator", "eq")), value.get("value"))
            )
        return MatchNode(tuple(predicates))
    if kind in {"all", "any"}:
        children = data.get("children", ())
        if not isinstance(children, Sequence) or isinstance(children, (str, bytes)):
            raise ValueError(f"{kind}.children must be a list")
        if not children or any(not isinstance(item, Mapping) for item in children):
            raise ValueError(f"{kind}.children must contain expression objects")
        parsed = tuple(parse_expression(item) for item in children)
        return AllNode(parsed) if kind == "all" else AnyNode(parsed)
    if kind == "not":
        child = data.get("child")
        if not isinstance(child, Mapping):
            raise ValueError("not.child must be an object")
        return NotNode(parse_expression(child))
    if kind == "sequence":
        steps = data.get("steps", ())
        if not isinstance(steps, Sequence) or isinstance(steps, (str, bytes)):
            raise ValueError("sequence.steps must be a list")
        if not steps or any(not isinstance(item, Mapping) for item in steps):
            raise ValueError("sequence.steps must contain expression objects")
        return SequenceNode(
            tuple(parse_expression(item) for item in steps),
            int(data.get("max_span_seconds", 300)),
        )
    if kind == "threshold":
        child = data.get("child")
        if not isinstance(child, Mapping):
            raise ValueError("threshold.child must be an object")
        return ThresholdNode(
            parse_expression(child),
            int(data["count"]),
            int(data.get("window_seconds", 300)),
            str(data["distinct_field"]) if data.get("distinct_field") else None,
        )
    if kind == "parent_child":
        parent, child = data.get("parent"), data.get("child")
        if not isinstance(parent, Mapping) or not isinstance(child, Mapping):
            raise ValueError("parent_child requires parent and child objects")
        return ParentChildNode(parse_expression(parent), parse_expression(child))
    if kind == "causal_graph":
        steps = data.get("steps", ())
        if not isinstance(steps, Sequence) or isinstance(steps, (str, bytes)):
            raise ValueError("causal_graph.steps must be a list")
        if not steps or any(not isinstance(item, Mapping) for item in steps):
            raise ValueError("causal_graph.steps must contain expression objects")
        return CausalGraphNode(
            tuple(parse_expression(item) for item in steps),
            str(data.get("link_field", "parent_event_id")),
        )
    if kind == "graph_path":
        steps = data.get("steps", ())
        link_fields = data.get("link_fields", ("parent_event_id", "caused_by_event_ids"))
        if not isinstance(steps, Sequence) or isinstance(steps, (str, bytes)):
            raise ValueError("graph_path.steps must be a list")
        if len(steps) < 2 or any(not isinstance(item, Mapping) for item in steps):
            raise ValueError("graph_path.steps must contain at least two expression objects")
        if not isinstance(link_fields, Sequence) or isinstance(link_fields, (str, bytes)):
            raise ValueError("graph_path.link_fields must be a list")
        return GraphPathNode(
            tuple(parse_expression(item) for item in steps),
            tuple(str(item) for item in link_fields),
            int(data.get("max_depth", 6)),
        )
    if kind == "graph_fanout":
        root, descendant = data.get("root"), data.get("descendant")
        link_fields = data.get("link_fields", ("parent_event_id", "caused_by_event_ids"))
        if not isinstance(root, Mapping) or not isinstance(descendant, Mapping):
            raise ValueError("graph_fanout requires root and descendant objects")
        if not isinstance(link_fields, Sequence) or isinstance(link_fields, (str, bytes)):
            raise ValueError("graph_fanout.link_fields must be a list")
        return GraphFanoutNode(
            parse_expression(root),
            parse_expression(descendant),
            int(data["count"]),
            str(data["distinct_field"]),
            tuple(str(item) for item in link_fields),
            int(data.get("max_depth", 6)),
        )
    raise ValueError(f"Unknown detection expression type: {kind or '<missing>'}")


def rule_to_dict(rule: DetectionRule) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "rule_id": rule.rule_id,
        "name": rule.name,
        "description": rule.description,
        "severity": rule.severity,
        "group_by": list(rule.group_by),
        "mappings": list(rule.mappings),
        "expression": expression_to_dict(rule.expression),
        "metadata": dict(rule.metadata),
    }


def parse_rule(data: Mapping[str, object]) -> DetectionRule:
    expression = data.get("expression")
    if not isinstance(expression, Mapping):
        raise ValueError("Detection rule requires an expression object")
    return DetectionRule(
        rule_id=str(data["rule_id"]),
        name=str(data["name"]),
        expression=parse_expression(expression),
        severity=str(data.get("severity", "medium")),
        description=str(data.get("description", "")),
        group_by=tuple(str(item) for item in data.get("group_by", ())),
        mappings=tuple(str(item) for item in data.get("mappings", ())),
        metadata=dict(data.get("metadata", {})) if isinstance(data.get("metadata", {}), Mapping) else {},
    )


def load_rule(path: str | Path) -> DetectionRule:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, Mapping):
        raise ValueError("Detection rule must be a JSON object")
    return parse_rule(data)
