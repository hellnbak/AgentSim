"""Bounded multi-agent investigation graphs and defensive invariants."""

from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, replace
from typing import Iterable, Mapping, Sequence

from agentsim.models.telemetry import NormalizedEvent


INVESTIGATION_SCHEMA_VERSION = "1.0"
MAX_INVESTIGATION_EVENTS = 5000
_SEVERITY_WEIGHT = {"critical": 25, "high": 15, "medium": 8, "low": 3}
_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass(frozen=True)
class InvestigationNode:
    event_id: str
    index: int
    timestamp: str
    trace_id: str
    fixture_id: str | None
    variant: str | None
    session_id: str | None
    event_type: str
    agent_id: str | None
    principal_id: str | None
    delegation_id: str | None
    data_lineage_id: str | None
    memory_id: str | None
    goal_id: str | None
    tool_risk: str | None
    input_trust: str | None
    policy_decision: str | None
    outcome: str | None
    depth: int = 0
    flags: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class InvestigationEdge:
    source_event_id: str
    target_event_id: str
    relationship: str
    trace_id: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class InvariantFinding:
    finding_id: str
    code: str
    severity: str
    title: str
    description: str
    trace_id: str
    event_ids: tuple[str, ...]
    evidence: Mapping[str, object]
    remediation: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["event_ids"] = list(self.event_ids)
        value["evidence"] = dict(self.evidence)
        value["remediation"] = list(self.remediation)
        return value


@dataclass(frozen=True)
class InvestigationPath:
    path_id: str
    finding_id: str
    severity: str
    title: str
    event_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["event_ids"] = list(self.event_ids)
        return value


@dataclass(frozen=True)
class InvestigationReport:
    status: str
    score: int
    event_count: int
    trace_count: int
    agent_count: int
    delegation_count: int
    memory_count: int
    goal_count: int
    max_depth: int
    nodes: tuple[InvestigationNode, ...]
    edges: tuple[InvestigationEdge, ...]
    findings: tuple[InvariantFinding, ...]
    paths: tuple[InvestigationPath, ...]
    traces: tuple[Mapping[str, object], ...]

    def to_dict(self) -> dict[str, object]:
        severity_counts = {
            severity: sum(item.severity == severity for item in self.findings)
            for severity in ("critical", "high", "medium", "low")
        }
        return {
            "kind": "multi-agent-investigation-report",
            "schema_version": INVESTIGATION_SCHEMA_VERSION,
            "status": self.status,
            "score": self.score,
            "summary": {
                "events": self.event_count,
                "traces": self.trace_count,
                "agents": self.agent_count,
                "delegations": self.delegation_count,
                "memories": self.memory_count,
                "goals": self.goal_count,
                "edges": len(self.edges),
                "max_depth": self.max_depth,
                "findings": len(self.findings),
                "severity": severity_counts,
            },
            "traces": [dict(item) for item in self.traces],
            "nodes": [item.to_dict() for item in self.nodes],
            "edges": [item.to_dict() for item in self.edges],
            "findings": [item.to_dict() for item in self.findings],
            "paths": [item.to_dict() for item in self.paths],
            "content_values_recorded": False,
        }


def _text(value: object) -> str | None:
    return str(value) if value not in (None, "") else None


def _strings(value: object) -> tuple[str, ...]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return tuple(str(item) for item in value if item not in (None, ""))
    return (str(value),) if value not in (None, "") else ()


def _event_id(event: NormalizedEvent, index: int) -> str:
    return _text(event.source_record_id) or _text(event.get("event_id")) or f"event-{index:05d}"


def _flags(event: NormalizedEvent) -> tuple[str, ...]:
    flags: list[str] = []
    if event.get("input_trust") == "untrusted":
        flags.append("untrusted_input")
    if event.get("tool_risk") in {"high", "critical"}:
        flags.append("high_risk_tool")
    if event.get("policy_decision") in {"deny", "block"}:
        flags.append("prevented")
    for name in (
        "identity_binding_valid",
        "goal_integrity_valid",
        "memory_provenance_valid",
        "memory_retention_valid",
    ):
        if event.get(name) is False:
            flags.append(name.removesuffix("_valid") + "_failure")
    return tuple(flags)


def _depths(nodes: Sequence[InvestigationNode], edges: Sequence[InvestigationEdge]) -> dict[str, int]:
    depths = {node.event_id: 0 for node in nodes}
    children: dict[str, set[str]] = {node.event_id: set() for node in nodes}
    indegree = {node.event_id: 0 for node in nodes}
    for edge in edges:
        if edge.relationship not in {"parent", "caused_by"}:
            continue
        if edge.target_event_id not in children[edge.source_event_id]:
            children[edge.source_event_id].add(edge.target_event_id)
            indegree[edge.target_event_id] += 1

    # A topological pass keeps this linear in graph size. Nodes in a malformed
    # causal cycle remain at depth zero instead of repeatedly inflating depth.
    pending = deque(event_id for event_id, degree in indegree.items() if degree == 0)
    while pending:
        source = pending.popleft()
        for target in children[source]:
            depths[target] = max(depths[target], depths[source] + 1)
            indegree[target] -= 1
            if indegree[target] == 0:
                pending.append(target)
    return depths


def _finding(
    findings: list[InvariantFinding],
    *,
    code: str,
    severity: str,
    title: str,
    description: str,
    trace_id: str,
    event_ids: Sequence[str],
    evidence: Mapping[str, object],
    remediation: Sequence[str],
) -> None:
    findings.append(
        InvariantFinding(
            finding_id=f"INV-{len(findings) + 1:04d}",
            code=code,
            severity=severity,
            title=title,
            description=description,
            trace_id=trace_id,
            event_ids=tuple(dict.fromkeys(event_ids)),
            evidence=dict(evidence),
            remediation=tuple(remediation),
        )
    )


def investigate_telemetry(events: Iterable[NormalizedEvent]) -> InvestigationReport:
    """Reconstruct a content-safe graph and evaluate multi-agent invariants."""

    values = tuple(events)
    if len(values) > MAX_INVESTIGATION_EVENTS:
        raise ValueError(f"investigation is limited to {MAX_INVESTIGATION_EVENTS} events")

    nodes: list[InvestigationNode] = []
    records: dict[str, NormalizedEvent] = {}
    external_ids: dict[str, str] = {}
    for index, event in enumerate(values):
        base_id = _event_id(event, index)
        event_id = base_id if base_id not in records else f"{base_id}#{index}"
        external_ids.setdefault(base_id, event_id)
        records[event_id] = event
        nodes.append(
            InvestigationNode(
                event_id=event_id,
                index=index,
                timestamp=event.timestamp,
                trace_id=_text(event.get("trace_id")) or "unknown-trace",
                fixture_id=_text(event.get("attributes.fixture_id")),
                variant=_text(event.get("attributes.variant")),
                session_id=_text(event.get("session_id")),
                event_type=event.event_type,
                agent_id=_text(event.get("agent_id")),
                principal_id=_text(event.get("principal_id")),
                delegation_id=_text(event.get("delegation_id")),
                data_lineage_id=_text(event.get("data_lineage_id")),
                memory_id=_text(event.get("memory_id")),
                goal_id=_text(event.get("goal_id")),
                tool_risk=_text(event.get("tool_risk")),
                input_trust=_text(event.get("input_trust")),
                policy_decision=_text(event.get("policy_decision")),
                outcome=_text(event.get("outcome")),
                flags=_flags(event),
            )
        )

    node_by_id = {node.event_id: node for node in nodes}
    edges: list[InvestigationEdge] = []
    edge_keys: set[tuple[str, str, str]] = set()

    def add_edge(source: str, target: str, relationship: str) -> None:
        key = (source, target, relationship)
        if source == target or key in edge_keys or source not in node_by_id or target not in node_by_id:
            return
        if node_by_id[source].trace_id != node_by_id[target].trace_id and relationship in {
            "parent",
            "caused_by",
            "delegation",
        }:
            return
        edge_keys.add(key)
        edges.append(InvestigationEdge(source, target, relationship, node_by_id[target].trace_id))

    for node in nodes:
        event = records[node.event_id]
        parent = _text(event.get("parent_event_id"))
        if parent and parent in external_ids:
            add_edge(external_ids[parent], node.event_id, "parent")
        for cause in _strings(event.get("caused_by_event_ids")):
            if cause in external_ids and cause != parent:
                add_edge(external_ids[cause], node.event_id, "caused_by")

    for attribute, relationship in (
        ("delegation_id", "delegation"),
        ("data_lineage_id", "data_lineage"),
        ("memory_id", "memory_lineage"),
    ):
        previous: dict[tuple[str, str], str] = {}
        for node in nodes:
            value = _text(records[node.event_id].get(attribute))
            if value:
                key = (node.trace_id, value)
                if key in previous:
                    add_edge(previous[key], node.event_id, relationship)
                previous[key] = node.event_id

    depths = _depths(nodes, edges)
    nodes = [replace(node, depth=depths.get(node.event_id, 0)) for node in nodes]
    node_by_id = {node.event_id: node for node in nodes}
    findings: list[InvariantFinding] = []

    causal_edges = [edge for edge in edges if edge.relationship in {"parent", "caused_by"}]
    for edge in causal_edges:
        parent = node_by_id[edge.source_event_id]
        child = node_by_id[edge.target_event_id]
        if parent.agent_id and child.agent_id and parent.agent_id != child.agent_id:
            event = records[child.event_id]
            if not child.delegation_id:
                _finding(
                    findings,
                    code="agent_handoff_without_delegation",
                    severity="high",
                    title="Agent identity changed without a delegation record",
                    description="A causal edge crosses agent identities without a delegation identifier.",
                    trace_id=child.trace_id,
                    event_ids=(parent.event_id, child.event_id),
                    evidence={"from_agent": parent.agent_id, "to_agent": child.agent_id},
                    remediation=("Require a signed delegation envelope for every cross-agent handoff.",),
                )
            elif (
                child.event_type == "agent.delegation.accepted"
                and event.get("identity_binding_valid") is False
            ):
                _finding(
                    findings,
                    code="delegation_identity_binding_failed",
                    severity="critical",
                    title="Delegation identity binding failed",
                    description="The receiving agent did not match the identity bound to the delegation.",
                    trace_id=child.trace_id,
                    event_ids=(parent.event_id, child.event_id),
                    evidence={"delegation_id": child.delegation_id, "from_agent": parent.agent_id, "observed_agent": child.agent_id},
                    remediation=("Verify sender, receiver, task, and delegation signatures before acceptance.",),
                )

    delegation_groups: dict[tuple[str, str], list[InvestigationNode]] = {}
    for node in nodes:
        if node.delegation_id:
            delegation_groups.setdefault((node.trace_id, node.delegation_id), []).append(node)
    for (trace_id, delegation_id), group in delegation_groups.items():
        principals = sorted({item.principal_id for item in group if item.principal_id})
        from_agents = sorted(
            {
                value
                for item in group
                if (value := _text(records[item.event_id].get("delegated_from_agent_id")))
            }
        )
        to_agents = sorted(
            {
                value
                for item in group
                if (value := _text(records[item.event_id].get("delegated_to_agent_id")))
            }
        )
        if len(principals) > 1 and not all(
            records[item.event_id].get("principal_transition_approved") is True for item in group
        ):
            _finding(
                findings,
                code="delegation_principal_drift",
                severity="high",
                title="Principal changed inside a delegation chain",
                description="Events sharing one delegation ID carry different principals without an approved transition.",
                trace_id=trace_id,
                event_ids=tuple(item.event_id for item in group),
                evidence={"delegation_id": delegation_id, "principal_ids": principals},
                remediation=("Bind the originating principal to the complete delegated task chain.",),
            )
        if len(from_agents) > 1 or len(to_agents) > 1:
            _finding(
                findings,
                code="delegation_endpoint_drift",
                severity="critical",
                title="Delegation endpoints changed in flight",
                description="The sender or receiver identity changed while the delegation ID remained constant.",
                trace_id=trace_id,
                event_ids=tuple(item.event_id for item in group),
                evidence={"delegation_id": delegation_id, "from_agents": from_agents, "to_agents": to_agents},
                remediation=("Treat delegation envelopes as immutable and reject endpoint changes.",),
            )

    previous_goal: dict[tuple[str, str], tuple[str, str]] = {}
    for node in nodes:
        event = records[node.event_id]
        if event.event_type == "agent.goal.integrity" and event.get("goal_integrity_valid") is False:
            _finding(
                findings,
                code="goal_integrity_failed",
                severity="critical",
                title="Bound goal integrity failed",
                description="An agent checkpoint reported that the active goal no longer matches its bound fingerprint.",
                trace_id=node.trace_id,
                event_ids=(node.event_id,),
                evidence={"goal_id": event.get("goal_id"), "agent_id": node.agent_id},
                remediation=("Re-bind the goal to trusted context and require approval for goal changes.",),
            )
        goal_id = _text(event.get("goal_id"))
        fingerprint = _text(event.get("goal_fingerprint"))
        if goal_id and fingerprint:
            key = (node.trace_id, goal_id)
            prior = previous_goal.get(key)
            if prior and prior[1] != fingerprint and event.get("goal_change_approved") is not True:
                _finding(
                    findings,
                    code="unapproved_goal_fingerprint_change",
                    severity="critical",
                    title="Goal fingerprint changed without approval",
                    description="A goal changed across the causal trace without an explicit approved transition.",
                    trace_id=node.trace_id,
                    event_ids=(prior[0], node.event_id),
                    evidence={"goal_id": goal_id, "previous_fingerprint": prior[1], "observed_fingerprint": fingerprint},
                    remediation=("Persist immutable goal fingerprints and verify them at every delegation boundary.",),
                )
            previous_goal[key] = (node.event_id, fingerprint)

        if event.event_type.startswith("agent.memory.") and event.get("memory_provenance_valid") is False:
            _finding(
                findings,
                code="memory_provenance_failed",
                severity="high",
                title="Memory provenance validation failed",
                description="A memory operation used data that could not be bound to a trusted lineage.",
                trace_id=node.trace_id,
                event_ids=(node.event_id,),
                evidence={"memory_id": event.get("memory_id"), "data_lineage_id": event.get("data_lineage_id")},
                remediation=("Require source identity and lineage validation before shared-memory writes or reads.",),
            )
        if event.event_type.startswith("agent.memory.") and event.get("memory_retention_valid") is False:
            _finding(
                findings,
                code="memory_retention_policy_failed",
                severity="high",
                title="Memory retention policy failed",
                description="A memory operation crossed its approved scope or retention boundary.",
                trace_id=node.trace_id,
                event_ids=(node.event_id,),
                evidence={"memory_id": event.get("memory_id"), "memory_scope": event.get("memory_scope"), "session_id": node.session_id},
                remediation=("Enforce per-session retention, expiry, and tenant scope before memory reuse.",),
            )
        if (
            event.event_type == "agent.memory.written"
            and event.get("memory_scope") in {"shared", "persistent"}
            and not node.data_lineage_id
        ):
            _finding(
                findings,
                code="shared_memory_lineage_missing",
                severity="high",
                title="Shared memory write lacks lineage",
                description="A shared or persistent memory write has no data-lineage identifier.",
                trace_id=node.trace_id,
                event_ids=(node.event_id,),
                evidence={"memory_id": event.get("memory_id"), "memory_scope": event.get("memory_scope")},
                remediation=("Attach immutable data-lineage identifiers to every retained memory item.",),
            )

    findings.sort(
        key=lambda item: (-_SEVERITY_ORDER[item.severity], item.trace_id, item.finding_id)
    )

    parent_by_child: dict[str, str] = {}
    for edge in causal_edges:
        parent_by_child.setdefault(edge.target_event_id, edge.source_event_id)
    paths: list[InvestigationPath] = []
    for finding in findings:
        if finding.severity not in {"critical", "high"} or not finding.event_ids:
            continue
        cursor = finding.event_ids[-1]
        chain = [cursor]
        seen = {cursor}
        while cursor in parent_by_child and len(chain) < 20:
            cursor = parent_by_child[cursor]
            if cursor in seen:
                break
            seen.add(cursor)
            chain.append(cursor)
        chain.reverse()
        paths.append(
            InvestigationPath(
                path_id=f"PATH-{len(paths) + 1:04d}",
                finding_id=finding.finding_id,
                severity=finding.severity,
                title=finding.title,
                event_ids=tuple(chain),
            )
        )

    trace_ids = sorted({node.trace_id for node in nodes})
    traces: list[dict[str, object]] = []
    for trace_id in trace_ids:
        trace_nodes = [node for node in nodes if node.trace_id == trace_id]
        trace_findings = [item for item in findings if item.trace_id == trace_id]
        traces.append(
            {
                "trace_id": trace_id,
                "fixture_id": next((item.fixture_id for item in trace_nodes if item.fixture_id), None),
                "variant": next((item.variant for item in trace_nodes if item.variant), None),
                "event_count": len(trace_nodes),
                "agent_ids": sorted({item.agent_id for item in trace_nodes if item.agent_id}),
                "delegation_ids": sorted({item.delegation_id for item in trace_nodes if item.delegation_id}),
                "finding_count": len(trace_findings),
                "highest_severity": max(
                    (item.severity for item in trace_findings),
                    key=lambda value: _SEVERITY_ORDER[value],
                    default="none",
                ),
                "max_depth": max((item.depth for item in trace_nodes), default=0),
            }
        )

    highest = max((_SEVERITY_ORDER[item.severity] for item in findings), default=0)
    status = {4: "critical", 3: "elevated", 2: "review", 1: "review", 0: "clean"}[highest]
    score = max(0, 100 - sum(_SEVERITY_WEIGHT[item.severity] for item in findings))
    return InvestigationReport(
        status=status,
        score=score,
        event_count=len(nodes),
        trace_count=len(trace_ids),
        agent_count=len({node.agent_id for node in nodes if node.agent_id}),
        delegation_count=len({node.delegation_id for node in nodes if node.delegation_id}),
        memory_count=len({node.memory_id for node in nodes if node.memory_id}),
        goal_count=len({node.goal_id for node in nodes if node.goal_id}),
        max_depth=max((node.depth for node in nodes), default=0),
        nodes=tuple(nodes),
        edges=tuple(edges),
        findings=tuple(findings),
        paths=tuple(paths),
        traces=tuple(traces),
    )


__all__ = [
    "InvariantFinding",
    "InvestigationEdge",
    "InvestigationNode",
    "InvestigationPath",
    "InvestigationReport",
    "investigate_telemetry",
]
