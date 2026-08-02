"""Disposable reference-agent runtime with fixed, in-memory synthetic tools."""

from __future__ import annotations

import copy
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping

from agentsim.models.agent_trace import AgentTraceEvent

from .fixtures import LabFixture, list_fixtures, run_fixture


@dataclass(frozen=True)
class ReferenceLabRun:
    run_id: str
    fixture_id: str
    passed: bool
    events: tuple[AgentTraceEvent, ...]
    synthetic_effects: tuple[Mapping[str, object], ...]
    reset_verified: bool
    safety: Mapping[str, object]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "kind": "agentsim-reference-agent-lab-run",
            "run_id": self.run_id,
            "fixture_id": self.fixture_id,
            "passed": self.passed,
            "events": [event.to_dict() for event in self.events],
            "synthetic_effects": [dict(effect) for effect in self.synthetic_effects],
            "reset_verified": self.reset_verified,
            "safety": dict(self.safety),
        }


class SyntheticToolRuntime:
    """Apply fixed dictionary changes only; never touch host resources."""

    def __init__(self) -> None:
        self._state: dict[str, object] = {"operation_count": 0, "last_tool": None}
        self._initial = copy.deepcopy(self._state)
        self._effects: list[dict[str, object]] = []

    @property
    def effects(self) -> tuple[Mapping[str, object], ...]:
        return tuple(copy.deepcopy(self._effects))

    def invoke(self, fixture: LabFixture, variant: str) -> Mapping[str, object]:
        self._state["operation_count"] = int(self._state["operation_count"]) + 1
        self._state["last_tool"] = fixture.tool_name
        effect = {
            "effect_type": "in_memory_synthetic_tool",
            "fixture_id": fixture.fixture_id,
            "variant": variant,
            "tool_name": fixture.tool_name,
            "external_state_changed": False,
        }
        self._effects.append(effect)
        return effect

    def reset(self) -> bool:
        self._state = copy.deepcopy(self._initial)
        self._effects.clear()
        return self._state == self._initial and not self._effects


def _fixture(fixture_id: str) -> LabFixture:
    try:
        return next(item for item in list_fixtures() if item.fixture_id == fixture_id)
    except StopIteration as exc:
        raise ValueError(f"Unknown lab fixture: {fixture_id}") from exc


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _trace(
    *,
    run_id: str,
    fixture: LabFixture,
    variant: str,
    allowed: bool,
    reason: str,
    tool_effect_applied: bool,
) -> tuple[AgentTraceEvent, ...]:
    trace_id = f"{run_id}:{variant}"
    request = fixture.malicious_request if variant == "malicious" else fixture.benign_request
    mcp_authorization = fixture.tool_name.startswith("mcp.")
    audience_valid = bool(request.get("audience_valid", True)) if mcp_authorization else None
    consent_valid = bool(request.get("consent", True)) if mcp_authorization else None
    common = {
        "timestamp": _timestamp(),
        "trace_id": trace_id,
        "session_id": f"reference-session-{variant}",
        "conversation_id": f"reference-conversation-{variant}",
        "agent_id": "agentsim-reference-agent",
        "agent_instance_id": f"reference-agent-{run_id[:8]}",
        "principal_id": "synthetic-operator",
        "tool_call_id": f"{trace_id}:tool-call",
        "tool_name": fixture.tool_name,
        "tool_risk": "low" if variant == "benign" else "high",
        "policy_id": fixture.control,
        "policy_version": "1.3",
        "synthetic": True,
        "content_recorded": False,
    }
    requested_id = f"{trace_id}:requested"
    policy_id = f"{trace_id}:policy"
    requested = AgentTraceEvent(
        **common,
        event_id=requested_id,
        event_type="agent.tool.requested",
        input_trust="trusted" if variant == "benign" else "untrusted",
        taint_labels=() if variant == "benign" else (fixture.attack_class,),
        outcome="proposed",
        attributes={
            "fixture_id": fixture.fixture_id,
            "variant": variant,
            "attack_class": fixture.attack_class,
            "arguments_recorded": False,
        },
    )
    authorization = (
        AgentTraceEvent(
            **common,
            event_id=f"{trace_id}:authorization",
            event_type="mcp.authorization.checked",
            source="mcp",
            parent_event_id=requested_id,
            caused_by_event_ids=(requested_id,),
            mcp_client_id="agentsim-reference-client",
            mcp_server_id="agentsim-reference-server",
            auth_audience="agentsim-reference-server",
            auth_resource="synthetic://mcp/reference-resource",
            auth_scopes=("read", "publish") if request.get("scope_expansion") else ("read",),
            auth_audience_valid=audience_valid,
            consent_valid=consent_valid,
            policy_decision="allow" if audience_valid and consent_valid else "deny",
            outcome="validated" if audience_valid and consent_valid else "prevented",
            attributes={
                "fixture_id": fixture.fixture_id,
                "variant": variant,
                "authorization_checkpoint": True,
            },
        )
        if mcp_authorization
        else None
    )
    policy = AgentTraceEvent(
        **common,
        event_id=policy_id,
        parent_event_id=requested_id,
        caused_by_event_ids=(requested_id,),
        event_type="agent.policy.decision",
        policy_decision="allow" if allowed else "deny",
        outcome="allowed" if allowed else "prevented",
        attributes={
            "fixture_id": fixture.fixture_id,
            "variant": variant,
            "decision_reason": reason,
            "control": fixture.control,
        },
    )
    outcome = AgentTraceEvent(
        **common,
        event_id=f"{trace_id}:outcome",
        parent_event_id=policy_id,
        caused_by_event_ids=(policy_id,),
        event_type="agent.tool.completed" if allowed else "agent.tool.blocked",
        policy_decision="allow" if allowed else "deny",
        outcome="simulated" if allowed else "prevented",
        attributes={
            "fixture_id": fixture.fixture_id,
            "variant": variant,
            "tool_effect_applied": tool_effect_applied,
            "external_state_changed": False,
            "result_recorded": False,
        },
    )
    events = [requested]
    if authorization is not None:
        events.append(authorization)
    events.extend((policy, outcome))
    return tuple(events)


def run_reference_fixture(fixture_id: str) -> ReferenceLabRun:
    """Run malicious and benign twins through the instrumented reference policy boundary."""

    fixture = _fixture(fixture_id)
    baseline = run_fixture(fixture_id)
    runtime = SyntheticToolRuntime()
    run_id = uuid.uuid4().hex
    events: list[AgentTraceEvent] = []
    effects: list[Mapping[str, object]] = []
    for event in baseline.events:
        variant = str(event["variant"])
        allowed = event["policy_decision"] == "allow"
        effect_applied = False
        if allowed:
            effects.append(runtime.invoke(fixture, variant))
            effect_applied = True
        events.extend(
            _trace(
                run_id=run_id,
                fixture=fixture,
                variant=variant,
                allowed=allowed,
                reason=str(event["reason"]),
                tool_effect_applied=effect_applied,
            )
        )
    reset_verified = runtime.reset()
    return ReferenceLabRun(
        run_id,
        fixture_id,
        baseline.passed and reset_verified,
        tuple(events),
        tuple(effects),
        reset_verified,
        {
            "execution_mode": "disposable_reference_agent",
            "network_opened": False,
            "process_started": False,
            "filesystem_changed": False,
            "external_tool_executed": False,
            "credential_used": False,
            "content_recorded": False,
            "synthetic_tool_effects": len(effects),
            "control": fixture.control,
        },
    )


def run_reference_suite() -> tuple[ReferenceLabRun, ...]:
    return tuple(run_reference_fixture(fixture.fixture_id) for fixture in list_fixtures())
