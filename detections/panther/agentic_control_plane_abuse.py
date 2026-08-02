"""Panther rule for high-confidence AgentSim control-plane failures."""


def _attributes(event):
    value = event.get("attributes")
    return value if isinstance(value, dict) else {}


def signal_type(event):
    attributes = _attributes(event)
    event_type = event.get("event_type")
    if (
        event_type == "agent.model.fallback"
        and attributes.get("safety_profile_changed") is True
        and attributes.get("policy_binding_valid") is False
    ):
        return "model_safety_downgrade"
    if (
        event_type == "agent.policy.decision"
        and event.get("policy_decision") == "allow"
        and attributes.get("policy_scope") == "executor"
        and attributes.get("intent_equivalent") is True
        and attributes.get("policy_version_match") is False
    ):
        return "planner_executor_policy_gap"
    if (
        event_type == "agent.approval.reused"
        and attributes.get("action_fingerprint_match") is False
    ):
        return "approval_replay"
    if (
        event_type == "agent.authorization.context_changed"
        and attributes.get("tenant_changed") is True
        and attributes.get("tenant_binding_valid") is False
    ):
        return "cross_tenant_context_confusion"
    if (
        event_type == "agent.tool.requested"
        and attributes.get("egress_capable") is True
        and attributes.get("composite_risk") == "high"
    ):
        return "tool_chain_capability_escalation"
    if (
        event_type == "agent.registry.entry.changed"
        and attributes.get("capability_expansion") is True
        and attributes.get("signature_valid") is False
    ):
        return "agent_registry_poisoning"
    return None


def rule(event):
    """Match direct control-plane security invariant failures."""

    return signal_type(event) is not None


def dedup(event):
    return str(event.get("trace_id") or event.get("session_id") or "unknown-trace")


def title(event):
    signal = signal_type(event) or "control_plane_failure"
    return f"Agent control-plane signal {signal}"


def alert_context(event):
    return {
        "signal_type": signal_type(event),
        "trace_id": event.get("trace_id"),
        "sequence": event.get("sequence"),
        "session_id": event.get("session_id"),
        "agent_id": event.get("agent_id"),
        "principal_id": event.get("principal_id"),
        "policy_id": event.get("policy_id"),
        "policy_version": event.get("policy_version"),
        "approval_id": event.get("approval_id"),
        "delegation_id": event.get("delegation_id"),
        "tool_name": event.get("tool_name"),
    }
