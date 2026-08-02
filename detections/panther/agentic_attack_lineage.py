"""Panther primitives for AgentSim v2 trust-lineage correlation."""


ORIGIN_EVENTS = {
    "agent.input.observed",
    "agent.memory.retrieved",
    "agent.retrieval.result",
}
ACTION_EVENTS = {
    "agent.tool.requested",
    "agent.network.requested",
    "agent.delegation.requested",
}


def _attributes(event):
    value = event.get("attributes")
    return value if isinstance(value, dict) else {}


def _is_origin(event):
    return event.get("event_type") in ORIGIN_EVENTS and (
        event.get("input_trust") == "untrusted" or bool(event.get("taint_labels"))
    )


def _is_action(event):
    recursive_depth = _attributes(event).get("recursive_depth", 0)
    try:
        deep_recursion = int(recursive_depth) >= 3
    except (TypeError, ValueError):
        deep_recursion = False
    return event.get("event_type") in ACTION_EVENTS and (
        event.get("tool_risk") in {"high", "critical"} or deep_recursion
    )


def rule(event):
    """Select correlation candidates without consulting ground-truth labels."""

    return _is_origin(event) or _is_action(event)


def dedup(event):
    """Group candidate checkpoints by trace and lineage."""

    return f"{event.get('trace_id', 'unknown')}:{event.get('data_lineage_id', 'none')}"


def unique(event):
    """Require one origin and one action through a unique-value threshold of two."""

    return "untrusted_origin" if _is_origin(event) else "risky_action"


def title(event):
    return f"Agent trust-boundary sequence in {event.get('trace_id', 'unknown trace')}"


def alert_context(event):
    return {
        "trace_id": event.get("trace_id"),
        "data_lineage_id": event.get("data_lineage_id"),
        "agent_id": event.get("agent_id"),
        "session_id": event.get("session_id"),
        "event_type": event.get("event_type"),
        "sequence": event.get("sequence"),
        "tool_name": event.get("tool_name"),
    }
