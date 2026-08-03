# AGENTSIM STATUS: SAMPLE - TUNING AND HUMAN REVIEW REQUIRED
def _value(event, field):
    value = event
    for part in field.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def rule(event):
    return all((
        _value(event, "event_type") == 'agent.tool.requested',
        _value(event, "input_trust") == 'untrusted',
        _value(event, "tool_risk") == 'high',
    ))


def title(event):
    return "Untrusted input reached a high-risk tool request"


def dedup(event):
    return str(event.get("trace_id", "missing-trace"))
