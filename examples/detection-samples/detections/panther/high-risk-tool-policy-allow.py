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
        _value(event, "event_type") == 'agent.policy.decision',
        _value(event, "tool_risk") == 'high',
        _value(event, "policy_decision") == 'allow',
    ))


def title(event):
    return "High-risk agent tool request received an allow decision"


def dedup(event):
    return str(event.get("trace_id", "missing-trace"))
