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
        _value(event, "event_type") == 'agent.goal.integrity',
        _value(event, "goal_integrity_valid") == False,
    ))


def title(event):
    return "Agent goal integrity validation failed"


def dedup(event):
    return str(event.get("trace_id", "missing-trace"))
