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
        _value(event, "event_type") == 'agent.delegation.accepted',
        _value(event, "identity_binding_valid") == False,
    ))


def title(event):
    return "Delegated agent identity binding failed"


def dedup(event):
    return str(event.get("trace_id", "missing-trace"))
