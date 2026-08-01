"""Panther rule for a burst of distinct AgentSim-style discovery commands."""

import re


PYTHON_PARENTS = {
    "py.exe",
    "python",
    "python.exe",
    "python3",
    "python3.exe",
    "pythonw.exe",
}

DISCOVERY_FAMILIES = (
    (
        "system",
        re.compile(
            r"\b(systeminfo|hostname|uname\s+-a|sw_vers|system_profiler)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "account",
        re.compile(
            r"\b(whoami|net\s+user|get-localuser|getent\s+passwd)\b"
            r"|cat\s+/etc/passwd|dscl\s+\.\s+list\s+/users",
            re.IGNORECASE,
        ),
    ),
    (
        "process",
        re.compile(
            r"\b(tasklist|get-process|ps\s+aux)\b|wmic\s+process|top\s+-(bn|l)",
            re.IGNORECASE,
        ),
    ),
    (
        "groups",
        re.compile(
            r"whoami\s+/groups|net\s+localgroup|get-localgroup|\bgroups\b"
            r"|getent\s+group|dscl\s+\.\s+list\s+/groups",
            re.IGNORECASE,
        ),
    ),
    (
        "connections",
        re.compile(
            r"\b(netstat|get-nettcpconnection)\b|ss\s+-tulpn|lsof\s+-np",
            re.IGNORECASE,
        ),
    ),
    (
        "network_config",
        re.compile(
            r"\b(ipconfig|ifconfig|networksetup)\b|ip\s+address\s+show"
            r"|arp\s+-a|get-netadapter|get-netipconfiguration",
            re.IGNORECASE,
        ),
    ),
    (
        "cloud",
        re.compile(
            r"aws\s+(sts|ec2)|az\s+resource\s+list|gcloud\s+services\s+list",
            re.IGNORECASE,
        ),
    ),
)


def _event_value(event, *field_names):
    for field_name in field_names:
        value = event.get(field_name)
        if value not in (None, ""):
            return str(value)
    return ""


def _basename(value):
    return value.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _discovery_family(command_line):
    for family, pattern in DISCOVERY_FAMILIES:
        if pattern.search(command_line):
            return family
    return None


def rule(event):
    """Match discovery commands whose immediate parent is Python."""

    parent = _event_value(event, "ParentBaseFileName", "ParentImageFileName")
    command_line = _event_value(event, "CommandLine")
    return _basename(parent) in PYTHON_PARENTS and _discovery_family(command_line) is not None


def dedup(event):
    """Group commands from one parent process on one Falcon endpoint."""

    endpoint = _event_value(event, "aid", "ComputerName") or "unknown-endpoint"
    parent_pid = _event_value(event, "ParentProcessId", "ContextProcessId")
    return f"{endpoint}:{parent_pid or 'unknown-parent'}"


def unique(event):
    """Count distinct discovery families toward the YAML threshold."""

    command_line = _event_value(event, "CommandLine")
    return _discovery_family(command_line) or "unknown"


def title(event):
    host = _event_value(event, "ComputerName", "aid") or "unknown endpoint"
    return f"High-velocity discovery burst on {host}"


def alert_context(event):
    return {
        "endpoint": _event_value(event, "ComputerName", "aid"),
        "parent": _event_value(event, "ParentBaseFileName", "ParentImageFileName"),
        "parent_process_id": _event_value(
            event, "ParentProcessId", "ContextProcessId"
        ),
        "command_line": _event_value(event, "CommandLine"),
        "discovery_family": unique(event),
    }
