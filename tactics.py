"""Legacy endpoint catalog view derived from reviewed v1 ability content.

New code should use :mod:`agentsim.content`. This compatibility module keeps
the v0.3 random telemetry simulator working while removing its duplicate,
hard-coded executable command dictionary.
"""

from __future__ import annotations

import shlex
import subprocess

from agentsim.content import load_ability_registry
from agentsim.content.catalog import resolve_command_sequence


_ABILITY_LAYOUT = (
    ("Phase 1: Host Discovery", "endpoint.discovery.system-information", "T1082 - System Information Discovery"),
    ("Phase 1: Host Discovery", "endpoint.discovery.current-user", "T1033 - System Owner/User Discovery"),
    ("Phase 1: Host Discovery", "endpoint.discovery.local-accounts", "T1087.001 - Account Discovery: Local Account"),
    ("Phase 1: Host Discovery", "endpoint.discovery.processes", "T1057 - Process Discovery"),
    ("Phase 2: Privilege and Network Discovery", "endpoint.discovery.local-groups", "T1069.001 - Permission Groups Discovery: Local Groups"),
    ("Phase 2: Privilege and Network Discovery", "endpoint.discovery.network-connections", "T1049 - System Network Connections Discovery"),
    ("Phase 2: Privilege and Network Discovery", "endpoint.discovery.network-configuration", "T1016 - System Network Configuration Discovery"),
    ("Phase 3: Cloud Service Discovery", "cloud.discovery.services", "T1526 - Cloud Service Discovery"),
)


def _legacy_command(platform_name: str, argv: tuple[str, ...]) -> tuple[str, str]:
    if platform_name == "Windows":
        executable = argv[0].lower()
        if executable == "powershell.exe":
            return "powershell", argv[-1]
        if executable == "cmd.exe":
            return "cmd", argv[-1]
        return "cmd", subprocess.list2cmdline(list(argv))
    return "bash", shlex.join(argv)


def _build_legacy_phases() -> dict[str, dict[str, dict[str, dict[str, list[str]]]]]:
    abilities = load_ability_registry()
    phases: dict[str, dict[str, dict[str, dict[str, list[str]]]]] = {}
    for phase, ability_id, tactic in _ABILITY_LAYOUT:
        ability = abilities[ability_id]
        for platform_name in ability.platforms:
            shell_commands: dict[str, list[str]] = {}
            for argv in resolve_command_sequence(ability.execution.command_ref, platform_name):
                shell, command = _legacy_command(platform_name, argv)
                shell_commands.setdefault(shell, []).append(command)
            phases.setdefault(phase, {}).setdefault(platform_name, {})[tactic] = shell_commands
    return phases


SIMULATION_PHASES = _build_legacy_phases()


# Compatibility-only wrong-platform probes used by the legacy random simulator.
LINUX_HALLUCINATIONS = ["ls -la", "cat /etc/passwd", "ifconfig", "uname -a", "ps aux"]
WINDOWS_HALLUCINATIONS = [
    "dir C:\\Windows\\System32",
    "ipconfig /all",
    "net user administrator",
    "tasklist",
]
