"""Built-in offline telemetry collectors."""

from __future__ import annotations

from .base import ProfiledJsonCollector, TelemetryCollector


COLLECTOR_NAMES = (
    "jsonl",
    "otel",
    "sysmon",
    "auditd",
    "cloudtrail",
    "crowdstrike",
    "splunk",
    "agent_runtime",
)


def collector_for(name: str) -> TelemetryCollector:
    selected = name.strip().lower().replace("-", "_")
    if selected not in COLLECTOR_NAMES:
        raise ValueError(f"unsupported telemetry collector: {name}")
    return ProfiledJsonCollector(selected)


__all__ = ["COLLECTOR_NAMES", "TelemetryCollector", "collector_for"]
