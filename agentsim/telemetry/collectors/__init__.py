"""Built-in offline telemetry collectors."""

from __future__ import annotations

from .base import ProfiledJsonCollector, TelemetryCollector


COLLECTOR_NAMES = (
    "jsonl",
    "otel",
    "otel_genai",
    "sysmon",
    "auditd",
    "cloudtrail",
    "crowdstrike",
    "elastic",
    "sentinel",
    "logscale",
    "panther",
    "graylog",
    "splunk",
    "agent_runtime",
    "mcp_audit",
)


def collector_for(name: str) -> TelemetryCollector:
    selected = name.strip().lower().replace("-", "_")
    if selected not in COLLECTOR_NAMES:
        raise ValueError(f"unsupported telemetry collector: {name}")
    return ProfiledJsonCollector(selected)


__all__ = ["COLLECTOR_NAMES", "TelemetryCollector", "collector_for"]
