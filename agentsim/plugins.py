"""Stable v1 plugin discovery and interface contracts."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata
from typing import Iterable, Mapping, Protocol, runtime_checkable

from agentsim.models.telemetry import NormalizedEvent


PLUGIN_API_VERSION = "1.0"
ENTRY_POINT_GROUPS = {
    "collector": "agentsim.collectors",
    "external_executor": "agentsim.external_executors",
    "renderer": "agentsim.detection_renderers",
    "telemetry_connector": "agentsim.telemetry_connectors",
}


@runtime_checkable
class CollectorPlugin(Protocol):
    api_version: str

    def collect(self, source: str) -> Iterable[NormalizedEvent]: ...


@runtime_checkable
class ExternalExecutorPlugin(Protocol):
    api_version: str

    def execute(self, plan: Mapping[str, object]) -> Mapping[str, object]: ...


@runtime_checkable
class DetectionRendererPlugin(Protocol):
    api_version: str

    def render(self, candidate: Mapping[str, object]) -> str: ...


@runtime_checkable
class TelemetryConnectorPlugin(Protocol):
    api_version: str

    def build_plan(self, specification: Mapping[str, object]) -> Mapping[str, object]: ...

    def execute(self, plan: Mapping[str, object]) -> Iterable[NormalizedEvent]: ...


@dataclass(frozen=True)
class PluginDescriptor:
    name: str
    kind: str
    module: str
    distribution: str | None
    distribution_version: str | None

    def to_dict(self) -> dict[str, object]:
        return self.__dict__.copy()


def discover_plugins() -> tuple[PluginDescriptor, ...]:
    """Inspect entry-point metadata without importing third-party plugin code."""

    entries = metadata.entry_points()
    descriptors: list[PluginDescriptor] = []
    for kind, group in ENTRY_POINT_GROUPS.items():
        selected = entries.select(group=group) if hasattr(entries, "select") else entries.get(group, ())
        for entry in selected:
            distribution = getattr(entry, "dist", None)
            descriptors.append(
                PluginDescriptor(
                    entry.name,
                    kind,
                    entry.value,
                    distribution.metadata.get("Name") if distribution else None,
                    distribution.version if distribution else None,
                )
            )
    return tuple(sorted(descriptors, key=lambda item: (item.kind, item.name)))


def load_plugin(kind: str, name: str) -> object:
    """Explicitly import one selected plugin and enforce the stable API version."""

    try:
        group = ENTRY_POINT_GROUPS[kind]
    except KeyError as exc:
        raise ValueError(f"Unknown plugin kind: {kind}") from exc
    entries = metadata.entry_points()
    selected = entries.select(group=group, name=name) if hasattr(entries, "select") else [
        entry for entry in entries.get(group, ()) if entry.name == name
    ]
    values = tuple(selected)
    if len(values) != 1:
        raise ValueError(f"Expected one {kind} plugin named {name}; found {len(values)}")
    plugin = values[0].load()
    instance = plugin() if isinstance(plugin, type) else plugin
    if getattr(instance, "api_version", None) != PLUGIN_API_VERSION:
        raise ValueError(f"Plugin {name} does not support AgentSim plugin API {PLUGIN_API_VERSION}")
    return instance
