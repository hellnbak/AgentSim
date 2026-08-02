"""Gated execution providers."""

from .base import ExecutionProvider, ProviderResult
from .docker import DockerExecutionProvider
from .local import LocalExecutionProvider
from .simulate import SimulationExecutionProvider


def provider_for_name(name: str) -> ExecutionProvider:
    providers: dict[str, ExecutionProvider] = {
        "simulate": SimulationExecutionProvider(),
        "local": LocalExecutionProvider(),
        "docker": DockerExecutionProvider(),
    }
    try:
        return providers[name]
    except KeyError as exc:
        raise ValueError(f"unsupported execution provider: {name}") from exc


__all__ = [
    "ExecutionProvider",
    "ProviderResult",
    "SimulationExecutionProvider",
    "LocalExecutionProvider",
    "DockerExecutionProvider",
    "provider_for_name",
]
