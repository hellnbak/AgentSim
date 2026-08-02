"""Localhost-only execution of static reviewed argv sequences."""

from __future__ import annotations

import hashlib
import platform
import subprocess
import time

from agentsim.content.catalog import resolve_command_sequence
from agentsim.models.ability import AbilityDefinition
from agentsim.models.target import TargetProfile
from agentsim.safety.resource_limits import RunLimits

from .base import ExecutionProvider, ProviderResult


def host_platform_name() -> str:
    observed = platform.system()
    if observed == "Darwin":
        return "macOS"
    if observed in {"Windows", "Linux"}:
        return observed
    raise RuntimeError(f"unsupported local execution platform: {observed or 'unknown'}")


class LocalExecutionProvider(ExecutionProvider):
    name = "local"

    def prepare(self, ability: AbilityDefinition, target: TargetProfile) -> None:
        if target.target_type != "localhost":
            raise ValueError("local provider requires an explicit localhost:// target")
        platform_name = host_platform_name()
        if platform_name not in ability.platforms:
            raise ValueError(f"ability does not support local platform: {platform_name}")
        resolve_command_sequence(ability.execution.command_ref, platform_name)

    def _run_ref(
        self,
        command_ref: str,
        platform_name: str,
        timeout_seconds: int,
        limits: RunLimits,
        *,
        cleanup: bool = False,
    ) -> ProviderResult:
        sequence = resolve_command_sequence(command_ref, platform_name)
        deadline = time.monotonic() + timeout_seconds
        output = bytearray()
        return_codes: list[int] = []
        attempted = False
        try:
            for argv in sequence:
                if limits.cancelled() and not cleanup:
                    raise RuntimeError("run cancelled by kill switch")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout_seconds)
                limits.before_process(cleanup=cleanup)
                attempted = True
                result = subprocess.run(
                    list(argv),
                    capture_output=True,
                    timeout=remaining,
                    check=False,
                )
                return_codes.append(result.returncode)
                output.extend(result.stdout or b"")
                output.extend(result.stderr or b"")
            digest = hashlib.sha256(output).hexdigest()
            succeeded = all(code == 0 for code in return_codes)
            return ProviderResult(
                status="executed" if succeeded else "failed",
                attempted=attempted,
                executed=attempted,
                return_codes=tuple(return_codes),
                output_digest=digest,
                output_bytes=len(output),
                error=None if succeeded else "one or more reviewed commands returned a non-zero status",
            )
        except subprocess.TimeoutExpired:
            return ProviderResult(
                status="failed",
                attempted=attempted,
                executed=attempted,
                return_codes=tuple(return_codes),
                error=f"reviewed command sequence exceeded {timeout_seconds} seconds",
            )
        except (OSError, RuntimeError) as exc:
            return ProviderResult(
                status="failed",
                attempted=attempted,
                executed=attempted,
                return_codes=tuple(return_codes),
                error=str(exc),
            )

    def execute(
        self,
        ability: AbilityDefinition,
        target: TargetProfile,
        limits: RunLimits,
    ) -> ProviderResult:
        self.prepare(ability, target)
        return self._run_ref(
            ability.execution.command_ref,
            host_platform_name(),
            ability.execution.timeout_seconds,
            limits,
        )

    def cleanup(
        self,
        ability: AbilityDefinition,
        target: TargetProfile,
        limits: RunLimits,
    ) -> ProviderResult:
        if not ability.execution.cleanup_ref:
            return ProviderResult(status="verified_noop", attempted=False, executed=False)
        self.prepare(ability, target)
        return self._run_ref(
            ability.execution.cleanup_ref,
            host_platform_name(),
            ability.execution.timeout_seconds,
            limits,
            cleanup=True,
        )
