"""Named-container lab provider using static reviewed argv sequences."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import time

from agentsim.content.catalog import resolve_command_sequence
from agentsim.models.ability import AbilityDefinition
from agentsim.models.target import TargetProfile
from agentsim.safety.resource_limits import RunLimits

from .base import ExecutionProvider, ProviderResult


class DockerExecutionProvider(ExecutionProvider):
    name = "docker"

    def prepare(self, ability: AbilityDefinition, target: TargetProfile) -> None:
        if target.target_type != "container":
            raise ValueError("docker provider requires an explicit docker:// target")
        if "Linux" not in ability.platforms:
            raise ValueError("docker provider requires Linux ability support")
        if shutil.which("docker") is None:
            raise RuntimeError("docker executable is not available")
        resolve_command_sequence(ability.execution.command_ref, "Linux")

    def _run_ref(
        self,
        command_ref: str,
        target: TargetProfile,
        timeout_seconds: int,
        limits: RunLimits,
        *,
        cleanup: bool = False,
    ) -> ProviderResult:
        sequence = resolve_command_sequence(command_ref, "Linux")
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
                    ["docker", "exec", "--", target.identifier, *argv],
                    capture_output=True,
                    timeout=remaining,
                    check=False,
                )
                return_codes.append(result.returncode)
                output.extend(result.stdout or b"")
                output.extend(result.stderr or b"")
            succeeded = all(code == 0 for code in return_codes)
            return ProviderResult(
                status="executed" if succeeded else "failed",
                attempted=attempted,
                executed=attempted,
                return_codes=tuple(return_codes),
                output_digest=hashlib.sha256(output).hexdigest(),
                output_bytes=len(output),
                error=None if succeeded else "one or more container commands returned a non-zero status",
            )
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
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
            target,
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
            target,
            ability.execution.timeout_seconds,
            limits,
            cleanup=True,
        )
