"""Run-scoped cancellation and resource-limit tracking."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from .authorization import AuthorizationManifest


@dataclass
class RunLimits:
    manifest: AuthorizationManifest
    started_monotonic: float = field(default_factory=time.monotonic)
    actions_started: int = 0
    processes_started: int = 0
    cleanup_processes_started: int = 0
    _cancelled: threading.Event = field(default_factory=threading.Event)

    def cancel(self) -> None:
        self._cancelled.set()

    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def before_action(self) -> None:
        if self.cancelled():
            raise RuntimeError("run cancelled by kill switch")
        if self.actions_started >= self.manifest.max_actions:
            raise RuntimeError("authorization action limit reached")
        if time.monotonic() - self.started_monotonic >= self.manifest.max_duration_seconds:
            raise RuntimeError("authorization duration limit reached")
        self.actions_started += 1

    def before_process(self, *, cleanup: bool = False) -> None:
        if cleanup:
            if self.cleanup_processes_started >= self.manifest.max_processes:
                raise RuntimeError("authorization cleanup-process reserve reached")
            self.cleanup_processes_started += 1
            return
        if self.cancelled():
            raise RuntimeError("run cancelled by kill switch")
        if time.monotonic() - self.started_monotonic >= self.manifest.max_duration_seconds:
            raise RuntimeError("authorization duration limit reached")
        if self.processes_started >= self.manifest.max_processes:
            raise RuntimeError("authorization process limit reached")
        self.processes_started += 1
