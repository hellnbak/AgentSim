"""Campaign and action outcome models."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping


@dataclass(frozen=True)
class ActionResult:
    action_id: str
    ability_id: str
    status: str
    authorized: bool
    attempted: bool
    executed: bool
    observed: bool
    detection_status: str
    cleanup_status: str
    duration_ms: int
    output_digest: str | None = None
    error: str | None = None
    defenses: tuple[str, ...] = ()


@dataclass(frozen=True)
class CampaignRunResult:
    run_id: str
    campaign_id: str
    mode: str
    provider: str
    target_uri: str
    status: str
    actions: tuple[ActionResult, ...]
    manifest_path: Path
    timeline_path: Path
    report_path: Path
    bundle_path: Path
    summary: Mapping[str, object] = field(default_factory=dict)
