"""Ground-truth action lifecycle schema v3 models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Mapping


SCHEMA_VERSION = "3.0"
LIFECYCLE_STATES = (
    "planned",
    "authorized",
    "denied",
    "prepared",
    "attempted",
    "simulated",
    "executed",
    "prevented",
    "observed",
    "detected",
    "missed",
    "detection_pending",
    "cleanup_started",
    "cleaned",
    "cleanup_failed",
    "verified",
    "cancelled",
    "failed",
)


@dataclass(frozen=True)
class ActionLifecycleEvent:
    """One immutable transition in an ability action lifecycle."""

    timestamp: str
    event_id: str
    run_id: str
    campaign_id: str
    ability_id: str
    action_id: str
    sequence: int
    lifecycle_state: str
    provider: str
    target_uri: str
    authorization_id: str
    outcome: str
    message: str
    parent_event_id: str | None = None
    attack_mappings: tuple[str, ...] = ()
    atlas_mappings: tuple[str, ...] = ()
    expected_telemetry: tuple[str, ...] = ()
    attributes: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.lifecycle_state not in LIFECYCLE_STATES:
            raise ValueError(f"unsupported lifecycle state: {self.lifecycle_state}")

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["schema_version"] = SCHEMA_VERSION
        return value
