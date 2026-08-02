"""Normalized defensive telemetry models used by the v1 validation engine."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Mapping


@dataclass(frozen=True)
class NormalizedEvent:
    """A redacted, vendor-neutral event with canonical defensive fields."""

    timestamp: str
    source: str
    event_type: str
    fields: Mapping[str, object]
    available_fields: tuple[str, ...]
    collector: str
    synthetic: bool = False
    source_record_id: str | None = None
    metadata: Mapping[str, object] = field(default_factory=dict)

    def get(self, field_name: str, default: object = None) -> object:
        if field_name == "timestamp":
            return self.timestamp
        if field_name == "source":
            return self.source
        if field_name == "event_type":
            return self.event_type
        return self.fields.get(field_name, default)

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["schema_version"] = "1.0"
        return value


@dataclass(frozen=True)
class CorrelatedAction:
    """Lifecycle ground truth joined to a bounded set of normalized events."""

    run_id: str
    action_id: str
    ability_id: str
    expected_sources: tuple[str, ...]
    event_indexes: tuple[int, ...]
    start_timestamp: str
    end_timestamp: str
    status: str
