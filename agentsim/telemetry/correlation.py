"""Correlate lifecycle-v3 ground truth to normalized telemetry."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Mapping, Sequence

from agentsim.models.telemetry import CorrelatedAction, NormalizedEvent


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def correlate_lifecycle(
    lifecycle_events: Sequence[Mapping[str, object]],
    telemetry: Sequence[NormalizedEvent],
    *,
    tolerance_seconds: int = 120,
) -> tuple[CorrelatedAction, ...]:
    if not 0 <= tolerance_seconds <= 3600:
        raise ValueError("tolerance_seconds must be between 0 and 3600")
    by_action: dict[str, list[Mapping[str, object]]] = {}
    for event in lifecycle_events:
        action_id = event.get("action_id")
        if isinstance(action_id, str):
            by_action.setdefault(action_id, []).append(event)
    results: list[CorrelatedAction] = []
    for action_id, events in by_action.items():
        ordered = sorted(events, key=lambda event: int(event.get("sequence", 0)))
        start = _time(str(ordered[0]["timestamp"]))
        end = _time(str(ordered[-1]["timestamp"]))
        expected = tuple(
            sorted(
                {
                    str(source)
                    for event in ordered
                    for source in event.get("expected_telemetry", [])
                }
            )
        )
        ability_id = str(ordered[0].get("ability_id", "unknown"))
        run_id = str(ordered[0].get("run_id", "unknown"))
        expected_folded = {source.casefold() for source in expected}
        lower = start - timedelta(seconds=tolerance_seconds)
        upper = end + timedelta(seconds=tolerance_seconds)
        indexes = tuple(
            index
            for index, item in enumerate(telemetry)
            if lower <= _time(item.timestamp) <= upper
            and (
                not expected
                or item.source.casefold() in expected_folded
                or item.event_type.casefold() in expected_folded
                or item.get("ability_id") == ability_id
            )
            and (item.get("run_id") in (None, run_id))
        )
        results.append(
            CorrelatedAction(
                run_id=run_id,
                action_id=action_id,
                ability_id=ability_id,
                expected_sources=expected,
                event_indexes=indexes,
                start_timestamp=ordered[0]["timestamp"],
                end_timestamp=ordered[-1]["timestamp"],
                status=str(ordered[-1].get("lifecycle_state", "unknown")),
            )
        )
    return tuple(results)
