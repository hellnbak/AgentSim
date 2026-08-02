"""JSONL lifecycle-v3 ground-truth persistence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping


def append_event(path: str | Path, event: Mapping[str, object]) -> None:
    with Path(path).open("a", encoding="utf-8") as output:
        output.write(json.dumps(event, sort_keys=True) + "\n")


def load_lifecycle_events(path: str | Path) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    for line_number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid lifecycle event on line {line_number}: {exc}") from exc
        if event.get("schema_version") != "3.0":
            raise ValueError(f"unsupported lifecycle schema on line {line_number}")
        events.append(event)
    return events
