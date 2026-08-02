"""Offline collector contracts and safe JSON record loading."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Mapping

from agentsim.models.telemetry import NormalizedEvent
from agentsim.telemetry.normalization import normalize_records


MAX_RECORDS = 250_000
MAX_FILE_BYTES = 256 * 1024 * 1024


class TelemetryCollector(ABC):
    """Stable v1 interface for read-only exported telemetry collectors."""

    api_version = "1.0"
    name: str

    @abstractmethod
    def collect(self, path: str | Path) -> tuple[NormalizedEvent, ...]:
        raise NotImplementedError


def read_json_records(path: str | Path) -> list[Mapping[str, object]]:
    candidate = Path(path)
    if not candidate.is_file():
        raise FileNotFoundError(f"telemetry export does not exist: {candidate}")
    if candidate.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("telemetry export exceeds the 256 MiB offline limit")
    text = candidate.read_text(encoding="utf-8")
    records: list[object]
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        records = []
        for line_number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid telemetry JSONL at line {line_number}: {exc}") from exc
    else:
        if isinstance(parsed, list):
            records = parsed
        elif isinstance(parsed, Mapping):
            nested = next(
                (
                    parsed[key]
                    for key in ("records", "events", "results", "Records")
                    if isinstance(parsed.get(key), list)
                ),
                None,
            )
            records = nested if isinstance(nested, list) else [parsed]
        else:
            raise ValueError("telemetry export must contain JSON objects")
    if len(records) > MAX_RECORDS:
        raise ValueError("telemetry export exceeds the 250000-record offline limit")
    if any(not isinstance(record, Mapping) for record in records):
        raise ValueError("telemetry export records must be JSON objects")
    return list(records)  # type: ignore[return-value]


class ProfiledJsonCollector(TelemetryCollector):
    """Collector for JSON/JSONL exports using a named normalization profile."""

    def __init__(self, name: str) -> None:
        self.name = name

    def collect(self, path: str | Path) -> tuple[NormalizedEvent, ...]:
        return normalize_records(read_json_records(path), collector=self.name)
