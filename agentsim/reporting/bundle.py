"""Portable campaign evidence bundles."""

from __future__ import annotations

import zipfile
from pathlib import Path


def write_evidence_bundle(
    output_path: str | Path,
    *,
    manifest_path: str | Path,
    timeline_path: str | Path,
    report_path: str | Path,
) -> Path:
    selected = Path(output_path)
    with zipfile.ZipFile(selected, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.write(manifest_path, arcname="run-manifest.json")
        bundle.write(timeline_path, arcname="action-lifecycle.jsonl")
        bundle.write(report_path, arcname="campaign-report.json")
    return selected
