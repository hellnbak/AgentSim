"""Portable campaign evidence bundles."""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Mapping


def write_evidence_bundle(
    output_path: str | Path,
    *,
    manifest_path: str | Path,
    timeline_path: str | Path,
    report_path: str | Path,
    artifacts: Mapping[str, str | Path] | None = None,
) -> Path:
    selected = Path(output_path)
    with zipfile.ZipFile(selected, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.write(manifest_path, arcname="run-manifest.json")
        bundle.write(timeline_path, arcname="action-lifecycle.jsonl")
        bundle.write(report_path, arcname="campaign-report.json")
        for archive_name, artifact_path in sorted((artifacts or {}).items()):
            artifact = Path(artifact_path)
            if artifact.is_file():
                bundle.write(artifact, arcname=archive_name)
    return selected
