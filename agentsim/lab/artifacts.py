"""Reviewed, non-executing references to artifacts inside an isolated lab root."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from agentsim.content.provenance import PackProvenance, parse_provenance


ARTIFACT_REFERENCE_SCHEMA_VERSION = "1.0"
_MAX_REFERENCE_BYTES = 128 * 1024
_MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
_ARTIFACT_TYPES = {"archive", "data", "document", "executable", "script"}
_ARTIFACT_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_TOP_FIELDS = {
    "schema_version",
    "kind",
    "artifact_id",
    "local_path",
    "sha256",
    "size_bytes",
    "media_type",
    "artifact_type",
    "platforms",
    "purpose",
    "provenance",
    "controls",
    "integrity",
}
_CONTROL_FIELDS = {
    "lab_only",
    "production_allowed",
    "network_access",
    "execution_allowed",
    "ephemeral_container_required",
    "cleanup_required",
    "max_runtime_seconds",
    "max_memory_mb",
}


def artifact_reference_digest(value: Mapping[str, object]) -> str:
    selected = {key: item for key, item in value.items() if key != "integrity"}
    canonical = json.dumps(selected, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _text(value: object, field: str, limit: int = 512) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"artifact reference {field} must be a non-empty string")
    if len(value) > limit:
        raise ValueError(f"artifact reference {field} exceeds {limit} characters")
    return value


def _positive_int(value: object, field: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ValueError(f"artifact reference {field} must be between 1 and {maximum}")
    return value


@dataclass(frozen=True)
class LabArtifactReference:
    artifact_id: str
    local_path: str
    sha256: str
    size_bytes: int
    media_type: str
    artifact_type: str
    platforms: tuple[str, ...]
    purpose: str
    provenance: PackProvenance
    max_runtime_seconds: int
    max_memory_mb: int
    reference_digest: str

    def to_dict(self) -> dict[str, object]:
        value = {
            "schema_version": ARTIFACT_REFERENCE_SCHEMA_VERSION,
            "kind": "lab-artifact-reference",
            "artifact_id": self.artifact_id,
            "local_path": self.local_path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "media_type": self.media_type,
            "artifact_type": self.artifact_type,
            "platforms": list(self.platforms),
            "purpose": self.purpose,
            "provenance": self.provenance.to_dict(),
            "controls": {
                "lab_only": True,
                "production_allowed": False,
                "network_access": "denied",
                "execution_allowed": False,
                "ephemeral_container_required": True,
                "cleanup_required": True,
                "max_runtime_seconds": self.max_runtime_seconds,
                "max_memory_mb": self.max_memory_mb,
            },
        }
        value["integrity"] = {
            "algorithm": "sha256",
            "digest": artifact_reference_digest(value),
        }
        return value


@dataclass(frozen=True)
class ArtifactReviewFinding:
    severity: str
    code: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"severity": self.severity, "code": self.code, "message": self.message}


@dataclass(frozen=True)
class LabArtifactReview:
    reference: LabArtifactReference | None
    artifact_path: str | None
    observed_sha256: str | None
    observed_size_bytes: int | None
    findings: tuple[ArtifactReviewFinding, ...]

    @property
    def verdict(self) -> str:
        if any(finding.severity == "block" for finding in self.findings):
            return "blocked"
        if any(finding.severity == "review" for finding in self.findings):
            return "review"
        return "approved"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": ARTIFACT_REFERENCE_SCHEMA_VERSION,
            "kind": "lab-artifact-review",
            "verdict": self.verdict,
            "artifact_id": self.reference.artifact_id if self.reference else None,
            "artifact_type": self.reference.artifact_type if self.reference else None,
            "artifact_path": self.artifact_path,
            "expected_sha256": self.reference.sha256 if self.reference else None,
            "observed_sha256": self.observed_sha256,
            "expected_size_bytes": self.reference.size_bytes if self.reference else None,
            "observed_size_bytes": self.observed_size_bytes,
            "findings": [finding.to_dict() for finding in self.findings],
            "controls": {
                "lab_only": True,
                "production_allowed": False,
                "network_access": "denied",
                "execution_allowed": False,
                "artifact_content_returned": False,
            },
        }


def parse_lab_artifact_reference(value: object) -> LabArtifactReference:
    if not isinstance(value, Mapping):
        raise ValueError("lab artifact reference must be an object")
    unknown = sorted(set(value) - _TOP_FIELDS)
    if unknown:
        raise ValueError(f"lab artifact reference contains unsupported fields: {', '.join(unknown)}")
    if value.get("schema_version") != ARTIFACT_REFERENCE_SCHEMA_VERSION or value.get("kind") != "lab-artifact-reference":
        raise ValueError("lab artifact reference must use schema_version 1.0")
    artifact_id = _text(value.get("artifact_id"), "artifact_id", 128)
    if not _ARTIFACT_ID.fullmatch(artifact_id):
        raise ValueError("artifact reference artifact_id has an invalid format")
    local_path = _text(value.get("local_path"), "local_path")
    path = Path(local_path)
    if (
        path.is_absolute()
        or local_path.startswith("~")
        or ".." in path.parts
        or "\\" in local_path
        or ":" in local_path
        or any(part in {"", ".", ".."} for part in local_path.split("/"))
    ):
        raise ValueError("artifact reference local_path must remain relative to the lab root")
    sha256 = _text(value.get("sha256"), "sha256", 64).lower()
    if not _SHA256.fullmatch(sha256):
        raise ValueError("artifact reference sha256 must be a lowercase SHA-256 digest")
    size_bytes = _positive_int(value.get("size_bytes"), "size_bytes", _MAX_ARTIFACT_BYTES)
    media_type = _text(value.get("media_type"), "media_type", 128)
    if "/" not in media_type or any(character.isspace() for character in media_type):
        raise ValueError("artifact reference media_type must be a MIME type")
    artifact_type = _text(value.get("artifact_type"), "artifact_type", 32)
    if artifact_type not in _ARTIFACT_TYPES:
        raise ValueError("artifact reference artifact_type is unsupported")
    platforms_value = value.get("platforms")
    if (
        not isinstance(platforms_value, Sequence)
        or isinstance(platforms_value, (str, bytes, bytearray))
        or not platforms_value
        or len(platforms_value) > 10
    ):
        raise ValueError("artifact reference platforms must contain 1 to 10 values")
    platforms = tuple(_text(item, "platforms[]", 64) for item in platforms_value)
    controls = value.get("controls")
    if not isinstance(controls, Mapping):
        raise ValueError("artifact reference controls must be an object")
    unknown_controls = sorted(set(controls) - _CONTROL_FIELDS)
    if unknown_controls:
        raise ValueError(
            f"artifact reference controls contain unsupported fields: {', '.join(unknown_controls)}"
        )
    required_controls = {
        "lab_only": True,
        "production_allowed": False,
        "network_access": "denied",
        "execution_allowed": False,
        "ephemeral_container_required": True,
        "cleanup_required": True,
    }
    for field, expected in required_controls.items():
        if controls.get(field) != expected:
            raise ValueError(f"artifact reference controls.{field} must be {expected!r}")
    max_runtime = _positive_int(
        controls.get("max_runtime_seconds"), "controls.max_runtime_seconds", 600
    )
    max_memory = _positive_int(controls.get("max_memory_mb"), "controls.max_memory_mb", 4096)
    integrity = value.get("integrity")
    if not isinstance(integrity, Mapping) or set(integrity) - {"algorithm", "digest"}:
        raise ValueError("artifact reference integrity must contain only algorithm and digest")
    expected_digest = integrity.get("digest")
    if integrity.get("algorithm") != "sha256" or not isinstance(expected_digest, str) or not _SHA256.fullmatch(expected_digest):
        raise ValueError("artifact reference integrity must use a lowercase SHA-256 digest")
    observed_digest = artifact_reference_digest(value)
    if observed_digest != expected_digest:
        raise ValueError("artifact reference integrity checksum does not match")
    return LabArtifactReference(
        artifact_id,
        local_path,
        sha256,
        size_bytes,
        media_type,
        artifact_type,
        platforms,
        _text(value.get("purpose"), "purpose", 1000),
        parse_provenance(value.get("provenance")),
        max_runtime,
        max_memory,
        expected_digest,
    )


def _within(root: Path, selected: Path) -> bool:
    return selected == root or root in selected.parents


def review_lab_artifact(
    reference_value: Mapping[str, object],
    *,
    lab_root: str | Path,
) -> LabArtifactReview:
    """Validate a local artifact by metadata and digest without executing it."""

    findings: list[ArtifactReviewFinding] = []
    try:
        reference = parse_lab_artifact_reference(reference_value)
    except ValueError as exc:
        return LabArtifactReview(
            None,
            None,
            None,
            None,
            (ArtifactReviewFinding("block", "reference_invalid", str(exc)),),
        )
    if reference.provenance.review_status != "approved":
        findings.append(
            ArtifactReviewFinding(
                "block" if reference.provenance.review_status == "rejected" else "review",
                "artifact_review_status",
                f"artifact provenance review is {reference.provenance.review_status}",
            )
        )
    root = Path(lab_root).resolve()
    if not root.is_dir():
        findings.append(ArtifactReviewFinding("block", "lab_root_invalid", "lab root is not a directory"))
        return LabArtifactReview(reference, str(root), None, None, tuple(findings))
    selected = root.joinpath(reference.local_path)
    candidate = selected
    while candidate != root:
        if candidate.is_symlink():
            findings.append(ArtifactReviewFinding("block", "symlink_rejected", "artifact paths may not contain symbolic links"))
            return LabArtifactReview(reference, str(selected), None, None, tuple(findings))
        candidate = candidate.parent
    resolved = selected.resolve()
    if not _within(root, resolved):
        findings.append(ArtifactReviewFinding("block", "path_escape", "artifact path escapes the lab root"))
        return LabArtifactReview(reference, str(resolved), None, None, tuple(findings))
    if not resolved.is_file():
        findings.append(ArtifactReviewFinding("block", "artifact_missing", "referenced artifact is not a regular file"))
        return LabArtifactReview(reference, str(resolved), None, None, tuple(findings))
    observed_size = resolved.stat().st_size
    if observed_size > _MAX_ARTIFACT_BYTES:
        findings.append(ArtifactReviewFinding("block", "artifact_too_large", "artifact exceeds the 32 MiB review limit"))
        return LabArtifactReview(reference, str(resolved), None, observed_size, tuple(findings))
    digest = hashlib.sha256()
    bytes_read = 0
    with resolved.open("rb") as input_file:
        while True:
            chunk = input_file.read(64 * 1024)
            if not chunk:
                break
            bytes_read += len(chunk)
            if bytes_read > _MAX_ARTIFACT_BYTES:
                findings.append(ArtifactReviewFinding("block", "artifact_too_large", "artifact exceeds the 32 MiB review limit"))
                return LabArtifactReview(reference, str(resolved), None, bytes_read, tuple(findings))
            digest.update(chunk)
    observed_digest = digest.hexdigest()
    if bytes_read != observed_size:
        observed_size = bytes_read
    if observed_size != reference.size_bytes:
        findings.append(ArtifactReviewFinding("block", "size_mismatch", "artifact size does not match the reference"))
    if observed_digest != reference.sha256:
        findings.append(ArtifactReviewFinding("block", "digest_mismatch", "artifact SHA-256 does not match the reference"))
    if reference.artifact_type in {"executable", "script"}:
        findings.append(
            ArtifactReviewFinding(
                "review",
                "executable_inspection_only",
                "executable artifacts remain inspection-only; the public core cannot execute them",
            )
        )
    return LabArtifactReview(reference, str(resolved), observed_digest, observed_size, tuple(findings))


def review_lab_artifact_file(
    reference_path: str | Path,
    *,
    lab_root: str | Path | None = None,
) -> LabArtifactReview:
    selected = Path(reference_path)
    if not selected.is_file():
        raise FileNotFoundError(f"lab artifact reference does not exist: {selected}")
    if selected.stat().st_size > _MAX_REFERENCE_BYTES:
        raise ValueError("lab artifact reference exceeds the 128 KiB limit")
    value = json.loads(selected.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("lab artifact reference must be a JSON object")
    return review_lab_artifact(value, lab_root=lab_root or selected.parent)


__all__ = [
    "ARTIFACT_REFERENCE_SCHEMA_VERSION",
    "ArtifactReviewFinding",
    "LabArtifactReference",
    "LabArtifactReview",
    "artifact_reference_digest",
    "parse_lab_artifact_reference",
    "review_lab_artifact",
    "review_lab_artifact_file",
]
