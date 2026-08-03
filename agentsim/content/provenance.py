"""Strict provenance metadata for reviewable community content packs."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping, Sequence
from urllib.parse import urlparse


PROVENANCE_SCHEMA_VERSION = "1.0"
_REVISION = re.compile(r"^[a-fA-F0-9]{40,64}$")
_LICENSE = re.compile(r"^[A-Za-z0-9.+-]{2,64}$")
_TOP_FIELDS = {"schema_version", "source", "authors", "license", "created_at", "review"}
_SOURCE_FIELDS = {"repository", "revision", "path"}
_REVIEW_FIELDS = {"status", "reviewer_id", "reviewed_at", "policy_id"}


def _text(value: object, field: str, *, limit: int = 512) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"provenance.{field} must be a non-empty string")
    if len(value) > limit:
        raise ValueError(f"provenance.{field} exceeds {limit} characters")
    return value


def _time(value: object, field: str) -> str:
    selected = _text(value, field, limit=64)
    try:
        parsed = datetime.fromisoformat(selected.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"provenance.{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"provenance.{field} must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class PackProvenance:
    repository: str
    revision: str
    source_path: str
    authors: tuple[str, ...]
    license: str
    created_at: str
    review_status: str
    reviewer_id: str
    reviewed_at: str
    policy_id: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": PROVENANCE_SCHEMA_VERSION,
            "source": {
                "repository": self.repository,
                "revision": self.revision,
                "path": self.source_path,
            },
            "authors": list(self.authors),
            "license": self.license,
            "created_at": self.created_at,
            "review": {
                "status": self.review_status,
                "reviewer_id": self.reviewer_id,
                "reviewed_at": self.reviewed_at,
                "policy_id": self.policy_id,
            },
        }

    @property
    def digest(self) -> str:
        return provenance_digest(self.to_dict())


def provenance_digest(value: object) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def parse_provenance(value: object) -> PackProvenance:
    if not isinstance(value, Mapping):
        raise ValueError("pack.provenance must be an object")
    unknown = sorted(set(value) - _TOP_FIELDS)
    if unknown:
        raise ValueError(f"pack.provenance contains unsupported fields: {', '.join(unknown)}")
    if value.get("schema_version") != PROVENANCE_SCHEMA_VERSION:
        raise ValueError("pack.provenance.schema_version must be 1.0")
    source = value.get("source")
    if not isinstance(source, Mapping):
        raise ValueError("pack.provenance.source must be an object")
    unknown_source = sorted(set(source) - _SOURCE_FIELDS)
    if unknown_source:
        raise ValueError(
            f"pack.provenance.source contains unsupported fields: {', '.join(unknown_source)}"
        )
    repository = _text(source.get("repository"), "source.repository")
    parsed_url = urlparse(repository)
    if (
        parsed_url.scheme != "https"
        or not parsed_url.netloc
        or parsed_url.username
        or parsed_url.query
        or parsed_url.fragment
    ):
        raise ValueError("provenance.source.repository must be an HTTPS repository URL")
    revision = _text(source.get("revision"), "source.revision", limit=64)
    if not _REVISION.fullmatch(revision):
        raise ValueError("provenance.source.revision must be a 40-64 character hex revision")
    source_path = _text(source.get("path"), "source.path")
    path_parts = source_path.split("/")
    if (
        source_path.startswith(("/", "~"))
        or "\\" in source_path
        or ":" in source_path
        or any(part in {"", ".", ".."} for part in path_parts)
    ):
        raise ValueError("provenance.source.path must be a repository-relative path")
    authors_value = value.get("authors")
    if (
        not isinstance(authors_value, Sequence)
        or isinstance(authors_value, (str, bytes, bytearray))
        or not authors_value
        or len(authors_value) > 20
    ):
        raise ValueError("provenance.authors must contain 1 to 20 identifiers")
    authors = tuple(_text(author, "authors[]", limit=256) for author in authors_value)
    if len(set(authors)) != len(authors):
        raise ValueError("provenance.authors must not contain duplicates")
    license_name = _text(value.get("license"), "license", limit=64)
    if not _LICENSE.fullmatch(license_name):
        raise ValueError("provenance.license must be an SPDX-style identifier")
    review = value.get("review")
    if not isinstance(review, Mapping):
        raise ValueError("pack.provenance.review must be an object")
    unknown_review = sorted(set(review) - _REVIEW_FIELDS)
    if unknown_review:
        raise ValueError(
            f"pack.provenance.review contains unsupported fields: {', '.join(unknown_review)}"
        )
    status = _text(review.get("status"), "review.status", limit=32)
    if status not in {"approved", "pending", "rejected"}:
        raise ValueError("provenance.review.status must be approved, pending, or rejected")
    created_at = _time(value.get("created_at"), "created_at")
    reviewed_at = _time(review.get("reviewed_at"), "review.reviewed_at")
    created_value = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    reviewed_value = datetime.fromisoformat(reviewed_at.replace("Z", "+00:00"))
    if reviewed_value < created_value:
        raise ValueError("provenance.review.reviewed_at must not precede created_at")
    return PackProvenance(
        repository,
        revision.lower(),
        source_path,
        authors,
        license_name,
        created_at,
        status,
        _text(review.get("reviewer_id"), "review.reviewer_id", limit=256),
        reviewed_at,
        _text(review.get("policy_id"), "review.policy_id", limit=256),
    )


__all__ = [
    "PROVENANCE_SCHEMA_VERSION",
    "PackProvenance",
    "parse_provenance",
    "provenance_digest",
]
