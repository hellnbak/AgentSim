"""Canonical checksums for public content packs."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Mapping

from .signature import verify_signature


_SHA256 = re.compile(r"^[a-f0-9]{64}$")


def content_digest(value: object) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_integrity(
    pack: Mapping[str, object],
    content_key: str,
    *,
    trusted_keys: Mapping[str, object] | None = None,
) -> None:
    integrity = pack.get("integrity")
    if integrity is None:
        raise ValueError("pack.integrity is required")
    if not isinstance(integrity, Mapping):
        raise ValueError("pack.integrity must be an object")
    if integrity.get("algorithm") != "sha256":
        raise ValueError("pack.integrity.algorithm must be sha256")
    expected = integrity.get("digest")
    if not isinstance(expected, str) or not _SHA256.fullmatch(expected):
        raise ValueError("pack.integrity.digest must be a SHA-256 hex digest")
    observed = content_digest(pack.get(content_key))
    if not hmac.compare_digest(observed, expected):
        raise ValueError("pack integrity checksum does not match its content")
    verify_signature(pack, content_key, trusted_keys=trusted_keys)
