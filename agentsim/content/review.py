"""Deterministic review gates for signed community content packs."""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from .ability_loader import parse_ability_pack
from .campaign_loader import parse_campaign_pack
from .integrity import content_digest
from .provenance import PackProvenance, parse_provenance
from .signature import SIGNATURE_ALGORITHM, verify_signature


PACK_REVIEW_SCHEMA_VERSION = "1.0"
_MAX_PACK_BYTES = 4 * 1024 * 1024
_MAX_TRUST_STORE_BYTES = 1024 * 1024
_HEX = re.compile(r"^[a-fA-F0-9]+$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_PROHIBITED_EXECUTABLE_KEYS = {
    "argv",
    "binary",
    "command",
    "download",
    "executable",
    "inline_payload",
    "payload",
    "script",
    "shell",
    "url",
}


@dataclass(frozen=True)
class PackReviewFinding:
    severity: str
    code: str
    message: str
    path: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
            "path": self.path,
        }


@dataclass(frozen=True)
class CommunityPackReview:
    pack_id: str
    pack_kind: str
    content_key: str
    content_digest: str | None
    signature_key_id: str | None
    provenance: PackProvenance | None
    item_count: int
    findings: tuple[PackReviewFinding, ...]
    checks: Mapping[str, bool]

    @property
    def verdict(self) -> str:
        if any(finding.severity == "block" for finding in self.findings):
            return "blocked"
        if any(finding.severity == "review" for finding in self.findings):
            return "review"
        return "approved"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": PACK_REVIEW_SCHEMA_VERSION,
            "kind": "community-pack-review",
            "verdict": self.verdict,
            "pack_id": self.pack_id,
            "pack_kind": self.pack_kind,
            "content_key": self.content_key,
            "content_digest": self.content_digest,
            "signature_key_id": self.signature_key_id,
            "provenance": self.provenance.to_dict() if self.provenance else None,
            "provenance_digest": self.provenance.digest if self.provenance else None,
            "item_count": self.item_count,
            "checks": dict(self.checks),
            "findings": [finding.to_dict() for finding in self.findings],
            "execution_performed": False,
        }


def _pack_shape(value: Mapping[str, object]) -> tuple[str, str, str]:
    if value.get("kind") == "ability-pack":
        return "ability-pack", "abilities", str(value.get("pack_id", ""))
    if value.get("kind") == "campaign-pack":
        return "campaign-pack", "campaigns", str(value.get("pack_id", ""))
    if value.get("pack_schema_version") == "1.0" and "rules" in value:
        return "detection-pack", "rules", str(value.get("pack_id", ""))
    raise ValueError("community review supports ability, campaign, and detection packs")


def _load_trust_store_value(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError("community trust store must be an object")
    if "keys" in value:
        unknown = sorted(set(value) - {"schema_version", "keys"})
        if unknown or value.get("schema_version") != "1.0":
            raise ValueError("community trust store must use schema_version 1.0")
        keys = value.get("keys")
    else:
        keys = value
    if not isinstance(keys, Mapping) or not keys or len(keys) > 100:
        raise ValueError("community trust store must contain 1 to 100 keys")
    parsed: dict[str, object] = {}
    for key_id, raw in keys.items():
        if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
            raise ValueError("community trust key IDs have an invalid format")
        if not isinstance(raw, Mapping):
            raise ValueError(f"community trust key is invalid: {key_id}")
        if set(raw) - {"algorithm", "exponent", "modulus_hex"}:
            raise ValueError(f"community trust key has unsupported fields: {key_id}")
        modulus = raw.get("modulus_hex")
        exponent = raw.get("exponent", 65537)
        if (
            raw.get("algorithm") != SIGNATURE_ALGORITHM
            or not isinstance(modulus, str)
            or len(modulus) < 256
            or len(modulus) > 2048
            or not _HEX.fullmatch(modulus)
            or isinstance(exponent, bool)
            or not isinstance(exponent, int)
            or exponent < 3
            or exponent > 2_147_483_647
            or exponent % 2 == 0
            or int(modulus, 16) % 2 == 0
        ):
            raise ValueError(f"community trust key is malformed: {key_id}")
        parsed[key_id] = {
            "algorithm": SIGNATURE_ALGORITHM,
            "exponent": exponent,
            "modulus_hex": modulus.lower(),
        }
    return parsed


def load_community_trust_store(path: str | Path) -> Mapping[str, object]:
    selected = Path(path)
    if not selected.is_file():
        raise FileNotFoundError(f"community trust store does not exist: {selected}")
    if selected.stat().st_size > _MAX_TRUST_STORE_BYTES:
        raise ValueError("community trust store exceeds the 1 MiB limit")
    return _load_trust_store_value(json.loads(selected.read_text(encoding="utf-8")))


def parse_community_trust_store(value: object) -> Mapping[str, object]:
    return _load_trust_store_value(value)


def _walk_prohibited(value: object, path: str = "content") -> list[PackReviewFinding]:
    findings: list[PackReviewFinding] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            name = str(key).casefold()
            child_path = f"{path}.{key}"
            if name in _PROHIBITED_EXECUTABLE_KEYS:
                findings.append(
                    PackReviewFinding(
                        "block",
                        "inline_executable_content",
                        f"community content may not define the {key} field",
                        child_path,
                    )
                )
            findings.extend(_walk_prohibited(item, child_path))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            findings.extend(_walk_prohibited(item, f"{path}[{index}]"))
    return findings


def _ability_safety(value: Mapping[str, object]) -> list[PackReviewFinding]:
    findings: list[PackReviewFinding] = []
    abilities = value.get("abilities")
    if not isinstance(abilities, Sequence):
        return findings
    for index, ability in enumerate(abilities):
        if not isinstance(ability, Mapping):
            continue
        execution = ability.get("execution")
        target = ability.get("target_constraints")
        path = f"abilities[{index}]"
        if isinstance(target, Mapping) and target.get("production_allowed") is True:
            findings.append(
                PackReviewFinding("block", "production_enabled", "community abilities must remain production locked", path)
            )
        if isinstance(execution, Mapping):
            if execution.get("requires_elevation") is True:
                findings.append(
                    PackReviewFinding("block", "elevation_requested", "community abilities may not request elevation", path)
                )
            providers = execution.get("supported_providers", ())
            if isinstance(providers, Sequence) and any(item != "simulate" for item in providers):
                findings.append(
                    PackReviewFinding("review", "active_provider", "local or Docker providers require separate command-catalog review", path)
                )
            if execution.get("network_access") == "required":
                findings.append(
                    PackReviewFinding("review", "network_capability", "network-capable content requires an explicit operator review", path)
                )
            if execution.get("state_changes") is True:
                findings.append(
                    PackReviewFinding("review", "state_change_capability", "state-changing content requires cleanup and operator review", path)
                )
    return findings


def _structural_review(
    value: Mapping[str, object], pack_kind: str
) -> tuple[int, str | None]:
    candidate = copy.deepcopy(dict(value))
    integrity = candidate.get("integrity")
    if isinstance(integrity, dict):
        integrity.pop("signature", None)
    try:
        if pack_kind == "ability-pack":
            return len(parse_ability_pack(candidate, "community-review")), None
        if pack_kind == "campaign-pack":
            return len(parse_campaign_pack(candidate, "community-review")), None
        from agentsim.detection.packs import parse_detection_pack

        return len(parse_detection_pack(candidate).rules), None
    except (TypeError, ValueError) as exc:
        return 0, str(exc)


def review_community_pack(
    value: Mapping[str, object],
    *,
    trusted_keys: Mapping[str, object] | None = None,
) -> CommunityPackReview:
    """Review one pack without importing code or resolving executable content."""

    rendered = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    if len(rendered.encode("utf-8")) > _MAX_PACK_BYTES:
        raise ValueError("community pack exceeds the 4 MiB review limit")
    pack_kind, content_key, pack_id = _pack_shape(value)
    findings: list[PackReviewFinding] = []
    checks = {"checksum": False, "signature": False, "provenance": False, "structure": False, "safety": False}
    digest: str | None = None
    key_id: str | None = None
    provenance: PackProvenance | None = None
    content = value.get(content_key)
    if isinstance(content, (Sequence, Mapping)) and not isinstance(content, (str, bytes, bytearray)):
        digest = content_digest(content)
    integrity = value.get("integrity")
    if not isinstance(integrity, Mapping):
        findings.append(PackReviewFinding("block", "checksum_invalid", "pack.integrity is required"))
    elif integrity.get("algorithm") != "sha256":
        findings.append(PackReviewFinding("block", "checksum_invalid", "pack.integrity.algorithm must be sha256"))
    elif (
        not isinstance(integrity.get("digest"), str)
        or not _SHA256.fullmatch(str(integrity["digest"]))
        or digest != integrity["digest"]
    ):
        findings.append(PackReviewFinding("block", "checksum_invalid", "pack integrity checksum does not match its content"))
    else:
        checks["checksum"] = True

    try:
        key_id = verify_signature(value, content_key, trusted_keys=trusted_keys)
        checks["signature"] = key_id is not None
        if key_id is None:
            findings.append(PackReviewFinding("block", "signature_missing", "community packs require a trusted signature"))
    except ValueError as exc:
        findings.append(PackReviewFinding("block", "signature_invalid", str(exc)))
    try:
        provenance = parse_provenance(value.get("provenance"))
        checks["provenance"] = True
        if provenance.review_status == "pending":
            findings.append(PackReviewFinding("review", "review_pending", "pack provenance review is still pending"))
        elif provenance.review_status == "rejected":
            findings.append(PackReviewFinding("block", "review_rejected", "pack provenance records a rejected review"))
    except ValueError as exc:
        findings.append(PackReviewFinding("block", "provenance_invalid", str(exc)))
    item_count, structure_error = _structural_review(value, pack_kind)
    if structure_error:
        findings.append(PackReviewFinding("block", "structure_invalid", structure_error))
    else:
        checks["structure"] = True
    safety_findings = _walk_prohibited(content)
    if pack_kind == "ability-pack":
        safety_findings.extend(_ability_safety(value))
    findings.extend(safety_findings)
    checks["safety"] = not any(finding.severity == "block" for finding in safety_findings)
    return CommunityPackReview(
        pack_id,
        pack_kind,
        content_key,
        digest,
        key_id,
        provenance,
        item_count,
        tuple(findings[:200]),
        checks,
    )


def review_community_pack_file(
    path: str | Path,
    *,
    trust_store_paths: Sequence[str | Path] = (),
) -> CommunityPackReview:
    selected = Path(path)
    if not selected.is_file():
        raise FileNotFoundError(f"community pack does not exist: {selected}")
    if selected.stat().st_size > _MAX_PACK_BYTES:
        raise ValueError("community pack exceeds the 4 MiB review limit")
    value = json.loads(selected.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("community pack must be a JSON object")
    keys: dict[str, object] = {}
    for trust_path in trust_store_paths:
        for key_id, key in load_community_trust_store(trust_path).items():
            if key_id in keys and keys[key_id] != key:
                raise ValueError(f"conflicting community trust key: {key_id}")
            keys[key_id] = key
    return review_community_pack(value, trusted_keys=keys)


__all__ = [
    "PACK_REVIEW_SCHEMA_VERSION",
    "CommunityPackReview",
    "PackReviewFinding",
    "load_community_trust_store",
    "parse_community_trust_store",
    "review_community_pack",
    "review_community_pack_file",
]
