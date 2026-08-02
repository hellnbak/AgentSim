"""Typed, expiring authorization manifests."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping


@dataclass(frozen=True)
class AuthorizationManifest:
    """Explicit authority, scope, targets, and resource limits for a run."""

    manifest_id: str
    authorized_by: str
    scope: str
    issued_at: str
    expires_at: str
    allowed_modes: tuple[str, ...]
    allowed_targets: tuple[str, ...]
    allowed_ability_ids: tuple[str, ...]
    allow_network: bool
    max_actions: int
    max_duration_seconds: int
    max_processes: int
    max_cloud_spend_usd: float

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "AuthorizationManifest":
        required_strings = ("manifest_id", "authorized_by", "scope", "issued_at", "expires_at")
        strings: dict[str, str] = {}
        for key in required_strings:
            item = value.get(key)
            if not isinstance(item, str) or not item.strip():
                raise ValueError(f"authorization.{key} must be a non-empty string")
            strings[key] = item
        issued_at = _parse_time(strings["issued_at"], "issued_at")
        expires_at = _parse_time(strings["expires_at"], "expires_at")
        if expires_at <= issued_at:
            raise ValueError("authorization.expires_at must be after issued_at")
        allowed_modes = _string_tuple(value.get("allowed_modes"), "allowed_modes")
        if any(mode not in {"simulate", "emulate", "lab"} for mode in allowed_modes):
            raise ValueError("authorization.allowed_modes contains an unsupported mode")
        allowed_targets = _string_tuple(value.get("allowed_targets"), "allowed_targets")
        allowed_abilities = _string_tuple(
            value.get("allowed_ability_ids", ("*",)), "allowed_ability_ids"
        )
        limits = value.get("resource_limits", {})
        if not isinstance(limits, Mapping):
            raise ValueError("authorization.resource_limits must be an object")
        return cls(
            **strings,
            allowed_modes=allowed_modes,
            allowed_targets=allowed_targets,
            allowed_ability_ids=allowed_abilities,
            allow_network=value.get("allow_network") is True,
            max_actions=_positive_int(limits.get("max_actions", 100), "max_actions"),
            max_duration_seconds=_positive_int(
                limits.get("max_duration_seconds", 3600), "max_duration_seconds"
            ),
            max_processes=_positive_int(limits.get("max_processes", 25), "max_processes"),
            max_cloud_spend_usd=_nonnegative_number(
                limits.get("max_cloud_spend_usd", 0), "max_cloud_spend_usd"
            ),
        )

    def expired(self, now: datetime | None = None) -> bool:
        selected = now or datetime.now(timezone.utc)
        if selected.tzinfo is None:
            selected = selected.replace(tzinfo=timezone.utc)
        return selected.astimezone(timezone.utc) >= _parse_time(self.expires_at, "expires_at")

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["resource_limits"] = {
            "max_actions": value.pop("max_actions"),
            "max_duration_seconds": value.pop("max_duration_seconds"),
            "max_processes": value.pop("max_processes"),
            "max_cloud_spend_usd": value.pop("max_cloud_spend_usd"),
        }
        return value


def _parse_time(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"authorization.{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"authorization.{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _string_tuple(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise ValueError(f"authorization.{field} must be a non-empty array")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError(f"authorization.{field} must contain non-empty strings")
    return tuple(str(item) for item in value)


def _positive_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"authorization.resource_limits.{field} must be positive")
    return value


def _nonnegative_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise ValueError(f"authorization.resource_limits.{field} must be non-negative")
    return float(value)


def load_authorization_manifest(path: str | Path) -> AuthorizationManifest:
    candidate = Path(path)
    if not candidate.is_file():
        raise FileNotFoundError(f"authorization manifest does not exist: {candidate}")
    try:
        value = json.loads(candidate.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid authorization manifest JSON: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ValueError("authorization manifest must be an object")
    return AuthorizationManifest.from_mapping(value)
