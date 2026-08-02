"""External-provider planning without execution or credential handling.

The public core emits reviewed lifecycle plans. An explicitly installed plugin
may execute them after applying its own authorization boundary.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlparse


_VERSION = re.compile(r"^(?:v)?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$")
_TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_STRATUS = re.compile(r"^(?:aws|azure|gcp|k8s)\.[a-z0-9.-]{3,120}$")
_CALDERA_ID = re.compile(r"^[A-Za-z0-9_.-]{3,128}$")


@dataclass(frozen=True)
class ExternalPlan:
    adapter: str
    provider_version: str
    target_uri: str
    phases: tuple[Mapping[str, object], ...]
    cleanup_required: bool
    network_required: bool
    execution_supported_by_core: bool = False

    def to_dict(self) -> dict[str, object]:
        value = {
            "schema_version": "1.0",
            "adapter": self.adapter,
            "provider_version": self.provider_version,
            "target_uri": self.target_uri,
            "phases": [dict(phase) for phase in self.phases],
            "cleanup_required": self.cleanup_required,
            "network_required": self.network_required,
            "execution_supported_by_core": self.execution_supported_by_core,
            "status": "reviewed_plan_requires_explicit_executor_plugin",
        }
        value["plan_sha256"] = hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return value


def _version(value: str) -> str:
    if not _VERSION.fullmatch(value):
        raise ValueError("External provider version must be an exact semantic version")
    return value


def build_atomic_plan(
    *, technique_id: str, test_guid: str, provider_version: str, target_uri: str
) -> ExternalPlan:
    if not _TECHNIQUE.fullmatch(technique_id):
        raise ValueError("Atomic technique_id must be an ATT&CK technique such as T1057")
    try:
        parsed_guid = uuid.UUID(test_guid)
    except ValueError as exc:
        raise ValueError("Atomic test_guid must be a UUID") from exc
    if str(parsed_guid) != test_guid.casefold():
        raise ValueError("Atomic test_guid must be a UUID")
    if not target_uri.startswith(("localhost://", "docker://", "lab-agent://")):
        raise ValueError("Atomic plans require an explicit localhost, container, or lab-agent target")
    common = [technique_id, "-TestGuids", test_guid]
    return ExternalPlan(
        "atomic-red-team",
        _version(provider_version),
        target_uri,
        (
            {"phase": "check_prerequisites", "argv": ["Invoke-AtomicTest", *common, "-CheckPrereqs"]},
            {"phase": "execute", "argv": ["Invoke-AtomicTest", *common]},
            {"phase": "cleanup", "argv": ["Invoke-AtomicTest", *common, "-Cleanup"]},
        ),
        cleanup_required=True,
        network_required=False,
    )


def build_stratus_plan(
    *, technique_id: str, provider_version: str, target_uri: str
) -> ExternalPlan:
    if not _STRATUS.fullmatch(technique_id):
        raise ValueError("Stratus technique_id must be a supported cloud or Kubernetes technique ID")
    if not target_uri.startswith(("cloud://", "kubernetes://")):
        raise ValueError("Stratus requires a named cloud sandbox or Kubernetes target URI")
    return ExternalPlan(
        "stratus-red-team",
        _version(provider_version),
        target_uri,
        (
            {"phase": "warmup", "argv": ["stratus", "warmup", technique_id]},
            {"phase": "execute", "argv": ["stratus", "detonate", technique_id]},
            {"phase": "revert", "argv": ["stratus", "revert", technique_id]},
            {"phase": "cleanup", "argv": ["stratus", "cleanup", technique_id]},
        ),
        cleanup_required=True,
        network_required=True,
    )


def build_caldera_plan(
    *, adversary_id: str, provider_version: str, target_uri: str, server_url: str
) -> ExternalPlan:
    if not _CALDERA_ID.fullmatch(adversary_id):
        raise ValueError("CALDERA adversary_id has an invalid format")
    parsed = urlparse(server_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("CALDERA server_url must be an explicit HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("CALDERA server_url may not contain credentials, query data, or fragments")
    endpoint = server_url.rstrip("/") + "/api/v2/operations"
    return ExternalPlan(
        "mitre-caldera",
        _version(provider_version),
        target_uri,
        (
            {
                "phase": "create_operation",
                "request": {
                    "method": "POST",
                    "url": endpoint,
                    "body": {"adversary_id": adversary_id, "name": "AgentSim authorized operation"},
                    "credentials_included": False,
                },
            },
            {"phase": "observe", "request": {"method": "GET", "url": endpoint, "credentials_included": False}},
            {"phase": "stop_and_cleanup", "manual_approval_required": True},
        ),
        cleanup_required=True,
        network_required=True,
    )


def adapter_names() -> tuple[str, ...]:
    return ("atomic-red-team", "stratus-red-team", "mitre-caldera")


def build_external_plan(adapter: str, **parameters: str) -> ExternalPlan:
    selected = adapter.casefold()
    if selected == "atomic-red-team":
        return build_atomic_plan(**parameters)
    if selected == "stratus-red-team":
        return build_stratus_plan(**parameters)
    if selected == "mitre-caldera":
        return build_caldera_plan(**parameters)
    raise ValueError(f"Unknown external adapter: {adapter}")
