"""Generated, content-safe detection and alert examples for supported SIEMs."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from importlib import resources
from pathlib import Path
from typing import Mapping, Sequence

from agentsim.defense.feedback import DetectionAlert, detection_alert_from_mapping
from agentsim.models.telemetry import NormalizedEvent
from agentsim.telemetry.connectors import CONNECTOR_NAMES
from agentsim.telemetry.normalization import normalize_record

from .ast import DetectionRule, parse_rule, rule_to_dict
from .packs import DetectionPack, parse_detection_pack
from .renderers import FORMATS


SAMPLE_SCHEMA_VERSION = "1.0"
DETECTION_SAMPLE_FORMATS = ("generic", *FORMATS)
ALERT_SAMPLE_PROFILES = ("generic", *CONNECTOR_NAMES)
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_FIELD = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.]{0,127}$")
_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
_MAX_SAMPLES = 100
_BASE_TIME = datetime(2026, 8, 2, 20, 0, tzinfo=timezone.utc)
_SENSITIVE_KEYS = frozenset(
    {
        "authorization",
        "credential",
        "message",
        "password",
        "payload",
        "prompt",
        "response",
        "secret",
        "token",
        "tool_arguments",
        "tool_result",
    }
)


@dataclass(frozen=True)
class SampleCondition:
    field: str
    value: str | bool | int | float

    def to_dict(self) -> dict[str, object]:
        return {"field": self.field, "operator": "eq", "value": self.value}


@dataclass(frozen=True)
class DetectionSample:
    sample_id: str
    rule_id: str
    scenario_id: str
    title: str
    description: str
    severity: str
    mappings: tuple[str, ...]
    conditions: tuple[SampleCondition, ...]
    benign_overrides: Mapping[str, str | bool | int | float]

    def to_dict(self) -> dict[str, object]:
        return {
            "sample_id": self.sample_id,
            "rule_id": self.rule_id,
            "scenario_id": self.scenario_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "mappings": list(self.mappings),
            "conditions": [item.to_dict() for item in self.conditions],
            "benign_overrides": dict(self.benign_overrides),
        }

    def rule(self) -> DetectionRule:
        return parse_rule(
            {
                "schema_version": "1.0",
                "rule_id": self.rule_id,
                "name": self.title,
                "description": self.description,
                "severity": self.severity,
                "group_by": ["trace_id"],
                "mappings": list(self.mappings),
                "expression": {
                    "type": "match",
                    "predicates": [item.to_dict() for item in self.conditions],
                },
                "metadata": {
                    "sample_id": self.sample_id,
                    "scenario_id": self.scenario_id,
                    "deployment_status": "tuning_required",
                    "content_values_required": False,
                },
            }
        )


def _text(value: object, name: str, *, limit: int = 512) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"{name} must be a non-empty string up to {limit} characters")
    return value


def _parse_sample(value: object, index: int) -> DetectionSample:
    if not isinstance(value, Mapping):
        raise ValueError(f"detection sample {index} must be an object")
    allowed = {
        "sample_id",
        "rule_id",
        "scenario_id",
        "title",
        "description",
        "severity",
        "mappings",
        "conditions",
        "benign_overrides",
    }
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"detection sample {index} has unsupported fields: {', '.join(unknown)}")
    sample_id = _text(value.get("sample_id"), f"sample {index}.sample_id", limit=128)
    rule_id = _text(value.get("rule_id"), f"sample {index}.rule_id", limit=128)
    scenario_id = _text(value.get("scenario_id"), f"sample {index}.scenario_id", limit=128)
    if (
        not _IDENTIFIER.fullmatch(sample_id)
        or not _IDENTIFIER.fullmatch(rule_id)
        or not _IDENTIFIER.fullmatch(scenario_id)
    ):
        raise ValueError(f"detection sample {index} identifiers are invalid")
    severity = str(value.get("severity", ""))
    if severity not in _SEVERITIES:
        raise ValueError(f"detection sample {index} severity is invalid")
    raw_mappings = value.get("mappings")
    raw_conditions = value.get("conditions")
    raw_overrides = value.get("benign_overrides")
    if (
        not isinstance(raw_mappings, Sequence)
        or isinstance(raw_mappings, (str, bytes, bytearray))
        or not raw_mappings
        or len(raw_mappings) > 20
    ):
        raise ValueError(f"detection sample {index} mappings must contain 1 to 20 values")
    if (
        not isinstance(raw_conditions, Sequence)
        or isinstance(raw_conditions, (str, bytes, bytearray))
        or not raw_conditions
        or len(raw_conditions) > 12
    ):
        raise ValueError(f"detection sample {index} conditions must contain 1 to 12 values")
    if not isinstance(raw_overrides, Mapping) or not raw_overrides:
        raise ValueError(f"detection sample {index} benign_overrides must be an object")
    conditions: list[SampleCondition] = []
    for condition_index, raw_condition in enumerate(raw_conditions):
        if not isinstance(raw_condition, Mapping) or set(raw_condition) != {"field", "value"}:
            raise ValueError(
                f"detection sample {index} condition {condition_index} is invalid"
            )
        field = str(raw_condition.get("field", ""))
        observed = raw_condition.get("value")
        if (
            not _FIELD.fullmatch(field)
            or isinstance(observed, (dict, list, tuple))
            or observed is None
            or (isinstance(observed, str) and len(observed) > 512)
        ):
            raise ValueError(
                f"detection sample {index} condition {condition_index} is invalid"
            )
        conditions.append(SampleCondition(field, observed))  # type: ignore[arg-type]
    condition_fields = {item.field for item in conditions}
    overrides: dict[str, str | bool | int | float] = {}
    for field, observed in raw_overrides.items():
        if (
            field not in condition_fields
            or isinstance(observed, (dict, list, tuple))
            or observed is None
            or (isinstance(observed, str) and len(observed) > 512)
        ):
            raise ValueError(f"detection sample {index} benign override is invalid")
        overrides[str(field)] = observed  # type: ignore[assignment]
    if all(overrides.get(item.field, item.value) == item.value for item in conditions):
        raise ValueError(f"detection sample {index} benign overrides do not change a condition")
    return DetectionSample(
        sample_id,
        rule_id,
        scenario_id,
        _text(value.get("title"), f"sample {index}.title"),
        _text(value.get("description"), f"sample {index}.description", limit=2000),
        severity,
        tuple(_text(item, f"sample {index}.mapping") for item in raw_mappings),
        tuple(conditions),
        overrides,
    )


def _catalog_value() -> Mapping[str, object]:
    resource = resources.files("agentsim.detection.sample_content") / "catalog.json"
    with resource.open("r", encoding="utf-8") as input_file:
        value = json.load(input_file)
    if not isinstance(value, Mapping):
        raise ValueError("detection sample catalog must be an object")
    allowed = {
        "schema_version",
        "kind",
        "catalog_id",
        "version",
        "description",
        "deployment_status",
        "synthetic",
        "content_values_recorded",
        "samples",
    }
    if set(value) - allowed:
        raise ValueError("detection sample catalog has unsupported fields")
    if (
        value.get("schema_version") != SAMPLE_SCHEMA_VERSION
        or value.get("kind") != "detection-sample-catalog"
        or value.get("deployment_status") != "tuning_required"
        or value.get("synthetic") is not True
        or value.get("content_values_recorded") is not False
    ):
        raise ValueError("detection sample catalog safety metadata is invalid")
    return value


def load_detection_samples() -> tuple[DetectionSample, ...]:
    value = _catalog_value()
    raw_samples = value.get("samples")
    if (
        not isinstance(raw_samples, Sequence)
        or isinstance(raw_samples, (str, bytes, bytearray))
        or not raw_samples
        or len(raw_samples) > _MAX_SAMPLES
    ):
        raise ValueError("detection sample catalog must contain 1 to 100 samples")
    samples = tuple(_parse_sample(item, index) for index, item in enumerate(raw_samples))
    for name, identifiers in (
        ("sample_id", [item.sample_id for item in samples]),
        ("rule_id", [item.rule_id for item in samples]),
    ):
        if len(set(identifiers)) != len(identifiers):
            raise ValueError(f"detection sample catalog has duplicate {name} values")
    return samples


def detection_sample_catalog() -> dict[str, object]:
    value = _catalog_value()
    samples = load_detection_samples()
    detection_file_count = sum(
        len(render_detection_sample(sample, format_name))
        for format_name in DETECTION_SAMPLE_FORMATS
        for sample in samples
    )
    return {
        "schema_version": SAMPLE_SCHEMA_VERSION,
        "kind": "detection-sample-catalog",
        "catalog_id": value["catalog_id"],
        "version": value["version"],
        "description": value["description"],
        "deployment_status": "tuning_required",
        "synthetic": True,
        "content_values_recorded": False,
        "execution_performed": False,
        "sample_count": len(samples),
        "detection_format_count": len(DETECTION_SAMPLE_FORMATS),
        "alert_profile_count": len(ALERT_SAMPLE_PROFILES),
        "detection_rule_variant_count": len(samples) * len(DETECTION_SAMPLE_FORMATS),
        "detection_file_count": detection_file_count,
        "alert_record_count": len(samples) * len(ALERT_SAMPLE_PROFILES),
        "detection_formats": list(DETECTION_SAMPLE_FORMATS),
        "alert_profiles": list(ALERT_SAMPLE_PROFILES),
        "samples": [item.to_dict() for item in samples],
    }


def sample_detection_pack() -> DetectionPack:
    samples = load_detection_samples()
    return parse_detection_pack(
        {
            "pack_schema_version": "1.0",
            "pack_id": "agentsim.detection-samples",
            "name": "AgentSim Detection Sample Pack",
            "version": "1.0.0",
            "description": "Six content-safe examples with matching malicious and benign telemetry.",
            "rules": [
                {
                    **rule_to_dict(sample.rule()),
                    "required_fields": sorted(
                        {"trace_id", *(item.field for item in sample.conditions)}
                    ),
                    "expected_sources": ["agent_runtime"],
                }
                for sample in samples
            ],
            "metadata": {
                "maintainer": "AgentSim contributors",
                "license": "MIT",
                "production_status": "tuning_required",
                "content_values_required": False,
                "synthetic": True,
            },
        }
    )


def _timestamp(index: int) -> str:
    return (_BASE_TIME + timedelta(minutes=index)).isoformat().replace("+00:00", "Z")


def _event_record(sample: DetectionSample, index: int, variant: str) -> dict[str, object]:
    values = {condition.field: condition.value for condition in sample.conditions}
    if variant == "benign":
        values.update(sample.benign_overrides)
    return {
        "timestamp": _timestamp(index),
        "source": "agent_runtime",
        "event_id": f"sample-event-{index + 1:02d}-{variant}",
        "trace_id": f"sample-trace-{index + 1:02d}",
        "agent_id": f"sample-agent-{index + 1:02d}",
        **values,
        "synthetic": True,
        "content_recorded": False,
        "scenario_id": sample.scenario_id,
        "variant": variant,
    }


def sample_telemetry_records(variant: str = "malicious") -> tuple[dict[str, object], ...]:
    if variant not in {"malicious", "benign"}:
        raise ValueError("sample telemetry variant must be malicious or benign")
    return tuple(
        _event_record(sample, index, variant)
        for index, sample in enumerate(load_detection_samples())
    )


def sample_telemetry(variant: str = "malicious") -> tuple[NormalizedEvent, ...]:
    return tuple(
        normalize_record(record, collector="agent_runtime", synthetic=True)
        for record in sample_telemetry_records(variant)
    )


def _json_value(value: object) -> str:
    return json.dumps(value, ensure_ascii=True)


def _python_value(value: object) -> str:
    if isinstance(value, bool):
        return "True" if value else "False"
    return repr(value)


def _condition_text(sample: DetectionSample, format_name: str) -> str:
    parts: list[str] = []
    for condition in sample.conditions:
        field = condition.field
        value = condition.value
        if format_name == "graylog":
            parts.append(f"{field.replace('.', '_')}:{_json_value(value)}")
        elif format_name == "splunk":
            rendered = str(value).lower() if isinstance(value, bool) else str(value)
            parts.append(f'{field}={_json_value(rendered)}')
        elif format_name == "kql":
            operator = "=="
            parts.append(f"{field} {operator} {_json_value(value)}")
        else:
            parts.append(f"{field} == {_json_value(value)}")
    separator = " AND " if format_name in {"graylog", "splunk", "crowdstrike"} else " and "
    return separator.join(parts)


def _sigma(sample: DetectionSample) -> str:
    rule_uuid = uuid.uuid5(uuid.NAMESPACE_URL, f"https://agentsim.dev/{sample.rule_id}")
    selections = "\n".join(
        f"    {item.field}: {_json_value(item.value)}" for item in sample.conditions
    )
    tags = "\n".join(f"  - {_json_value(item)}" for item in sample.mappings)
    return f"""title: {_json_value(sample.title)}
id: {rule_uuid}
status: test
description: {_json_value('[TUNING REQUIRED] ' + sample.description)}
author: AgentSim contributors
date: 2026-08-02
tags:
{tags}
logsource:
  category: application
  product: agentsim
detection:
  selection:
{selections}
  condition: selection
falsepositives:
  - Authorized synthetic AgentSim control validation
level: {sample.severity}
"""


def _panther(sample: DetectionSample) -> Mapping[str, str]:
    conditions = "\n".join(
        f"        _value(event, {_json_value(item.field)}) == {_python_value(item.value)},"
        for item in sample.conditions
    )
    python_source = f'''# AGENTSIM STATUS: SAMPLE - TUNING AND HUMAN REVIEW REQUIRED
def _value(event, field):
    value = event
    for part in field.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def rule(event):
    return all((
{conditions}
    ))


def title(event):
    return {_json_value(sample.title)}


def dedup(event):
    return str(event.get("trace_id", "missing-trace"))
'''
    metadata = f"""AnalysisType: rule
DisplayName: {_json_value(sample.title)}
Enabled: false
Filename: {sample.sample_id}.py
RuleID: {sample.rule_id}
Severity: {sample.severity.title()}
LogTypes:
  - AgentSim.AgentEvent
Tags:
  - AgentSim
  - Sample
Description: {_json_value('[TUNING REQUIRED] ' + sample.description)}
Runbook: Validate the trace, policy decision, identity binding, and synthetic status before response.
Threshold: 1
"""
    return {
        f"{sample.sample_id}.py": python_source,
        f"{sample.sample_id}.yml": metadata,
    }


def render_detection_sample(sample: DetectionSample, format_name: str) -> Mapping[str, str]:
    selected = format_name.casefold()
    if selected not in DETECTION_SAMPLE_FORMATS:
        raise ValueError(f"unsupported detection sample format: {format_name}")
    header = "AGENTSIM STATUS: SAMPLE - TUNING AND HUMAN REVIEW REQUIRED"
    if selected == "generic":
        return {
            f"{sample.sample_id}.json": json.dumps(
                rule_to_dict(sample.rule()), indent=2, sort_keys=True
            )
            + "\n"
        }
    if selected == "sigma":
        return {f"{sample.sample_id}.yml": _sigma(sample)}
    if selected == "kql":
        return {
            f"{sample.sample_id}.kql": (
                f"// {header}\nAgentSimEvents\n"
                f"| where {_condition_text(sample, selected)}\n"
                "| project timestamp, trace_id, agent_id, event_id, event_type, "
                "policy_decision, tool_name, tool_risk\n"
            )
        }
    if selected == "splunk":
        return {
            f"{sample.sample_id}.spl": (
                f"# {header}\n"
                "index=<agent_runtime_index> sourcetype=agentsim:agent_event "
                f"{_condition_text(sample, selected)}\n"
                "| table _time trace_id agent_id event_id event_type policy_decision tool_name tool_risk\n"
            )
        }
    if selected == "crowdstrike":
        condition = " AND ".join(
            f"{item.field}={_json_value(item.value)}" for item in sample.conditions
        )
        return {
            f"{sample.sample_id}.cql": (
                f"// {header}\n#repo=agentsim\n| {condition}\n"
                "| select([@timestamp, trace_id, agent_id, event_id, event_type, "
                "policy_decision, tool_name, tool_risk])\n"
            )
        }
    if selected == "elastic":
        return {
            f"{sample.sample_id}.eql": (
                f"// {header}\nany where {_condition_text(sample, selected)}\n"
            )
        }
    if selected == "panther":
        return _panther(sample)
    return {
        f"{sample.sample_id}.query": (
            f"// {header}\nstreams:<agent-runtime-stream-id> AND "
            f"{_condition_text(sample, selected)}\n"
        )
    }


def _generic_alert(sample: DetectionSample, index: int) -> dict[str, object]:
    return DetectionAlert(
        alert_id=f"generic-alert-{index + 1:02d}",
        rule_id=sample.rule_id,
        detected_at=_timestamp(index),
        severity=sample.severity,
        trace_id=f"sample-trace-{index + 1:02d}",
        source_record_ids=(f"sample-event-{index + 1:02d}-malicious",),
        agent_id=f"sample-agent-{index + 1:02d}",
        synthetic=True,
        content_values_recorded=False,
    ).to_dict()


def _vendor_alert(profile: str, sample: DetectionSample, index: int) -> dict[str, object]:
    generic = _generic_alert(sample, index)
    observed_at = str(generic["detected_at"])
    alert_id = f"{profile}-alert-{index + 1:02d}"
    common = {
        "trace_id": generic["trace_id"],
        "agent_id": generic["agent_id"],
        "scenario_id": sample.scenario_id,
        "synthetic": True,
        "content_values_recorded": False,
    }
    if profile == "splunk":
        return {
            "_time": observed_at,
            "sourcetype": "agentsim:alert",
            "event_type": "detection.alert",
            "event_id": alert_id,
            "search_name": sample.rule_id,
            "alert_title": sample.title,
            "severity": sample.severity,
            "status": "new",
            "source_event_ids": generic["source_record_ids"],
            **common,
        }
    if profile == "elastic":
        return {
            "@timestamp": observed_at,
            "event": {
                "kind": "signal",
                "category": "intrusion_detection",
                "action": "detection.alert",
                "id": alert_id,
                "dataset": "agentsim.alerts",
            },
            "kibana": {
                "alert": {
                    "rule": {"uuid": sample.rule_id, "name": sample.title},
                    "severity": sample.severity,
                    "status": "active",
                }
            },
            "trace": {"id": generic["trace_id"]},
            "agent": {"id": generic["agent_id"]},
            "agentsim": {
                "scenario_id": sample.scenario_id,
                "source_event_ids": generic["source_record_ids"],
                "synthetic": True,
                "content_values_recorded": False,
            },
        }
    if profile == "crowdstrike":
        return {
            "timestamp": observed_at,
            "event_platform": "AgentSim",
            "event_simpleName": "AgentSimDetectionAlert",
            "id": alert_id,
            "aid": generic["agent_id"],
            "RuleId": sample.rule_id,
            "RuleName": sample.title,
            "Severity": sample.severity,
            "Status": "new",
            "SourceEventIds": generic["source_record_ids"],
            **common,
        }
    if profile == "sentinel":
        return {
            "TimeGenerated": observed_at,
            "Type": "SecurityAlert",
            "SystemAlertId": alert_id,
            "VendorName": "AgentSim",
            "AlertName": sample.title,
            "AlertSeverity": sample.severity.title(),
            "Status": "New",
            "TraceId": generic["trace_id"],
            "AgentId": generic["agent_id"],
            "ExtendedProperties": {
                "rule_id": sample.rule_id,
                "scenario_id": sample.scenario_id,
                "source_event_ids": generic["source_record_ids"],
                "synthetic": True,
                "content_values_recorded": False,
            },
        }
    if profile == "panther":
        return {
            "p_event_time": observed_at,
            "p_log_type": "AgentSim.Alert",
            "p_alert_id": alert_id,
            "p_rule_id": sample.rule_id,
            "p_rule_name": sample.title,
            "p_alert_severity": sample.severity.upper(),
            "p_alert_status": "OPEN",
            "source_event_ids": generic["source_record_ids"],
            **common,
        }
    if profile == "graylog":
        return {
            "timestamp": observed_at,
            "source": "agentsim",
            "event_type": "detection.alert",
            "event_id": alert_id,
            "event_definition_id": sample.rule_id,
            "event_definition_title": sample.title,
            "alert_severity": sample.severity,
            "alert_status": "unresolved",
            "source_event_ids": generic["source_record_ids"],
            **common,
        }
    raise ValueError(f"unsupported alert sample profile: {profile}")


def alert_sample_records(profile: str = "generic") -> tuple[dict[str, object], ...]:
    selected = profile.casefold()
    if selected not in ALERT_SAMPLE_PROFILES:
        raise ValueError(f"unsupported alert sample profile: {profile}")
    values = tuple(
        _generic_alert(sample, index)
        if selected == "generic"
        else _vendor_alert(selected, sample, index)
        for index, sample in enumerate(load_detection_samples())
    )
    if selected == "generic":
        for value in values:
            detection_alert_from_mapping(value)
    _assert_content_safe(values)
    return values


def _assert_content_safe(value: object, path: str = "sample") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            name = str(key).casefold()
            if name in _SENSITIVE_KEYS:
                raise ValueError(f"detection sample contains prohibited content field: {path}.{key}")
            _assert_content_safe(item, f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            _assert_content_safe(item, f"{path}[{index}]")


def _write_export_file(
    root: Path,
    relative: str,
    content: str,
    manifest: list[dict[str, object]],
    *,
    kind: str,
    profile: str,
) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    data = content.encode("utf-8")
    path.write_bytes(data)
    manifest.append(
        {
            "path": relative,
            "kind": kind,
            "profile": profile,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    )


def export_detection_sample_library(
    destination: str | Path,
    *,
    formats: Sequence[str] = (),
    alert_profiles: Sequence[str] = (),
) -> Path:
    root = Path(destination)
    selected_formats = (
        tuple(dict.fromkeys(item.casefold() for item in formats))
        or DETECTION_SAMPLE_FORMATS
    )
    selected_alerts = tuple(
        dict.fromkeys(item.casefold() for item in alert_profiles)
    ) or ALERT_SAMPLE_PROFILES
    unknown_formats = sorted(set(selected_formats) - set(DETECTION_SAMPLE_FORMATS))
    unknown_alerts = sorted(set(selected_alerts) - set(ALERT_SAMPLE_PROFILES))
    if unknown_formats or unknown_alerts:
        raise ValueError(
            "unsupported detection or alert sample profiles: "
            + ", ".join((*unknown_formats, *unknown_alerts))
        )
    if root.is_symlink() or root.exists() and (not root.is_dir() or any(root.iterdir())):
        raise ValueError("detection sample export destination must be absent or empty")
    root.mkdir(parents=True, exist_ok=True)
    manifest_files: list[dict[str, object]] = []
    samples = load_detection_samples()
    for format_name in selected_formats:
        for sample in samples:
            for filename, content in render_detection_sample(sample, format_name).items():
                _write_export_file(
                    root,
                    f"detections/{format_name}/{filename}",
                    content,
                    manifest_files,
                    kind="detection",
                    profile=format_name,
                )
    for profile in selected_alerts:
        content = "".join(
            json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n"
            for item in alert_sample_records(profile)
        )
        _write_export_file(
            root,
            f"alerts/{profile}.jsonl",
            content,
            manifest_files,
            kind="alert",
            profile=profile,
        )
    for variant in ("malicious", "benign"):
        content = "".join(
            json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n"
            for item in sample_telemetry_records(variant)
        )
        _write_export_file(
            root,
            f"telemetry/{variant}.jsonl",
            content,
            manifest_files,
            kind="telemetry",
            profile="generic",
        )
    readme = """# AgentSim detection and alert samples

Every record is synthetic and content-safe. Detection queries are examples that
require field mapping, tuning, benign-control validation, and human review before
use. They are not automatically deployed by AgentSim.

- `detections/`: one sample per supported output format and detection family.
- `alerts/`: six trace-linked alert records for each supported SIEM plus generic.
- `telemetry/`: malicious and benign source records for offline evaluation.
- `manifest.json`: file inventory and SHA-256 checksums.
"""
    _write_export_file(
        root,
        "README.md",
        readme,
        manifest_files,
        kind="documentation",
        profile="generic",
    )
    manifest = {
        "schema_version": SAMPLE_SCHEMA_VERSION,
        "kind": "detection-sample-export",
        "catalog_id": "agentsim.detection-samples",
        "catalog_version": "1.0.0",
        "deployment_status": "tuning_required",
        "synthetic": True,
        "content_values_recorded": False,
        "execution_performed": False,
        "sample_count": len(samples),
        "detection_file_count": sum(
            1 for item in manifest_files if item["kind"] == "detection"
        ),
        "alert_record_count": len(samples) * len(selected_alerts),
        "file_count": len(manifest_files),
        "detection_formats": list(selected_formats),
        "alert_profiles": list(selected_alerts),
        "files": sorted(manifest_files, key=lambda item: str(item["path"])),
    }
    (root / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return root


__all__ = [
    "ALERT_SAMPLE_PROFILES",
    "DETECTION_SAMPLE_FORMATS",
    "DetectionSample",
    "alert_sample_records",
    "detection_sample_catalog",
    "export_detection_sample_library",
    "load_detection_samples",
    "render_detection_sample",
    "sample_detection_pack",
    "sample_telemetry",
    "sample_telemetry_records",
]
