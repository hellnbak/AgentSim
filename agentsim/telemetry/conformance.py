"""Cross-runtime conformance checks for the portable telemetry profiles."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from agentsim.lab.reference import run_reference_fixture
from agentsim.models.agent_trace import AgentTraceEvent

from .mappings import (
    PORTABLE_PROFILES,
    PROFILE_VERSIONS,
    agent_trace_from_portable_record,
    map_agent_trace,
)


CONFORMANCE_SCHEMA_VERSION = "1.0"
_CORE_INVARIANTS = (
    "timestamp",
    "event_id",
    "event_type",
    "trace_id",
    "session_id",
    "agent_id",
    "source",
    "conversation_id",
    "agent_instance_id",
    "principal_id",
    "parent_event_id",
    "caused_by_event_ids",
    "delegation_id",
    "delegated_from_agent_id",
    "delegated_to_agent_id",
    "identity_binding_valid",
    "data_lineage_id",
    "memory_id",
    "memory_scope",
    "memory_provenance_valid",
    "memory_retention_valid",
    "goal_id",
    "goal_fingerprint",
    "goal_integrity_valid",
    "goal_change_approved",
    "tool_call_id",
    "tool_name",
    "tool_risk",
    "policy_id",
    "policy_version",
    "policy_decision",
    "input_trust",
    "taint_labels",
    "outcome",
    "synthetic",
    "content_recorded",
)


@dataclass(frozen=True)
class ConformanceFailure:
    profile: str
    event_id: str
    field: str
    expected: object
    observed: object

    def to_dict(self) -> dict[str, object]:
        return {
            "profile": self.profile,
            "event_id": self.event_id,
            "field": self.field,
            "expected": self.expected,
            "observed": self.observed,
        }


@dataclass(frozen=True)
class ProfileConformance:
    profile: str
    profile_version: str
    event_count: int
    invariant_checks: int
    native_coverage_percent: float
    failures: tuple[ConformanceFailure, ...]

    @property
    def passed(self) -> bool:
        return not self.failures

    def to_dict(self) -> dict[str, object]:
        return {
            "profile": self.profile,
            "profile_version": self.profile_version,
            "passed": self.passed,
            "event_count": self.event_count,
            "invariant_checks": self.invariant_checks,
            "native_coverage_percent": self.native_coverage_percent,
            "failures": [failure.to_dict() for failure in self.failures],
        }


@dataclass(frozen=True)
class RuntimeConformanceReport:
    fixture_id: str
    source_runtime: str
    profiles: tuple[ProfileConformance, ...]
    event_count: int

    @property
    def passed(self) -> bool:
        return bool(self.profiles) and all(profile.passed for profile in self.profiles)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": CONFORMANCE_SCHEMA_VERSION,
            "kind": "cross-runtime-fixture-conformance",
            "fixture_id": self.fixture_id,
            "source_runtime": self.source_runtime,
            "passed": self.passed,
            "event_count": self.event_count,
            "profile_count": len(self.profiles),
            "profiles": [profile.to_dict() for profile in self.profiles],
            "safety": {
                "synthetic_only": True,
                "execution_performed": False,
                "network_opened": False,
                "content_values_recorded": False,
            },
        }


def _compare(
    expected: AgentTraceEvent, observed: AgentTraceEvent, profile: str
) -> tuple[ConformanceFailure, ...]:
    failures: list[ConformanceFailure] = []
    for field in _CORE_INVARIANTS:
        wanted, actual = getattr(expected, field), getattr(observed, field)
        if wanted != actual:
            failures.append(
                ConformanceFailure(profile, expected.event_id, field, wanted, actual)
            )
    for field, wanted in expected.attributes.items():
        if observed.attributes.get(field) != wanted:
            failures.append(
                ConformanceFailure(
                    profile,
                    expected.event_id,
                    f"attributes.{field}",
                    wanted,
                    observed.attributes.get(field),
                )
            )
    return tuple(failures)


def evaluate_fixture_conformance(
    events: Sequence[AgentTraceEvent],
    *,
    fixture_id: str,
    source_runtime: str = "agentsim-reference-agent",
    profiles: Sequence[str] = PORTABLE_PROFILES,
) -> RuntimeConformanceReport:
    if not events:
        raise ValueError("fixture conformance requires at least one event")
    if len(events) > 2000:
        raise ValueError("fixture conformance is limited to 2,000 events")
    selected = tuple(dict.fromkeys(profiles))
    if not selected or any(profile not in PORTABLE_PROFILES for profile in selected):
        raise ValueError("fixture conformance profiles must be otel, ecs, or ocsf")
    results: list[ProfileConformance] = []
    for profile in selected:
        failures: list[ConformanceFailure] = []
        coverage: list[float] = []
        invariant_checks = 0
        for event in events:
            mapped = map_agent_trace(event, profile)
            coverage.append(float(mapped.to_dict()["mapping"]["native_coverage_percent"]))  # type: ignore[index]
            restored = agent_trace_from_portable_record(
                mapped.record, profile=profile, synthetic=event.synthetic
            )
            invariant_checks += len(_CORE_INVARIANTS) + len(event.attributes)
            failures.extend(_compare(event, restored, profile))
        results.append(
            ProfileConformance(
                profile,
                PROFILE_VERSIONS[profile],
                len(events),
                invariant_checks,
                round(sum(coverage) / len(coverage), 2),
                tuple(failures[:200]),
            )
        )
    return RuntimeConformanceReport(
        fixture_id,
        source_runtime,
        tuple(results),
        len(events),
    )


def run_fixture_conformance(
    fixture_id: str,
    *,
    profiles: Sequence[str] = PORTABLE_PROFILES,
) -> RuntimeConformanceReport:
    """Run a fixed reference fixture and round-trip it through each profile."""

    run = run_reference_fixture(fixture_id)
    return evaluate_fixture_conformance(
        run.events,
        fixture_id=fixture_id,
        profiles=profiles,
    )


__all__ = [
    "CONFORMANCE_SCHEMA_VERSION",
    "ConformanceFailure",
    "ProfileConformance",
    "RuntimeConformanceReport",
    "evaluate_fixture_conformance",
    "run_fixture_conformance",
]
