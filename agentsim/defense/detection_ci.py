"""Detection CI gates for agent-runtime baseline and candidate recordings."""

from __future__ import annotations

import hashlib
import json
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping, Sequence

from agentsim.detection.packs import DetectionPack, DetectionSweepReport, sweep_detection_pack
from agentsim.models.telemetry import NormalizedEvent
from agentsim.telemetry.assurance import TelemetryAssuranceReport, assess_telemetry
from agentsim.telemetry.flight_recorder import FlightRecorderBundle
from agentsim.telemetry.investigation import InvestigationReport, investigate_telemetry


DETECTION_CI_SCHEMA_VERSION = "1.0"
_STATUS_RANK = {"clean": 0, "healthy": 0, "review": 1, "degraded": 1, "elevated": 2, "critical": 3, "unusable": 3}
_PENALTY = {"critical": 35, "high": 20, "medium": 8, "low": 3}


@dataclass(frozen=True)
class DetectionCiTransition:
    rule_id: str
    severity: str
    baseline_status: str
    candidate_status: str
    change: str
    baseline_field_coverage_percent: float
    candidate_field_coverage_percent: float
    missing_fields: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class DetectionCiFinding:
    finding_id: str
    code: str
    severity: str
    title: str
    rule_id: str | None
    baseline: object
    candidate: object
    remediation: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class DetectionCiReport:
    report_id: str
    expected_classification: str
    pack_id: str
    pack_version: str
    status: str
    score: int
    baseline: Mapping[str, object]
    candidate: Mapping[str, object]
    transitions: tuple[DetectionCiTransition, ...]
    findings: tuple[DetectionCiFinding, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": DETECTION_CI_SCHEMA_VERSION,
            "kind": "agent-detection-ci-report",
            "report_id": self.report_id,
            "expected_classification": self.expected_classification,
            "pack_id": self.pack_id,
            "pack_version": self.pack_version,
            "status": self.status,
            "score": self.score,
            "summary": {
                "regressions": sum(item.change == "regressed" for item in self.transitions),
                "improvements": sum(item.change == "improved" for item in self.transitions),
                "changed": sum(item.change == "changed" for item in self.transitions),
                "unchanged": sum(item.change == "unchanged" for item in self.transitions),
                "findings": len(self.findings),
                "blocking_findings": sum(
                    item.severity in {"critical", "high"} for item in self.findings
                ),
            },
            "baseline": dict(self.baseline),
            "candidate": dict(self.candidate),
            "transitions": [item.to_dict() for item in self.transitions],
            "findings": [item.to_dict() for item in self.findings],
            "ground_truth_source": "explicit_expected_classification",
            "content_values_recorded": False,
        }

    def to_markdown(self) -> str:
        lines = [
            "# AgentSim Detection CI",
            "",
            f"**Status:** {self.status.upper()}  ",
            f"**Score:** {self.score}/100  ",
            f"**Expected class:** {self.expected_classification}  ",
            f"**Detection pack:** `{self.pack_id}` `{self.pack_version}`",
            "",
            "## Findings",
            "",
        ]
        if not self.findings:
            lines.append("No detection or telemetry regressions were found.")
        for finding in self.findings:
            target = f" (`{finding.rule_id}`)" if finding.rule_id else ""
            lines.append(f"- **{finding.severity.upper()}** {finding.title}{target}")
        lines.extend(
            [
                "",
                "## Rule transitions",
                "",
                "| Rule | Baseline | Candidate | Change | Field coverage |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for item in self.transitions:
            lines.append(
                f"| `{item.rule_id}` | {item.baseline_status} | {item.candidate_status} | "
                f"{item.change} | {item.baseline_field_coverage_percent:.1f}% → "
                f"{item.candidate_field_coverage_percent:.1f}% |"
            )
        lines.extend(
            [
                "",
                "_This report contains structural telemetry and identifiers only; content values were not recorded._",
                "",
            ]
        )
        return "\n".join(lines)

    def to_junit(self) -> str:
        suite = ET.Element(
            "testsuite",
            {
                "name": "agentsim-detection-ci",
                "tests": str(max(1, len(self.transitions))),
                "failures": str(sum(item.change == "regressed" for item in self.transitions)),
            },
        )
        if not self.transitions:
            ET.SubElement(suite, "testcase", {"name": "no-rules"})
        for item in self.transitions:
            case = ET.SubElement(suite, "testcase", {"name": item.rule_id})
            if item.change == "regressed":
                failure = ET.SubElement(case, "failure", {"message": "detection regression"})
                failure.text = f"{item.baseline_status} -> {item.candidate_status}"
        return ET.tostring(suite, encoding="unicode") + "\n"

    def to_sarif(self) -> dict[str, object]:
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AgentSim Detection CI",
                            "version": self.pack_version,
                            "rules": [
                                {
                                    "id": finding.code,
                                    "name": finding.code,
                                    "shortDescription": {"text": finding.title},
                                }
                                for finding in self.findings
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": finding.code,
                            "level": "error"
                            if finding.severity in {"critical", "high"}
                            else "warning",
                            "message": {
                                "text": finding.title
                                + (f" ({finding.rule_id})" if finding.rule_id else "")
                            },
                            "properties": {
                                "severity": finding.severity,
                                "content_values_recorded": False,
                            },
                        }
                        for finding in self.findings
                    ],
                }
            ],
        }

    def write_artifacts(
        self,
        *,
        json_path: str | Path,
        markdown_path: str | Path | None = None,
        junit_path: str | Path | None = None,
        sarif_path: str | Path | None = None,
    ) -> tuple[Path, ...]:
        outputs: list[Path] = []

        def write(path: str | Path, content: str) -> None:
            candidate = Path(path)
            candidate.parent.mkdir(parents=True, exist_ok=True)
            candidate.write_text(content, encoding="utf-8")
            outputs.append(candidate)

        write(json_path, json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n")
        if markdown_path:
            write(markdown_path, self.to_markdown())
        if junit_path:
            write(junit_path, self.to_junit())
        if sarif_path:
            write(sarif_path, json.dumps(self.to_sarif(), indent=2, sort_keys=True) + "\n")
        return tuple(outputs)


def _summary(
    events: Sequence[NormalizedEvent],
    assurance: TelemetryAssuranceReport,
    investigation: InvestigationReport,
    sweep: DetectionSweepReport,
) -> dict[str, object]:
    values = sweep.to_dict()
    return {
        "events": len(events),
        "traces": assurance.trace_count,
        "agents": investigation.agent_count,
        "assurance_status": assurance.status,
        "assurance_score": assurance.score,
        "investigation_status": investigation.status,
        "investigation_score": investigation.score,
        "detections": dict(values["summary"]),
        "content_values_recorded": False,
    }


def evaluate_detection_ci(
    baseline_events: Sequence[NormalizedEvent],
    candidate_events: Sequence[NormalizedEvent],
    *,
    pack: DetectionPack,
    expected_classification: str,
    baseline_id: str = "baseline",
    candidate_id: str = "candidate",
    max_assurance_drop: int = 5,
    min_event_retention: float = 0.8,
) -> DetectionCiReport:
    if expected_classification not in {"malicious", "benign", "unknown"}:
        raise ValueError("expected_classification must be malicious, benign, or unknown")
    if (
        isinstance(max_assurance_drop, bool)
        or not isinstance(max_assurance_drop, int)
        or max_assurance_drop < 0
    ):
        raise ValueError("max_assurance_drop must be a non-negative integer")
    if (
        isinstance(min_event_retention, bool)
        or not isinstance(min_event_retention, (int, float))
        or not 0 <= min_event_retention <= 1
    ):
        raise ValueError("min_event_retention must be between 0 and 1")

    baseline_assurance = assess_telemetry(baseline_events)
    candidate_assurance = assess_telemetry(candidate_events)
    baseline_investigation = investigate_telemetry(baseline_events)
    candidate_investigation = investigate_telemetry(candidate_events)
    baseline_sweep = sweep_detection_pack(pack, baseline_events)
    candidate_sweep = sweep_detection_pack(pack, candidate_events)
    baseline_by_rule = {item.rule_id: item for item in baseline_sweep.outcomes}
    candidate_by_rule = {item.rule_id: item for item in candidate_sweep.outcomes}
    transitions: list[DetectionCiTransition] = []
    findings: list[DetectionCiFinding] = []

    def finding(
        code: str,
        severity: str,
        title: str,
        *,
        rule_id: str | None = None,
        baseline: object,
        candidate: object,
        remediation: Sequence[str],
    ) -> None:
        findings.append(
            DetectionCiFinding(
                f"CI-{len(findings) + 1:04d}",
                code,
                severity,
                title,
                rule_id,
                baseline,
                candidate,
                tuple(remediation),
            )
        )

    for rule_id in sorted(baseline_by_rule):
        before = baseline_by_rule[rule_id]
        after = candidate_by_rule[rule_id]
        change = "unchanged"
        if before.status != after.status:
            if after.status == "visibility_gap" and before.status != "visibility_gap":
                change = "regressed"
                finding(
                    "new_visibility_gap",
                    "high",
                    "Candidate telemetry introduced a detection visibility gap",
                    rule_id=rule_id,
                    baseline=before.status,
                    candidate=after.status,
                    remediation=("Restore the missing fields or source before merging the agent change.",),
                )
            elif before.status == "visibility_gap" and after.status != "visibility_gap":
                change = "improved"
            elif expected_classification == "malicious":
                change = "regressed" if before.status == "detected" else "improved"
                if change == "regressed":
                    finding(
                        "malicious_detection_lost",
                        "critical",
                        "Candidate lost a malicious baseline detection",
                        rule_id=rule_id,
                        baseline=before.status,
                        candidate=after.status,
                        remediation=("Restore the causal signal or update the reviewed rule before merging.",),
                    )
            elif expected_classification == "benign":
                change = "regressed" if after.status == "detected" else "improved"
                if change == "regressed":
                    finding(
                        "new_benign_detection",
                        "high",
                        "Candidate introduced a benign baseline detection",
                        rule_id=rule_id,
                        baseline=before.status,
                        candidate=after.status,
                        remediation=("Retune the rule against the benign twin without suppressing malicious coverage.",),
                    )
            else:
                change = "changed"
                finding(
                    "unclassified_detection_change",
                    "medium",
                    "Detection behavior changed for an unclassified recording",
                    rule_id=rule_id,
                    baseline=before.status,
                    candidate=after.status,
                    remediation=("Assign an expected classification and review the transition.",),
                )
        missing_fields = tuple(sorted(set(after.missing_fields) - set(before.missing_fields)))
        transitions.append(
            DetectionCiTransition(
                rule_id,
                after.severity,
                before.status,
                after.status,
                change,
                before.field_coverage_percent,
                after.field_coverage_percent,
                missing_fields,
            )
        )

    assurance_drop = baseline_assurance.score - candidate_assurance.score
    if assurance_drop > max_assurance_drop:
        finding(
            "telemetry_assurance_regression",
            "high" if assurance_drop >= 15 else "medium",
            "Candidate telemetry assurance score regressed",
            baseline=baseline_assurance.score,
            candidate=candidate_assurance.score,
            remediation=("Repair timestamp, identity, causal-link, or redaction provenance before merging.",),
        )
    if _STATUS_RANK[candidate_investigation.status] > _STATUS_RANK[baseline_investigation.status]:
        finding(
            "agent_invariant_regression",
            "high",
            "Candidate introduced a more severe agent invariant state",
            baseline=baseline_investigation.status,
            candidate=candidate_investigation.status,
            remediation=("Review the new identity, delegation, goal, memory, or policy findings.",),
        )
    retention = len(candidate_events) / len(baseline_events) if baseline_events else 1.0
    if retention < min_event_retention:
        finding(
            "event_retention_regression",
            "high",
            "Candidate retained too few defensive checkpoints",
            baseline=len(baseline_events),
            candidate=len(candidate_events),
            remediation=("Restore lifecycle instrumentation or document intentionally removed checkpoints.",),
        )

    if any(item.severity in {"critical", "high"} for item in findings):
        status = "block"
    elif findings:
        status = "review"
    else:
        status = "pass"
    score = max(0, 100 - sum(_PENALTY[item.severity] for item in findings))
    report_key = {
        "baseline": baseline_id,
        "candidate": candidate_id,
        "pack": f"{pack.pack_id}:{pack.version}",
        "classification": expected_classification,
        "transitions": [item.to_dict() for item in transitions],
    }
    return DetectionCiReport(
        report_id="dci-" + hashlib.sha256(
            json.dumps(report_key, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()[:24],
        expected_classification=expected_classification,
        pack_id=pack.pack_id,
        pack_version=pack.version,
        status=status,
        score=score,
        baseline={
            "recording_id": baseline_id,
            **_summary(
                baseline_events, baseline_assurance, baseline_investigation, baseline_sweep
            ),
        },
        candidate={
            "recording_id": candidate_id,
            **_summary(
                candidate_events, candidate_assurance, candidate_investigation, candidate_sweep
            ),
        },
        transitions=tuple(transitions),
        findings=tuple(findings),
    )


def compare_flight_bundles(
    baseline: FlightRecorderBundle,
    candidate: FlightRecorderBundle,
    *,
    pack: DetectionPack,
    expected_classification: str | None = None,
    max_assurance_drop: int = 5,
    min_event_retention: float = 0.8,
) -> DetectionCiReport:
    classification = expected_classification or baseline.classification
    if classification == "unknown" and candidate.classification != "unknown":
        classification = candidate.classification
    if (
        baseline.classification != "unknown"
        and candidate.classification != "unknown"
        and baseline.classification != candidate.classification
    ):
        raise ValueError("baseline and candidate flight classifications must match")
    return evaluate_detection_ci(
        baseline.normalized_events,
        candidate.normalized_events,
        pack=pack,
        expected_classification=classification,
        baseline_id=baseline.recorder_id,
        candidate_id=candidate.recorder_id,
        max_assurance_drop=max_assurance_drop,
        min_event_retention=min_event_retention,
    )


__all__ = [
    "DetectionCiFinding",
    "DetectionCiReport",
    "DetectionCiTransition",
    "compare_flight_bundles",
    "evaluate_detection_ci",
]
