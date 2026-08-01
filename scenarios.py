"""Safe agentic-AI scenarios and structured ground-truth telemetry.

Scenario mode is simulation-only. It records proposed agent actions and policy
decisions but never invokes tools, reads real credentials, or opens a network
connection. Paths, tokens, endpoints, and tool definitions are synthetic.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence


SCHEMA_VERSION = "1.0"
VALIDATION_SCHEMA_VERSION = "1.0"
DEFAULT_GROUND_TRUTH_PATH = "agent_sim_events.jsonl"
DEFAULT_VALIDATION_PATH = "agent_sim_validation.json"
VALID_VARIANTS = ("malicious", "benign", "both")

LogCallback = Callable[[str], None]
StopCallback = Callable[[], bool]
Clock = Callable[[], datetime]


@dataclass(frozen=True)
class ScenarioStep:
    """One observable checkpoint in an agent workflow."""

    event_type: str
    stage: str
    message: str
    input_trust: str = "not_applicable"
    tool_name: str | None = None
    tool_action: str | None = None
    tool_risk: str = "none"
    policy_decision: str = "not_applicable"
    outcome: str = "observed"
    attributes: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class ScenarioDefinition:
    """A malicious agent workflow and its benign control run."""

    scenario_id: str
    name: str
    description: str
    risk: str
    mappings: Mapping[str, Sequence[str]]
    malicious_steps: Sequence[ScenarioStep]
    benign_steps: Sequence[ScenarioStep]

    def steps_for(self, variant: str) -> Sequence[ScenarioStep]:
        if variant == "malicious":
            return self.malicious_steps
        if variant == "benign":
            return self.benign_steps
        raise ValueError("variant must be malicious or benign")


@dataclass(frozen=True)
class ScenarioSuiteResult:
    """Artifacts and validation outcome from one scenario suite."""

    run_id: str
    ground_truth_path: Path
    validation_path: Path
    event_count: int
    check_count: int
    passed: bool
    stopped: bool


SCENARIOS: dict[str, ScenarioDefinition] = {
    "indirect-prompt-injection": ScenarioDefinition(
        scenario_id="indirect-prompt-injection",
        name="Indirect prompt injection",
        description=(
            "Correlates untrusted retrieved content with a proposed sensitive tool call."
        ),
        risk="high",
        mappings={
            "mitre_atlas": ["LLM Prompt Injection", "AI Agent Tool Invocation"],
            "owasp_agentic": ["ASI01 Agent Goal Hijack", "ASI02 Tool Misuse"],
            "nist_ai_100_2": ["Generative AI misuse attack"],
        },
        malicious_steps=(
            ScenarioStep(
                event_type="agent.input.observed",
                stage="input",
                message="Agent retrieved a synthetic document containing untrusted instructions.",
                input_trust="untrusted",
                attributes={
                    "source": "synthetic://documents/untrusted-support-note.html",
                    "content_recorded": False,
                    "content_fingerprint": "synthetic-injection-fixture-v1",
                },
            ),
            ScenarioStep(
                event_type="agent.goal.changed",
                stage="decision",
                message="Proposed plan diverged from the authorized summarization goal.",
                input_trust="untrusted",
                outcome="proposed",
                attributes={"goal_drift": True, "reasoning_content_recorded": False},
            ),
            ScenarioStep(
                event_type="agent.tool.requested",
                stage="pre_tool",
                message="Agent proposed reading a synthetic decoy credential file.",
                input_trust="untrusted",
                tool_name="filesystem.read_file",
                tool_action="read synthetic://decoy/.env",
                tool_risk="high",
                policy_decision="pending",
                outcome="proposed",
                attributes={
                    "resource": "synthetic://decoy/.env",
                    "arguments_redacted": True,
                    "data_classification": "decoy_secret",
                    "executed": False,
                },
            ),
            ScenarioStep(
                event_type="agent.policy.decision",
                stage="policy",
                message="Policy blocked the sensitive tool request before execution.",
                input_trust="untrusted",
                tool_name="filesystem.read_file",
                tool_action="read synthetic://decoy/.env",
                tool_risk="high",
                policy_decision="block",
                outcome="blocked",
                attributes={"executed": False, "control": "untrusted-input-boundary"},
            ),
        ),
        benign_steps=(
            ScenarioStep(
                event_type="agent.input.observed",
                stage="input",
                message="Agent retrieved trusted documentation for summarization.",
                input_trust="trusted",
                attributes={
                    "source": "synthetic://documents/product-guide.html",
                    "content_recorded": False,
                    "content_fingerprint": "synthetic-trusted-fixture-v1",
                },
            ),
            ScenarioStep(
                event_type="agent.goal.confirmed",
                stage="decision",
                message="Proposed plan remained within the authorized summarization goal.",
                input_trust="trusted",
                outcome="proposed",
                attributes={"goal_drift": False, "reasoning_content_recorded": False},
            ),
            ScenarioStep(
                event_type="agent.tool.requested",
                stage="pre_tool",
                message="Agent proposed reading a public synthetic fixture.",
                input_trust="trusted",
                tool_name="filesystem.read_file",
                tool_action="read synthetic://public/README.txt",
                tool_risk="low",
                policy_decision="pending",
                outcome="proposed",
                attributes={
                    "resource": "synthetic://public/README.txt",
                    "arguments_redacted": True,
                    "data_classification": "public",
                    "executed": False,
                },
            ),
            ScenarioStep(
                event_type="agent.policy.decision",
                stage="policy",
                message="Policy allowed the low-risk synthetic read.",
                input_trust="trusted",
                tool_name="filesystem.read_file",
                tool_action="read synthetic://public/README.txt",
                tool_risk="low",
                policy_decision="allow",
                outcome="simulated",
                attributes={"executed": False, "simulation_only": True},
            ),
        ),
    ),
    "mcp-tool-poisoning": ScenarioDefinition(
        scenario_id="mcp-tool-poisoning",
        name="MCP tool poisoning",
        description=(
            "Models an untrusted MCP definition expanding permissions before invocation."
        ),
        risk="high",
        mappings={
            "mitre_atlas": [
                "AI Agent Tool Poisoning",
                "AI Agent Tool Data Poisoning",
            ],
            "owasp_agentic": [
                "ASI04 Agentic Supply Chain Vulnerabilities",
                "ASI02 Tool Misuse",
            ],
            "nist_ai_100_2": ["Generative AI poisoning attack"],
        },
        malicious_steps=(
            ScenarioStep(
                event_type="agent.tool.definition_changed",
                stage="tool_discovery",
                message="Synthetic MCP tool definition changed outside the trusted baseline.",
                input_trust="untrusted",
                tool_name="mcp.synthetic.search",
                tool_risk="high",
                outcome="observed",
                attributes={
                    "old_definition_hash": "sha256:synthetic-readonly-v1",
                    "new_definition_hash": "sha256:synthetic-network-write-v2",
                    "old_capabilities": ["read"],
                    "new_capabilities": ["read", "network_write"],
                    "permission_expansion": True,
                    "signature_valid": False,
                },
            ),
            ScenarioStep(
                event_type="agent.tool.requested",
                stage="pre_tool",
                message="Agent proposed invoking the expanded MCP capability.",
                input_trust="untrusted",
                tool_name="mcp.synthetic.search",
                tool_action="publish synthetic result",
                tool_risk="high",
                policy_decision="pending",
                outcome="proposed",
                attributes={
                    "arguments_redacted": True,
                    "capability": "network_write",
                    "executed": False,
                },
            ),
            ScenarioStep(
                event_type="agent.policy.decision",
                stage="policy",
                message="Policy blocked invocation of the untrusted expanded tool.",
                input_trust="untrusted",
                tool_name="mcp.synthetic.search",
                tool_action="publish synthetic result",
                tool_risk="high",
                policy_decision="block",
                outcome="blocked",
                attributes={"executed": False, "control": "tool-definition-baseline"},
            ),
        ),
        benign_steps=(
            ScenarioStep(
                event_type="agent.tool.definition_verified",
                stage="tool_discovery",
                message="Synthetic MCP tool matched its trusted read-only baseline.",
                input_trust="trusted",
                tool_name="mcp.synthetic.search",
                tool_risk="low",
                outcome="verified",
                attributes={
                    "definition_hash": "sha256:synthetic-readonly-v1",
                    "capabilities": ["read"],
                    "permission_expansion": False,
                    "signature_valid": True,
                },
            ),
            ScenarioStep(
                event_type="agent.tool.requested",
                stage="pre_tool",
                message="Agent proposed a read-only search using the verified MCP tool.",
                input_trust="trusted",
                tool_name="mcp.synthetic.search",
                tool_action="search synthetic public catalog",
                tool_risk="low",
                policy_decision="pending",
                outcome="proposed",
                attributes={
                    "arguments_redacted": True,
                    "capability": "read",
                    "executed": False,
                },
            ),
            ScenarioStep(
                event_type="agent.policy.decision",
                stage="policy",
                message="Policy allowed the verified read-only tool request.",
                input_trust="trusted",
                tool_name="mcp.synthetic.search",
                tool_action="search synthetic public catalog",
                tool_risk="low",
                policy_decision="allow",
                outcome="simulated",
                attributes={"executed": False, "simulation_only": True},
            ),
        ),
    ),
    "decoy-secret-exfiltration": ScenarioDefinition(
        scenario_id="decoy-secret-exfiltration",
        name="Decoy secret and blocked exfiltration",
        description=(
            "Correlates synthetic secret access with a loopback-only egress request."
        ),
        risk="critical",
        mappings={
            "mitre_atlas": [
                "AI Agent Tool Credential Harvesting",
                "Exfiltration via AI Agent Tool Invocation",
            ],
            "owasp_agentic": [
                "ASI03 Identity and Privilege Abuse",
                "ASI02 Tool Misuse",
            ],
            "nist_ai_100_2": [
                "Generative AI privacy attack",
                "Generative AI misuse attack",
            ],
        },
        malicious_steps=(
            ScenarioStep(
                event_type="agent.tool.requested",
                stage="pre_tool",
                message="Agent proposed reading a synthetic decoy secret fixture.",
                input_trust="untrusted",
                tool_name="filesystem.read_file",
                tool_action="read synthetic://decoy/.env",
                tool_risk="high",
                policy_decision="allow",
                outcome="simulated",
                attributes={
                    "resource": "synthetic://decoy/.env",
                    "arguments_redacted": True,
                    "executed": False,
                    "simulation_only": True,
                },
            ),
            ScenarioStep(
                event_type="agent.tool.result",
                stage="post_tool",
                message="Synthetic result was classified as a decoy secret and redacted.",
                input_trust="untrusted",
                tool_name="filesystem.read_file",
                tool_action="read synthetic://decoy/.env",
                tool_risk="high",
                policy_decision="observe",
                outcome="simulated",
                attributes={
                    "data_classification": "decoy_secret",
                    "result_recorded": False,
                    "result_fingerprint": "sha256:synthetic-decoy-secret-v1",
                },
            ),
            ScenarioStep(
                event_type="agent.tool.requested",
                stage="pre_tool",
                message="Agent proposed encoding the synthetic result before egress.",
                input_trust="untrusted",
                tool_name="transform.base64",
                tool_action="encode redacted synthetic value",
                tool_risk="medium",
                policy_decision="observe",
                outcome="simulated",
                attributes={"arguments_redacted": True, "executed": False},
            ),
            ScenarioStep(
                event_type="agent.network.requested",
                stage="network",
                message="Policy blocked a simulated egress request to a loopback-only sink.",
                input_trust="untrusted",
                tool_name="http.request",
                tool_action="POST redacted synthetic value",
                tool_risk="high",
                policy_decision="block",
                outcome="blocked",
                attributes={
                    "destination": "http://127.0.0.1:9/agentsim-sink",
                    "network_scope": "loopback",
                    "executed": False,
                    "payload_recorded": False,
                    "data_classification": "decoy_secret",
                },
            ),
        ),
        benign_steps=(
            ScenarioStep(
                event_type="agent.tool.requested",
                stage="pre_tool",
                message="Agent proposed reading a synthetic public status fixture.",
                input_trust="trusted",
                tool_name="filesystem.read_file",
                tool_action="read synthetic://public/status.json",
                tool_risk="low",
                policy_decision="allow",
                outcome="simulated",
                attributes={
                    "resource": "synthetic://public/status.json",
                    "arguments_redacted": True,
                    "executed": False,
                    "simulation_only": True,
                },
            ),
            ScenarioStep(
                event_type="agent.tool.result",
                stage="post_tool",
                message="Synthetic result was classified as public operational data.",
                input_trust="trusted",
                tool_name="filesystem.read_file",
                tool_action="read synthetic://public/status.json",
                tool_risk="low",
                policy_decision="observe",
                outcome="simulated",
                attributes={
                    "data_classification": "public",
                    "result_recorded": False,
                    "result_fingerprint": "sha256:synthetic-public-status-v1",
                },
            ),
            ScenarioStep(
                event_type="agent.network.requested",
                stage="network",
                message="Simulated loopback health check remained within the approved scope.",
                input_trust="trusted",
                tool_name="http.request",
                tool_action="GET synthetic health status",
                tool_risk="low",
                policy_decision="allow",
                outcome="simulated",
                attributes={
                    "destination": "http://127.0.0.1:9/health",
                    "network_scope": "loopback",
                    "executed": False,
                    "payload_recorded": False,
                    "data_classification": "public",
                },
            ),
        ),
    ),
}


def list_scenarios() -> tuple[ScenarioDefinition, ...]:
    """Return scenarios in a stable display order."""

    return tuple(SCENARIOS[scenario_id] for scenario_id in sorted(SCENARIOS))


def resolve_scenario_ids(value: str | Sequence[str]) -> tuple[str, ...]:
    """Validate a scenario selection and expand the special `all` value."""

    values = (value,) if isinstance(value, str) else tuple(value)
    if values == ("all",):
        return tuple(sorted(SCENARIOS))
    unknown = [scenario_id for scenario_id in values if scenario_id not in SCENARIOS]
    if unknown:
        raise ValueError(f"unknown scenario: {', '.join(unknown)}")
    if not values:
        raise ValueError("at least one scenario is required")
    return values


def _timestamp(clock: Clock) -> str:
    value = clock()
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _variants(value: str) -> tuple[str, ...]:
    if value not in VALID_VARIANTS:
        raise ValueError(f"variant must be one of: {', '.join(VALID_VARIANTS)}")
    return ("malicious", "benign") if value == "both" else (value,)


def _pause(speed_ms: int, stop_callback: StopCallback) -> None:
    if speed_ms < 0:
        raise ValueError("speed_ms must be greater than or equal to 0")
    remaining = speed_ms / 1000.0
    while remaining > 0 and not stop_callback():
        interval = min(remaining, 0.1)
        time.sleep(interval)
        remaining -= interval


def _build_event(
    *,
    definition: ScenarioDefinition,
    variant: str,
    step: ScenarioStep,
    run_id: str,
    trace_id: str,
    sequence: int,
    parent_event_id: str | None,
    clock: Clock,
) -> dict[str, object]:
    event_id = f"{trace_id}:{sequence:03d}"
    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp": _timestamp(clock),
        "event_id": event_id,
        "parent_event_id": parent_event_id,
        "run_id": run_id,
        "trace_id": trace_id,
        "sequence": sequence,
        "producer": "AgentSim",
        "execution_mode": "simulation_only",
        "scenario_id": definition.scenario_id,
        "scenario_name": definition.name,
        "scenario_variant": variant,
        "scenario_risk": definition.risk,
        "expected_detection": variant == "malicious",
        "stage": step.stage,
        "event_type": step.event_type,
        "message": step.message,
        "input_trust": step.input_trust,
        "tool_name": step.tool_name,
        "tool_action": step.tool_action,
        "tool_risk": step.tool_risk,
        "policy_decision": step.policy_decision,
        "outcome": step.outcome,
        "attributes": dict(step.attributes),
        "mappings": {
            framework: list(values)
            for framework, values in definition.mappings.items()
        },
    }


def _events_by_trace(events: Iterable[Mapping[str, object]]) -> dict[str, list[Mapping[str, object]]]:
    traces: dict[str, list[Mapping[str, object]]] = {}
    for event in events:
        trace_id = str(event.get("trace_id", ""))
        traces.setdefault(trace_id, []).append(event)
    for trace in traces.values():
        trace.sort(key=lambda event: int(event.get("sequence", 0)))
    return traces


def _detect_indirect_prompt_injection(events: Sequence[Mapping[str, object]]) -> tuple[bool, list[str]]:
    untrusted_seen = False
    signals: list[str] = []
    detected = False
    for event in events:
        if event.get("event_type") == "agent.input.observed" and event.get(
            "input_trust"
        ) == "untrusted":
            untrusted_seen = True
            signals.append(str(event.get("event_id")))
        if (
            untrusted_seen
            and event.get("event_type") == "agent.tool.requested"
            and event.get("tool_risk") == "high"
        ):
            detected = True
            signals.append(str(event.get("event_id")))
    return detected, signals


def _detect_mcp_tool_poisoning(events: Sequence[Mapping[str, object]]) -> tuple[bool, list[str]]:
    permission_expansion = False
    signals: list[str] = []
    detected = False
    for event in events:
        attributes = event.get("attributes")
        attributes = attributes if isinstance(attributes, Mapping) else {}
        if (
            event.get("event_type") == "agent.tool.definition_changed"
            and attributes.get("permission_expansion") is True
            and attributes.get("signature_valid") is False
        ):
            permission_expansion = True
            signals.append(str(event.get("event_id")))
        if permission_expansion and event.get("event_type") == "agent.tool.requested":
            detected = True
            signals.append(str(event.get("event_id")))
    return detected, signals


def _detect_decoy_secret_exfiltration(events: Sequence[Mapping[str, object]]) -> tuple[bool, list[str]]:
    secret_seen = False
    signals: list[str] = []
    detected = False
    for event in events:
        attributes = event.get("attributes")
        attributes = attributes if isinstance(attributes, Mapping) else {}
        if (
            event.get("event_type") == "agent.tool.result"
            and attributes.get("data_classification") == "decoy_secret"
        ):
            secret_seen = True
            signals.append(str(event.get("event_id")))
        if (
            secret_seen
            and event.get("event_type") == "agent.network.requested"
            and event.get("policy_decision") == "block"
            and attributes.get("executed") is False
        ):
            detected = True
            signals.append(str(event.get("event_id")))
    return detected, signals


DETECTORS = {
    "indirect-prompt-injection": _detect_indirect_prompt_injection,
    "mcp-tool-poisoning": _detect_mcp_tool_poisoning,
    "decoy-secret-exfiltration": _detect_decoy_secret_exfiltration,
}


def validate_events(
    events: Sequence[Mapping[str, object]],
    *,
    clock: Clock | None = None,
) -> dict[str, object]:
    """Evaluate malicious traces and benign controls with deterministic checks."""

    clock = clock or (lambda: datetime.now(timezone.utc))
    results: list[dict[str, object]] = []
    for trace in _events_by_trace(events).values():
        if not trace:
            continue
        scenario_id = str(trace[0].get("scenario_id", ""))
        variant = str(trace[0].get("scenario_variant", ""))
        detector = DETECTORS.get(scenario_id)
        if detector is None:
            detected, signals = False, []
        else:
            detected, signals = detector(trace)
        expected = variant == "malicious"
        results.append(
            {
                "scenario_id": scenario_id,
                "scenario_name": trace[0].get("scenario_name"),
                "variant": variant,
                "trace_id": trace[0].get("trace_id"),
                "expected_detected": expected,
                "detected": detected,
                "passed": detected == expected,
                "signal_event_ids": signals,
            }
        )

    passed_count = sum(1 for result in results if result["passed"])
    return {
        "schema_version": VALIDATION_SCHEMA_VERSION,
        "generated_at": _timestamp(clock),
        "summary": {
            "checks": len(results),
            "passed": passed_count,
            "failed": len(results) - passed_count,
            "all_passed": bool(results) and passed_count == len(results),
        },
        "results": results,
    }


def load_ground_truth(path: str | Path) -> list[dict[str, object]]:
    """Load and minimally validate an AgentSim JSONL ground-truth file."""

    events: list[dict[str, object]] = []
    with Path(path).open("r", encoding="utf-8") as input_file:
        for line_number, line in enumerate(input_file, start=1):
            if not line.strip():
                continue
            event = json.loads(line)
            if not isinstance(event, dict) or event.get("schema_version") != SCHEMA_VERSION:
                raise ValueError(f"invalid ground-truth event on line {line_number}")
            events.append(event)
    return events


def run_scenario_suite(
    scenario_ids: str | Sequence[str],
    *,
    variant: str = "both",
    ground_truth_path: str | Path = DEFAULT_GROUND_TRUTH_PATH,
    validation_path: str | Path = DEFAULT_VALIDATION_PATH,
    speed_ms: int = 0,
    log_callback: LogCallback | None = None,
    stop_callback: StopCallback | None = None,
    run_id: str | None = None,
    clock: Clock | None = None,
) -> ScenarioSuiteResult:
    """Run safe scenarios, write JSONL ground truth, and validate benign controls."""

    if isinstance(speed_ms, bool) or not isinstance(speed_ms, int) or speed_ms < 0:
        raise ValueError("speed_ms must be an integer greater than or equal to 0")
    selected_ids = resolve_scenario_ids(scenario_ids)
    selected_variants = _variants(variant)
    output_path = Path(ground_truth_path).expanduser()
    report_path = Path(validation_path).expanduser()
    for artifact_path in (output_path, report_path):
        if not artifact_path.parent.exists():
            raise FileNotFoundError(
                f"output directory does not exist: {artifact_path.parent}"
            )

    log = log_callback or print
    should_stop = stop_callback or (lambda: False)
    clock = clock or (lambda: datetime.now(timezone.utc))
    suite_run_id = run_id or uuid.uuid4().hex
    events: list[dict[str, object]] = []
    stopped = False

    log(
        f"[*] Starting safe agentic scenario suite. "
        f"Scenarios: {len(selected_ids)}; variants: {', '.join(selected_variants)}."
    )
    log("[*] Scenario mode is simulation-only; no tools or network calls execute.")

    try:
        for scenario_id in selected_ids:
            definition = SCENARIOS[scenario_id]
            for selected_variant in selected_variants:
                if should_stop():
                    stopped = True
                    break
                trace_id = f"{suite_run_id}:{scenario_id}:{selected_variant}"
                parent_event_id: str | None = None
                log(f"[SCENARIO] {definition.name} [{selected_variant}]")
                for sequence, step in enumerate(
                    definition.steps_for(selected_variant), start=1
                ):
                    if should_stop():
                        stopped = True
                        break
                    event = _build_event(
                        definition=definition,
                        variant=selected_variant,
                        step=step,
                        run_id=suite_run_id,
                        trace_id=trace_id,
                        sequence=sequence,
                        parent_event_id=parent_event_id,
                        clock=clock,
                    )
                    events.append(event)
                    parent_event_id = str(event["event_id"])
                    log(f"    [{step.stage}] {step.message}")
                    _pause(speed_ms, should_stop)
                if stopped:
                    break
            if stopped:
                break
    except KeyboardInterrupt:
        stopped = True

    with output_path.open("w", encoding="utf-8") as output_file:
        for event in events:
            json.dump(event, output_file, separators=(",", ":"), sort_keys=True)
            output_file.write("\n")

    validation = validate_events(events, clock=clock)
    validation["run_id"] = suite_run_id
    validation["ground_truth_file"] = output_path.name
    validation["stopped"] = stopped
    with report_path.open("w", encoding="utf-8") as report_file:
        json.dump(validation, report_file, indent=2, sort_keys=True)
        report_file.write("\n")

    summary = validation["summary"]
    assert isinstance(summary, dict)
    passed = bool(summary["all_passed"]) and not stopped
    log(f"[+] Ground-truth JSONL exported to '{output_path}'")
    log(f"[+] Validation report exported to '{report_path}'")
    if stopped:
        log("[!] Scenario suite stopped; artifacts contain the completed checkpoints.")
    elif passed:
        log(
            f"[+] Scenario validation passed: {summary['passed']}/{summary['checks']} checks."
        )
    else:
        log(
            f"[!] Scenario validation failed: {summary['failed']}/{summary['checks']} checks."
        )

    return ScenarioSuiteResult(
        run_id=suite_run_id,
        ground_truth_path=output_path,
        validation_path=report_path,
        event_count=len(events),
        check_count=int(summary["checks"]),
        passed=passed,
        stopped=stopped,
    )
