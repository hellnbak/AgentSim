"""AgentSim simulation engine and command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import platform
import random
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Sequence

from scenarios import (
    DEFAULT_BUNDLE_PATH,
    DEFAULT_COVERAGE_PATH,
    DEFAULT_GROUND_TRUTH_PATH,
    DEFAULT_JUNIT_PATH,
    DEFAULT_OTEL_PATH,
    DEFAULT_SARIF_PATH,
    DEFAULT_VALIDATION_PATH,
    list_scenarios,
    load_scenario_registry,
    run_scenario_suite,
)
from mcp_lab import DEFAULT_MCP_LAB_PATH, run_mcp_lab
from tactics import SIMULATION_PHASES, LINUX_HALLUCINATIONS, WINDOWS_HALLUCINATIONS


__version__ = "0.3.0"
ATTACK_VERSION = "19.1"
NAVIGATOR_VERSION = "5.3.2"
LAYER_VERSION = "4.5"
NETWORK_PHASE = "Phase 3: Cloud Service Discovery"
TECHNIQUE_ID_PATTERN = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")

LogCallback = Callable[[str], None]
StopCallback = Callable[[], bool]
Action = dict[str, object]


def _validate_integer(name: str, value: int, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name} must be an integer greater than or equal to {minimum}")
    return value


def _validate_probability(name: str, value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number between 0.0 and 1.0")
    value = float(value)
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be between 0.0 and 1.0")
    return value


class AgentSim:
    """Simulate the command-selection patterns of a looping autonomous agent."""

    def __init__(
        self,
        speed_ms: int = 100,
        hallucination_rate: float = 0.15,
        context_loss_rate: float = 0.05,
        error_retry_rate: float = 0.30,
        evasion_rate: float = 0.10,
        log_callback: LogCallback | None = None,
        *,
        allow_network: bool = False,
        dry_run: bool = False,
        output_path: str | os.PathLike[str] = "agent_sim_layer.json",
        seed: int | None = None,
        os_type: str | None = None,
        command_timeout: float = 5.0,
        stop_callback: StopCallback | None = None,
    ) -> None:
        self.speed_ms = _validate_integer("speed_ms", speed_ms, 0)
        self.hallucination_rate = _validate_probability(
            "hallucination_rate", hallucination_rate
        )
        self.context_loss_rate = _validate_probability(
            "context_loss_rate", context_loss_rate
        )
        self.error_retry_rate = _validate_probability(
            "error_retry_rate", error_retry_rate
        )
        self.evasion_rate = _validate_probability("evasion_rate", evasion_rate)
        if not isinstance(command_timeout, (int, float)) or command_timeout <= 0:
            raise ValueError("command_timeout must be greater than 0")

        self.allow_network = bool(allow_network)
        self.dry_run = bool(dry_run)
        self.output_path = Path(output_path)
        self.command_timeout = float(command_timeout)
        self.log_callback = log_callback or print
        self.stop_callback = stop_callback or (lambda: False)
        self.random = random.Random(seed)
        self.executed_tactics: set[str] = set()
        self.recent_tactics: list[str] = []

        detected_os = os_type or self._detect_os()
        if detected_os not in {"Windows", "Linux", "macOS"}:
            raise ValueError("os_type must be one of: Windows, Linux, macOS")
        self.os_type = detected_os

        self.log_callback(f"[*] Detected OS: {self.os_type}")
        if self.dry_run:
            self.log_callback("[*] Dry-run mode enabled; no commands will be executed.")
        elif not self.allow_network:
            self.log_callback(
                "[*] Network access disabled; cloud CLI actions will be skipped."
            )

        self.action_space = self._build_action_space()

    @staticmethod
    def _detect_os() -> str:
        raw_os = platform.system()
        if raw_os == "Windows":
            return "Windows"
        if raw_os == "Darwin":
            return "macOS"
        if raw_os == "Linux":
            return "Linux"
        raise RuntimeError(f"unsupported operating system: {raw_os or 'unknown'}")

    def _build_action_space(self) -> list[Action]:
        space: list[Action] = []
        for phase, os_dict in SIMULATION_PHASES.items():
            for tactic, shells in os_dict.get(self.os_type, {}).items():
                for shell, commands in shells.items():
                    for command in commands:
                        space.append(
                            {
                                "phase": phase,
                                "tactic": tactic,
                                "shell": shell,
                                "command": command,
                                "requires_network": phase == NETWORK_PHASE,
                            }
                        )
        return space

    def _build_command(self, shell: str, command: str, evade: bool) -> list[str]:
        if self.os_type == "Windows":
            if evade:
                nested_command = subprocess.list2cmdline(
                    ["cmd.exe", "/d", "/s", "/c", command]
                )
                return [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    nested_command,
                ]
            if shell == "powershell":
                return [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    command,
                ]
            return ["cmd.exe", "/d", "/s", "/c", command]

        if evade:
            return [
                "/bin/sh",
                "-c",
                f"/bin/bash -c {shlex.quote(command)}",
            ]
        return ["/bin/bash", "-c", command]

    def _execute_command(self, shell: str, command: str, evade: bool = False) -> str:
        if self.dry_run:
            return ""

        full_command = self._build_command(shell, command, evade)
        try:
            result = subprocess.run(
                full_command,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=self.command_timeout,
                check=False,
            )
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return f"command timed out after {self.command_timeout:g} seconds"
        except OSError as exc:
            return f"unable to execute command: {exc}"

    def _simulate_hallucination(self) -> Action:
        if self.os_type == "Windows":
            return {
                "tactic": "Hallucination",
                "shell": "cmd",
                "command": self.random.choice(LINUX_HALLUCINATIONS),
                "requires_network": False,
            }
        return {
            "tactic": "Hallucination",
            "shell": "bash",
            "command": self.random.choice(WINDOWS_HALLUCINATIONS),
            "requires_network": False,
        }

    def _run_action(self, action: Action, evade: bool) -> str | None:
        command = str(action["command"])
        shell = str(action["shell"])
        requires_network = bool(action.get("requires_network", False))

        if requires_network and not self.allow_network and not self.dry_run:
            self.log_callback(
                f"[!] SKIPPED NETWORK ACTION: {command} "
                "(use --allow-network to opt in)"
            )
            return None

        tactic = str(action["tactic"])
        if TECHNIQUE_ID_PATTERN.search(tactic):
            self.executed_tactics.add(tactic)

        verb = "WOULD EXECUTE" if self.dry_run else "EXECUTING"
        self.log_callback(f"[*] {verb}: {command} ({shell})")
        return self._execute_command(shell, command, evade)

    def _simulate_context_loss(self) -> None:
        self.log_callback("[!] CONTEXT LOSS: Re-establishing baseline...")
        self.recent_tactics.clear()
        baseline: Action = {
            "phase": "Baseline",
            "tactic": "T1033 - System Owner/User Discovery",
            "shell": "cmd" if self.os_type == "Windows" else "bash",
            "command": "whoami",
            "requires_network": False,
        }
        self._run_action(baseline, evade=False)
        self._pause()

    def _pause(self) -> None:
        remaining = self.speed_ms / 1000.0
        while remaining > 0 and not self.stop_callback():
            interval = min(remaining, 0.1)
            time.sleep(interval)
            remaining -= interval

    @staticmethod
    def _looks_like_command_error(output: str) -> bool:
        lowered = output.lower()
        return any(
            marker in lowered
            for marker in (
                "not recognized",
                "command not found",
                "no such file or directory",
                "unable to execute command",
            )
        )

    @staticmethod
    def _looks_like_access_error(output: str) -> bool:
        lowered = output.lower()
        return "access is denied" in lowered or "permission denied" in lowered

    def _generate_attack_navigator_layer(self) -> Path:
        techniques = []
        for tactic_label in sorted(self.executed_tactics):
            match = TECHNIQUE_ID_PATTERN.search(tactic_label)
            if match:
                techniques.append(
                    {
                        "techniqueID": match.group(1),
                        "tactic": "discovery",
                        "score": 100,
                        "comment": tactic_label,
                    }
                )

        layer = {
            "name": "AgentSim Execution Layer",
            "versions": {
                "attack": ATTACK_VERSION,
                "navigator": NAVIGATOR_VERSION,
                "layer": LAYER_VERSION,
            },
            "domain": "enterprise-attack",
            "description": "ATT&CK techniques simulated by AgentSim",
            "techniques": techniques,
            "gradient": {
                "colors": ["#ffe766", "#ffaf66"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [
                {"label": "Simulated by AgentSim", "color": "#ffaf66"}
            ],
        }

        output_path = self.output_path.expanduser()
        if not output_path.parent.exists():
            raise FileNotFoundError(
                f"output directory does not exist: {output_path.parent}"
            )
        with output_path.open("w", encoding="utf-8") as output_file:
            json.dump(layer, output_file, indent=2)
            output_file.write("\n")

        self.log_callback(
            f"\n[+] MITRE ATT&CK Navigator layer exported to '{output_path}'"
        )
        return output_path

    def run_simulation(self, total_iterations: int) -> Path:
        total_iterations = _validate_integer("total_iterations", total_iterations, 1)
        phases = tuple(SIMULATION_PHASES)
        self.log_callback(f"[*] Starting AgentSim. Target: {total_iterations} cycles.")

        previous_phase: str | None = None
        for index in range(total_iterations):
            if self.stop_callback():
                self.log_callback(
                    "[!] STOP REQUESTED: Exporting the partial simulation layer."
                )
                break
            phase_index = min(index * len(phases) // total_iterations, len(phases) - 1)
            current_phase = phases[phase_index]
            if previous_phase is not None and current_phase != previous_phase:
                self.log_callback(f"\n[=== PHASE TRANSITION: {current_phase} ===]")
                self.recent_tactics.clear()
            previous_phase = current_phase

            self.log_callback(f"\n--- Agent Cycle {index + 1} ({current_phase}) ---")
            if self.random.random() < self.context_loss_rate:
                self._simulate_context_loss()
                continue

            phase_actions = [
                action
                for action in self.action_space
                if action["phase"] == current_phase
            ]
            if not phase_actions:
                self.log_callback("[!] No actions found for this phase. Exiting.")
                break

            action = self.random.choice(phase_actions)
            retry_count = 0
            while (
                action["tactic"] in self.recent_tactics
                and self.random.random() < 0.5
                and retry_count < 10
            ):
                action = self.random.choice(phase_actions)
                retry_count += 1

            self.recent_tactics.append(str(action["tactic"]))
            if len(self.recent_tactics) > 3:
                self.recent_tactics.pop(0)

            evade = self.random.random() < self.evasion_rate
            if evade:
                self.log_callback("[!] EVASION: Wrapping command in nested shell...")

            if self.random.random() < self.hallucination_rate:
                hallucination = self._simulate_hallucination()
                self.log_callback(
                    f"[!] HALLUCINATION: {hallucination['command']} "
                    f"({hallucination['shell']})"
                )
                output = self._execute_command(
                    str(hallucination["shell"]),
                    str(hallucination["command"]),
                    evade,
                )
                if self._looks_like_command_error(output):
                    self.log_callback(
                        "[*] PARSING LOOP: Error detected. Correcting and retrying..."
                    )
                    self._pause()
                    retry_action = self.random.choice(phase_actions)
                    self.log_callback(
                        "    [Reasoning] Retrying with compatible command."
                    )
                    self._run_action(retry_action, evade)
            else:
                output = self._run_action(action, evade)
                if (
                    output is not None
                    and self._looks_like_access_error(output)
                    and self.random.random() < self.error_retry_rate
                ):
                    self.log_callback(
                        "[*] PARSING LOOP: Access denied. Pivoting to alternative method..."
                    )
                    self._pause()
                    if self.os_type == "Windows":
                        alternatives = [
                            candidate
                            for candidate in phase_actions
                            if candidate["shell"] == "powershell"
                            and candidate != action
                        ]
                    else:
                        alternatives = [
                            candidate for candidate in phase_actions if candidate != action
                        ]
                    if alternatives:
                        retry_action = self.random.choice(alternatives)
                        self.log_callback(
                            "    [Reasoning] Trying an alternative command."
                        )
                        self._run_action(retry_action, evade)

            self._pause()

        return self._generate_attack_navigator_layer()


def _probability_argument(value: str) -> float:
    try:
        return _validate_probability("value", float(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _nonnegative_integer(value: str) -> int:
    try:
        return _validate_integer("value", int(value), 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _positive_integer(value: str) -> int:
    try:
        return _validate_integer("value", int(value), 1)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "AgentSim: simulate autonomous-agent command patterns for detection "
            "engineering. Local read-only commands execute by default."
        )
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    scenario_group = parser.add_argument_group("safe agentic scenario lab")
    scenario_group.add_argument(
        "--list-scenarios",
        action="store_true",
        help="List the simulation-only agentic scenarios and exit.",
    )
    scenario_group.add_argument(
        "--scenario",
        metavar="ID|all",
        help="Run one safe agentic scenario, or all scenarios, instead of command simulation.",
    )
    scenario_group.add_argument(
        "--scenario-pack",
        action="append",
        default=[],
        metavar="PATH",
        help=(
            "Load a declarative JSON scenario pack or directory. Repeat to load "
            "multiple packs; built-in packs remain enabled."
        ),
    )
    scenario_group.add_argument(
        "--variant",
        choices=("malicious", "benign", "both"),
        default="both",
        help="Scenario variant to emit (default: both malicious and benign controls).",
    )
    scenario_group.add_argument(
        "--ground-truth-output",
        default=DEFAULT_GROUND_TRUTH_PATH,
        metavar="PATH",
        help=f"Scenario JSONL output path (default: {DEFAULT_GROUND_TRUTH_PATH}).",
    )
    scenario_group.add_argument(
        "--validation-output",
        default=DEFAULT_VALIDATION_PATH,
        metavar="PATH",
        help=f"Scenario validation report path (default: {DEFAULT_VALIDATION_PATH}).",
    )
    scenario_group.add_argument(
        "--mutations",
        type=_nonnegative_integer,
        default=0,
        metavar="COUNT",
        help="Generate semantic-preserving mutations per malicious/benign trace (0-100).",
    )
    scenario_group.add_argument(
        "--mutation-seed",
        type=int,
        help="Random seed for reproducible scenario mutations.",
    )
    scenario_group.add_argument(
        "--junit-output",
        default=DEFAULT_JUNIT_PATH,
        metavar="PATH",
        help=f"JUnit XML benchmark output (default: {DEFAULT_JUNIT_PATH}).",
    )
    scenario_group.add_argument(
        "--sarif-output",
        default=DEFAULT_SARIF_PATH,
        metavar="PATH",
        help=f"SARIF benchmark output (default: {DEFAULT_SARIF_PATH}).",
    )
    scenario_group.add_argument(
        "--otel-output",
        default=DEFAULT_OTEL_PATH,
        metavar="PATH",
        help=f"OpenTelemetry-compatible log output (default: {DEFAULT_OTEL_PATH}).",
    )
    scenario_group.add_argument(
        "--coverage-output",
        default=DEFAULT_COVERAGE_PATH,
        metavar="PATH",
        help=f"Framework and detector coverage report (default: {DEFAULT_COVERAGE_PATH}).",
    )
    scenario_group.add_argument(
        "--bundle-output",
        default=DEFAULT_BUNDLE_PATH,
        metavar="PATH",
        help=f"ZIP evidence bundle output (default: {DEFAULT_BUNDLE_PATH}).",
    )
    scenario_group.add_argument(
        "--mcp-lab",
        action="store_true",
        help="Run the in-memory MCP authorization boundary lab and exit.",
    )
    scenario_group.add_argument(
        "--mcp-lab-output",
        default=DEFAULT_MCP_LAB_PATH,
        metavar="PATH",
        help=f"MCP lab JSON report path (default: {DEFAULT_MCP_LAB_PATH}).",
    )
    parser.add_argument(
        "-i",
        "--iterations",
        type=_positive_integer,
        default=20,
        help="Number of agent cycles to run (must be at least 1).",
    )
    parser.add_argument(
        "--speed",
        type=_nonnegative_integer,
        default=100,
        help="Delay between agent actions in milliseconds.",
    )
    parser.add_argument(
        "--hallucination-rate",
        type=_probability_argument,
        default=0.15,
        help="Probability (0.0-1.0) of using syntax from the wrong OS.",
    )
    parser.add_argument(
        "--context-loss-rate",
        type=_probability_argument,
        default=0.05,
        help="Probability (0.0-1.0) of re-running baseline discovery.",
    )
    parser.add_argument(
        "--retry-rate",
        type=_probability_argument,
        default=0.30,
        help="Probability (0.0-1.0) of retrying after an access error.",
    )
    parser.add_argument(
        "--evasion-rate",
        type=_probability_argument,
        default=0.10,
        help="Probability (0.0-1.0) of wrapping a command in nested shells.",
    )
    parser.add_argument(
        "--allow-network",
        action="store_true",
        help="Allow authenticated, read-only cloud CLI commands (disabled by default).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show selected commands without executing them.",
    )
    parser.add_argument(
        "--output",
        default="agent_sim_layer.json",
        metavar="PATH",
        help="Navigator layer output path (default: agent_sim_layer.json).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        help="Random seed for a reproducible simulation.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        scenario_registry = load_scenario_registry(args.scenario_pack)
    except (FileNotFoundError, ValueError) as exc:
        parser.error(str(exc))

    if args.list_scenarios:
        for definition in list_scenarios(scenario_registry):
            print(f"{definition.scenario_id}\t{definition.name}")
            print(f"  {definition.description}")
        return 0

    if args.mcp_lab:
        try:
            path = run_mcp_lab(args.mcp_lab_output)
            report = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError) as exc:
            parser.error(str(exc))
        return 0 if report["summary"]["all_passed"] else 1

    if args.scenario:
        try:
            result = run_scenario_suite(
                args.scenario,
                variant=args.variant,
                ground_truth_path=args.ground_truth_output,
                validation_path=args.validation_output,
                junit_path=args.junit_output,
                sarif_path=args.sarif_output,
                otel_path=args.otel_output,
                coverage_path=args.coverage_output,
                bundle_path=args.bundle_output,
                mutation_count=args.mutations,
                mutation_seed=args.mutation_seed,
                speed_ms=args.speed,
                registry=scenario_registry,
            )
        except (FileNotFoundError, ValueError) as exc:
            parser.error(str(exc))
        if result.stopped:
            return 130
        return 0 if result.passed else 1

    simulator = AgentSim(
        speed_ms=args.speed,
        hallucination_rate=args.hallucination_rate,
        context_loss_rate=args.context_loss_rate,
        error_retry_rate=args.retry_rate,
        evasion_rate=args.evasion_rate,
        allow_network=args.allow_network,
        dry_run=args.dry_run,
        output_path=args.output,
        seed=args.seed,
    )

    try:
        simulator.run_simulation(args.iterations)
    except KeyboardInterrupt:
        print("\n[!] Simulation stopped by user.")
        simulator._generate_attack_navigator_layer()
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
