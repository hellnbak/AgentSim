"""Local Flask dashboard for AgentSim."""

from __future__ import annotations

import hmac
import json
import os
import platform
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    redirect,
    render_template_string,
    request,
    send_file,
    url_for,
)

from core import AgentSim
from agentsim.content import load_ability_registry, load_campaign_registry
from agentsim.defense import (
    DetectionAlert,
    DetectionSnapshot,
    OperatorAnnotation,
    analyze_gaps,
    compare_detection_snapshots,
    generate_runbook,
    reconcile_detection_feedback,
)
from agentsim.detection import (
    analyze_coverage,
    evaluate_rule,
    generate_candidate,
    load_detection_pack,
    sweep_detection_pack,
)
from agentsim.external import adapter_names
from agentsim.lab import (
    list_fixtures,
    run_fixture,
    run_lab_suite,
    run_reference_fixture,
    run_reference_suite,
)
from agentsim.telemetry.connectors import CONNECTOR_NAMES
from agentsim.models.target import TargetProfile
from agentsim.orchestration.runner import CampaignRunner
from agentsim.safety.authorization import AuthorizationManifest
from agentsim.storage import RunStore
from agentsim.telemetry.normalization import normalize_records
from agentsim.telemetry.assurance import assess_telemetry
from agentsim.telemetry.investigation import investigate_telemetry
from scenarios import (
    DEFAULT_BUNDLE_PATH,
    DEFAULT_COVERAGE_PATH,
    DEFAULT_JUNIT_PATH,
    DEFAULT_OTEL_PATH,
    DEFAULT_SARIF_PATH,
    SCENARIOS,
    estimate_event_count,
    load_ground_truth,
    run_scenario_suite,
)


app = Flask(__name__)
state_lock = threading.RLock()
state_changed = threading.Condition(state_lock)
log_queue: list[dict[str, Any]] = []
is_running = False
sim_thread: threading.Thread | None = None
event_sequence = 0
form_token = secrets.token_urlsafe(32)
stop_event = threading.Event()
last_layer_path: Path | None = None
last_ground_truth_path: Path | None = None
last_validation_path: Path | None = None
last_bundle_path: Path | None = None
last_benchmark_metrics: dict[str, Any] = {}
run_started_at: float | None = None
run_finished_at: float | None = None
current_params: dict[str, Any] = {}
last_outcome = "ready"
LAYER_OUTPUT_PATH = Path.cwd() / "agent_sim_layer.json"
GROUND_TRUTH_OUTPUT_PATH = Path.cwd() / "agent_sim_events.jsonl"
VALIDATION_OUTPUT_PATH = Path.cwd() / "agent_sim_validation.json"
JUNIT_OUTPUT_PATH = Path.cwd() / DEFAULT_JUNIT_PATH
SARIF_OUTPUT_PATH = Path.cwd() / DEFAULT_SARIF_PATH
OTEL_OUTPUT_PATH = Path.cwd() / DEFAULT_OTEL_PATH
COVERAGE_OUTPUT_PATH = Path.cwd() / DEFAULT_COVERAGE_PATH
BUNDLE_OUTPUT_PATH = Path.cwd() / DEFAULT_BUNDLE_PATH
CAMPAIGN_DATABASE_PATH = Path.cwd() / "agent_sim_runs.db"
CAMPAIGN_OUTPUT_DIRECTORY = Path.cwd() / "agent_sim_campaign_runs"
ABILITIES = load_ability_registry()
CAMPAIGNS = load_campaign_registry()
MAX_EVENTS = 2000


def _host_os_name() -> str:
    system_name = platform.system()
    if system_name == "Darwin":
        return "macOS"
    return system_name or "Unknown"


def _classify_message(message: str) -> dict[str, Any]:
    clean_message = str(message).strip()
    event: dict[str, Any] = {
        "message": clean_message,
        "kind": "info",
        "category": "system",
    }

    cycle_match = re.search(r"Agent Cycle (\d+) \((.+)\)", clean_message)
    if cycle_match:
        event.update(
            kind="cycle",
            category="system",
            cycle=int(cycle_match.group(1)),
            phase=cycle_match.group(2),
        )
        return event

    phase_match = re.search(r"PHASE TRANSITION: (.+?)\s*=*\]$", clean_message)
    if phase_match:
        event.update(kind="phase", category="system", phase=phase_match.group(1))
        return event

    if clean_message.startswith("[SCENARIO]"):
        event.update(kind="scenario", category="system")
        return event

    checkpoint_match = re.match(
        r"\[(input|decision|pre_tool|post_tool|tool_discovery|network|policy|"
        r"memory|inter_agent|delegation|approval|authorization|budget|retrieval|"
        r"configuration|observation)\]\s+(.+)",
        clean_message,
    )
    if checkpoint_match:
        stage = checkpoint_match.group(1)
        lower_message = clean_message.lower()
        blocked = stage in {"policy", "network", "authorization", "budget"} and (
            "block" in lower_message or "denied" in lower_message
        )
        risky = any(
            marker in lower_message
            for marker in (
                "untrusted", "changed", "decoy", "goal drift", "block", "spoof",
                "taint", "exceeded", "mismatch", "denied", "different audience",
                "recursive", "poison", "failed its integrity", "disabling",
            )
        )
        event.update(
            kind="blocked" if blocked else (
                "tool"
                if stage in {"pre_tool", "tool_discovery", "network", "delegation"}
                else "checkpoint"
            ),
            category="anomaly" if risky else (
                "command"
                if stage in {"pre_tool", "tool_discovery", "network", "delegation"}
                else "system"
            ),
            stage=stage,
        )
        return event

    command_match = re.search(
        r"\[\*\] (WOULD EXECUTE|EXECUTING): (.+) \(([^()]+)\)$",
        clean_message,
    )
    if command_match:
        event.update(
            kind="dry_command" if command_match.group(1) == "WOULD EXECUTE" else "command",
            category="command",
            command=command_match.group(2),
            shell=command_match.group(3),
        )
        return event

    hallucination_match = re.search(
        r"HALLUCINATION: (.+) \(([^()]+)\)$", clean_message
    )
    if hallucination_match:
        event.update(
            kind="hallucination",
            category="anomaly",
            command=hallucination_match.group(1),
            shell=hallucination_match.group(2),
        )
    elif "CONTEXT LOSS" in clean_message:
        event.update(kind="context_loss", category="anomaly")
    elif "EVASION:" in clean_message:
        event.update(kind="evasion", category="anomaly")
    elif "PARSING LOOP:" in clean_message or "[Reasoning]" in clean_message:
        event.update(kind="retry", category="anomaly")
    elif "SKIPPED NETWORK ACTION" in clean_message:
        event.update(kind="skipped", category="anomaly")
    elif "STOP REQUESTED" in clean_message:
        event.update(kind="stop_requested", category="anomaly")
    elif "Simulation stopped" in clean_message:
        event.update(kind="stopped", category="anomaly")
    elif "Simulation failed" in clean_message:
        event.update(kind="error", category="anomaly")
    elif "Scenario suite failed" in clean_message or "Scenario validation failed" in clean_message:
        event.update(kind="error", category="anomaly")
    elif "Scenario suite stopped" in clean_message:
        event.update(kind="stopped", category="anomaly")
    elif "Scenario suite complete" in clean_message or "Scenario validation passed" in clean_message:
        event.update(kind="complete", category="system")
    elif "Ground-truth JSONL exported" in clean_message or "Validation report exported" in clean_message:
        event.update(kind="export", category="system")
    elif "Simulation finished" in clean_message:
        event.update(kind="complete", category="system")
    elif "Navigator layer exported" in clean_message:
        event.update(kind="export", category="system")
    elif "Starting AgentSim" in clean_message or "Run requested" in clean_message:
        event.update(kind="start", category="system")
    elif "Detected OS" in clean_message:
        event.update(kind="environment", category="system")
    elif clean_message.startswith("[!]"):
        event.update(kind="warning", category="anomaly")

    return event


def _append_event(
    message: str,
    *,
    kind: str | None = None,
    category: str | None = None,
    **metadata: Any,
) -> dict[str, Any]:
    global event_sequence
    event = _classify_message(message)
    if kind is not None:
        event["kind"] = kind
    if category is not None:
        event["category"] = category
    event.update(metadata)

    with state_changed:
        event_sequence += 1
        event["id"] = event_sequence
        event["time"] = time.strftime("%H:%M:%S")
        log_queue.append(event)
        if len(log_queue) > MAX_EVENTS:
            del log_queue[: len(log_queue) - MAX_EVENTS]
        state_changed.notify_all()
    return event


def log_callback(message: str) -> None:
    _append_event(message)


def _status_snapshot() -> dict[str, Any]:
    with state_lock:
        return {
            "running": is_running,
            "os": _host_os_name(),
            "event_count": len(log_queue),
            "layer_available": bool(
                last_layer_path is not None and last_layer_path.exists()
            ),
            "ground_truth_available": bool(
                last_ground_truth_path is not None and last_ground_truth_path.exists()
            ),
            "validation_available": bool(
                last_validation_path is not None and last_validation_path.exists()
            ),
            "bundle_available": bool(
                last_bundle_path is not None and last_bundle_path.exists()
            ),
            "benchmark_metrics": dict(last_benchmark_metrics),
            "started_at": run_started_at,
            "finished_at": run_finished_at,
            "params": dict(current_params),
            "outcome": last_outcome,
        }


def run_sim_background(**kwargs: Any) -> None:
    global is_running, last_layer_path, run_finished_at, last_outcome
    status_message = "[*] Simulation finished. Navigator layer is ready."
    outcome = "error"
    exported_path: Path | None = None
    try:
        simulator = AgentSim(
            speed_ms=kwargs["speed"],
            hallucination_rate=kwargs["hallucination_rate"],
            context_loss_rate=kwargs["context_loss_rate"],
            error_retry_rate=kwargs["retry_rate"],
            evasion_rate=kwargs["evasion_rate"],
            allow_network=kwargs["allow_network"],
            dry_run=kwargs["dry_run"],
            seed=kwargs["seed"],
            output_path=LAYER_OUTPUT_PATH,
            stop_callback=stop_event.is_set,
            log_callback=log_callback,
        )
        exported_path = simulator.run_simulation(kwargs["iterations"])
        if stop_event.is_set():
            status_message = "[!] Simulation stopped. Partial Navigator layer is ready."
            outcome = "stopped"
        else:
            outcome = "complete"
    except Exception as exc:  # Keep a failed worker from wedging the UI.
        status_message = f"[!] Simulation failed: {exc}"
    finally:
        with state_changed:
            is_running = False
            last_outcome = outcome
            run_finished_at = time.time()
            if exported_path is not None and exported_path.exists():
                last_layer_path = exported_path
            state_changed.notify_all()
        log_callback(status_message)


def run_scenario_background(**kwargs: Any) -> None:
    global is_running, last_ground_truth_path, last_validation_path, last_bundle_path
    global last_benchmark_metrics, run_finished_at, last_outcome
    status_message = "[*] Scenario suite failed before validation completed."
    outcome = "error"
    result = None
    try:
        result = run_scenario_suite(
            kwargs["scenario"],
            variant=kwargs["variant"],
            ground_truth_path=GROUND_TRUTH_OUTPUT_PATH,
            validation_path=VALIDATION_OUTPUT_PATH,
            junit_path=JUNIT_OUTPUT_PATH,
            sarif_path=SARIF_OUTPUT_PATH,
            otel_path=OTEL_OUTPUT_PATH,
            coverage_path=COVERAGE_OUTPUT_PATH,
            bundle_path=BUNDLE_OUTPUT_PATH,
            mutation_count=kwargs["mutations"],
            mutation_seed=kwargs["mutation_seed"],
            speed_ms=kwargs["speed"],
            stop_callback=stop_event.is_set,
            log_callback=log_callback,
        )
        if result.stopped:
            status_message = "[!] Scenario suite stopped. Partial artifacts are ready."
            outcome = "stopped"
        elif result.passed:
            status_message = "[*] Scenario suite complete. Ground truth and validation are ready."
            outcome = "complete"
        else:
            status_message = "[!] Scenario suite failed validation. Review the report."
    except Exception as exc:  # Keep a failed worker from wedging the UI.
        status_message = f"[!] Scenario suite failed: {exc}"
    finally:
        with state_changed:
            is_running = False
            last_outcome = outcome
            run_finished_at = time.time()
            if result is not None:
                if result.ground_truth_path.exists():
                    last_ground_truth_path = result.ground_truth_path
                if result.validation_path.exists():
                    last_validation_path = result.validation_path
                if result.bundle_path is not None and result.bundle_path.exists():
                    last_bundle_path = result.bundle_path
                last_benchmark_metrics = dict(result.metrics)
            state_changed.notify_all()
        log_callback(status_message)


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="dark">
    <title>AgentSim · Detection-First Adversary Emulation</title>
    <style>
        :root {
            --bg: #071017;
            --bg-raised: #0b1720;
            --panel: #0e1d27;
            --panel-soft: #122631;
            --panel-hover: #172f3b;
            --line: #203947;
            --line-strong: #315362;
            --text: #e8f1f4;
            --muted: #8fa6af;
            --subtle: #637b85;
            --accent: #42d4b5;
            --accent-strong: #20b99a;
            --accent-soft: rgba(66, 212, 181, 0.12);
            --blue: #65aef7;
            --blue-soft: rgba(101, 174, 247, 0.12);
            --amber: #f2b95f;
            --amber-soft: rgba(242, 185, 95, 0.12);
            --red: #ff756f;
            --red-soft: rgba(255, 117, 111, 0.12);
            --violet: #a98cff;
            --radius: 14px;
            --shadow: 0 20px 60px rgba(0, 0, 0, 0.22);
            font-family: Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        }

        * { box-sizing: border-box; }
        html { min-width: 320px; background: var(--bg); }
        body {
            min-height: 100vh;
            margin: 0;
            color: var(--text);
            background:
                radial-gradient(circle at 82% -10%, rgba(66, 212, 181, 0.09), transparent 32rem),
                linear-gradient(180deg, #08131b 0, var(--bg) 24rem);
        }
        button, input, select { font: inherit; }
        button, a { -webkit-tap-highlight-color: transparent; }
        button:focus-visible, input:focus-visible, select:focus-visible, summary:focus-visible, a:focus-visible {
            outline: 2px solid var(--accent);
            outline-offset: 2px;
        }

        .topbar {
            height: 72px;
            padding: 0 28px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid rgba(49, 83, 98, 0.55);
            background: rgba(7, 16, 23, 0.82);
            backdrop-filter: blur(16px);
            position: sticky;
            top: 0;
            z-index: 20;
        }
        .brand { display: flex; align-items: center; gap: 12px; min-width: 0; }
        .brand-mark {
            width: 38px;
            height: 38px;
            display: grid;
            place-items: center;
            border: 1px solid rgba(66, 212, 181, 0.45);
            border-radius: 11px;
            background: linear-gradient(145deg, rgba(66, 212, 181, 0.18), rgba(101, 174, 247, 0.08));
            color: var(--accent);
            font: 700 17px/1 ui-monospace, SFMono-Regular, Menlo, monospace;
            box-shadow: inset 0 0 18px rgba(66, 212, 181, 0.07);
        }
        .brand-copy { min-width: 0; }
        .brand-name { font-size: 15px; font-weight: 720; letter-spacing: 0.01em; }
        .brand-subtitle { color: var(--muted); font-size: 11px; letter-spacing: 0.1em; text-transform: uppercase; margin-top: 2px; }
        .topbar-meta { display: flex; align-items: center; gap: 10px; }
        .host-chip, .status-pill {
            min-height: 32px;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 0 11px;
            border: 1px solid var(--line);
            border-radius: 999px;
            color: var(--muted);
            background: rgba(14, 29, 39, 0.76);
            font-size: 12px;
            font-weight: 650;
        }
        .status-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--subtle); }
        .status-pill.running { color: var(--accent); border-color: rgba(66, 212, 181, 0.34); background: var(--accent-soft); }
        .status-pill.running .status-dot { background: var(--accent); box-shadow: 0 0 0 4px rgba(66, 212, 181, 0.11); animation: pulse 1.8s infinite; }
        .status-pill.error { color: var(--red); border-color: rgba(255, 117, 111, 0.34); background: var(--red-soft); }
        .status-pill.error .status-dot { background: var(--red); }
        @keyframes pulse { 50% { opacity: 0.45; } }

        .app-shell {
            width: min(1540px, 100%);
            margin: 0 auto;
            padding: 22px 28px 32px;
            display: grid;
            grid-template-columns: 350px minmax(0, 1fr);
            gap: 22px;
            align-items: start;
        }
        .card {
            background: linear-gradient(180deg, rgba(16, 34, 45, 0.96), rgba(12, 27, 36, 0.96));
            border: 1px solid var(--line);
            border-radius: var(--radius);
            box-shadow: var(--shadow);
        }
        .config-panel { position: sticky; top: 94px; overflow: hidden; }
        .panel-header { padding: 20px 20px 16px; border-bottom: 1px solid var(--line); }
        .eyebrow {
            color: var(--accent);
            font: 700 10px/1 ui-monospace, SFMono-Regular, Menlo, monospace;
            letter-spacing: 0.14em;
            text-transform: uppercase;
        }
        h1, h2, h3, p { margin-top: 0; }
        .panel-header h2 { margin: 7px 0 5px; font-size: 18px; letter-spacing: -0.01em; }
        .panel-header p { margin: 0; color: var(--muted); font-size: 12px; line-height: 1.5; }
        .config-form { padding: 18px 20px 20px; }
        .section-label {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin: 0 0 9px;
            color: var(--muted);
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.07em;
            text-transform: uppercase;
        }
        .preset-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 7px; margin-bottom: 9px; }
        .preset {
            min-height: 36px;
            padding: 0 10px;
            border: 1px solid var(--line);
            border-radius: 9px;
            color: var(--muted);
            background: rgba(7, 16, 23, 0.45);
            cursor: pointer;
            font-size: 12px;
            font-weight: 650;
            transition: 160ms ease;
        }
        .preset:hover { border-color: var(--line-strong); color: var(--text); background: var(--panel-hover); }
        .preset.active { color: var(--accent); border-color: rgba(66, 212, 181, 0.38); background: var(--accent-soft); }
        .preset-description { min-height: 34px; color: var(--subtle); font-size: 11px; line-height: 1.5; margin: 0 0 18px; }
        .control { margin-bottom: 17px; }
        .control-head { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; margin-bottom: 8px; }
        .control label { color: var(--text); font-size: 12px; font-weight: 640; }
        .control output { color: var(--accent); font: 650 11px/1 ui-monospace, SFMono-Regular, Menlo, monospace; }
        input[type="range"] {
            width: 100%;
            height: 4px;
            margin: 4px 0;
            appearance: none;
            border-radius: 999px;
            background: var(--line);
            accent-color: var(--accent);
        }
        input[type="range"]::-webkit-slider-thumb {
            appearance: none;
            width: 16px;
            height: 16px;
            border: 3px solid var(--panel);
            border-radius: 50%;
            background: var(--accent);
            box-shadow: 0 0 0 1px rgba(66, 212, 181, 0.55);
            cursor: pointer;
        }
        .range-scale { display: flex; justify-content: space-between; margin-top: 4px; color: var(--subtle); font-size: 9px; }
        details.advanced { margin: 2px -4px 16px; padding: 0 4px; border-top: 1px solid var(--line); border-bottom: 1px solid var(--line); }
        details.advanced summary {
            padding: 13px 0;
            color: var(--muted);
            cursor: pointer;
            font-size: 12px;
            font-weight: 650;
            list-style: none;
        }
        details.advanced summary::-webkit-details-marker { display: none; }
        details.advanced summary::after { content: "+"; float: right; color: var(--accent); font-size: 17px; line-height: 12px; }
        details.advanced[open] summary::after { content: "−"; }
        .advanced-content { padding: 4px 0 2px; }
        .field-row { display: grid; grid-template-columns: 1fr auto; align-items: center; gap: 10px; margin-bottom: 14px; }
        .field-row label { color: var(--muted); font-size: 12px; }
        .mode-select, .scenario-select {
            width: 100%;
            height: 38px;
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: 0 30px 0 10px;
            color: var(--text);
            background: rgba(7, 16, 23, 0.65);
        }
        .run-mode-control { margin-bottom: 18px; }
        .run-mode-control label, .scenario-controls label {
            display: block;
            margin-bottom: 7px;
            color: var(--muted);
            font-size: 11px;
            font-weight: 650;
        }
        .scenario-controls {
            margin-bottom: 17px;
            padding: 13px;
            border: 1px solid rgba(101, 174, 247, 0.25);
            border-radius: 10px;
            background: var(--blue-soft);
        }
        .scenario-controls .field-block + .field-block { margin-top: 12px; }
        .scenario-copy { margin: 10px 0 0; color: var(--subtle); font-size: 10px; line-height: 1.5; }
        .hidden { display: none !important; }
        .seed-input {
            width: 118px;
            height: 34px;
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: 0 9px;
            color: var(--text);
            background: rgba(7, 16, 23, 0.65);
            font: 12px ui-monospace, SFMono-Regular, Menlo, monospace;
        }
        .seed-wrap { display: flex; gap: 5px; }
        .icon-button {
            height: 34px;
            min-width: 34px;
            padding: 0 9px;
            border: 1px solid var(--line);
            border-radius: 8px;
            color: var(--muted);
            background: var(--panel-soft);
            cursor: pointer;
            font-size: 11px;
            font-weight: 700;
        }
        .toggle-row {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 14px;
            padding: 11px 0;
            border-top: 1px solid rgba(32, 57, 71, 0.7);
        }
        .toggle-copy strong { display: block; font-size: 12px; margin-bottom: 3px; }
        .toggle-copy span { display: block; color: var(--subtle); font-size: 10px; line-height: 1.4; }
        .switch { position: relative; flex: 0 0 auto; width: 38px; height: 22px; }
        .switch input { position: absolute; opacity: 0; pointer-events: none; }
        .switch-track { position: absolute; inset: 0; border: 1px solid var(--line-strong); border-radius: 999px; background: #09151d; transition: 160ms ease; cursor: pointer; }
        .switch-track::after { content: ""; position: absolute; width: 14px; height: 14px; left: 3px; top: 3px; border-radius: 50%; background: var(--muted); transition: 160ms ease; }
        .switch input:checked + .switch-track { border-color: rgba(66, 212, 181, 0.58); background: var(--accent-soft); }
        .switch input:checked + .switch-track::after { transform: translateX(16px); background: var(--accent); }
        .switch input:focus-visible + .switch-track { outline: 2px solid var(--accent); outline-offset: 2px; }
        .network-warning { display: none; margin: 0 0 12px; padding: 9px 10px; border: 1px solid rgba(242, 185, 95, 0.28); border-radius: 8px; color: var(--amber); background: var(--amber-soft); font-size: 10px; line-height: 1.45; }
        .network-warning.visible { display: block; }
        .form-error { min-height: 17px; margin: 1px 0 5px; color: var(--red); font-size: 11px; line-height: 1.4; }
        .action-row { display: grid; grid-template-columns: 1fr 88px; gap: 8px; }
        .primary-button, .danger-button {
            min-height: 42px;
            border-radius: 10px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 750;
            transition: 160ms ease;
        }
        .primary-button { border: 1px solid var(--accent); color: #042219; background: var(--accent); box-shadow: 0 8px 22px rgba(66, 212, 181, 0.18); }
        .primary-button:hover:not(:disabled) { background: #60e5c8; transform: translateY(-1px); }
        .danger-button { border: 1px solid rgba(255, 117, 111, 0.35); color: var(--red); background: var(--red-soft); }
        .danger-button:hover:not(:disabled) { border-color: var(--red); }
        .primary-button:disabled, .danger-button:disabled { opacity: 0.38; cursor: not-allowed; transform: none; box-shadow: none; }
        .safety-note { display: flex; gap: 7px; margin: 12px 0 0; color: var(--subtle); font-size: 9.5px; line-height: 1.5; }
        .safety-note::before { content: "i"; flex: 0 0 auto; width: 15px; height: 15px; display: grid; place-items: center; border: 1px solid var(--line-strong); border-radius: 50%; color: var(--muted); font: 700 9px/1 serif; }

        .workspace { min-width: 0; display: grid; gap: 16px; }
        .run-overview { padding: 19px 20px 17px; }
        .overview-top { display: flex; align-items: flex-start; justify-content: space-between; gap: 20px; }
        .overview-top h1 { margin: 5px 0 6px; font-size: clamp(20px, 2.2vw, 28px); letter-spacing: -0.03em; }
        .overview-top p { margin: 0; color: var(--muted); font-size: 12px; line-height: 1.5; }
        .run-clock { text-align: right; }
        .run-clock span { display: block; color: var(--subtle); font-size: 9px; font-weight: 700; letter-spacing: 0.09em; text-transform: uppercase; }
        .run-clock strong { display: block; margin-top: 4px; color: var(--text); font: 650 20px/1 ui-monospace, SFMono-Regular, Menlo, monospace; }
        .progress-track { height: 3px; margin: 18px 0 17px; overflow: hidden; border-radius: 999px; background: var(--line); }
        .progress-value { width: 0; height: 100%; border-radius: inherit; background: linear-gradient(90deg, var(--accent), var(--blue)); transition: width 260ms ease; }
        .phase-rail { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; }
        .phase {
            position: relative;
            min-width: 0;
            padding: 10px 11px;
            border: 1px solid var(--line);
            border-radius: 10px;
            background: rgba(7, 16, 23, 0.4);
            transition: 180ms ease;
        }
        .phase-index { display: block; color: var(--subtle); font: 700 9px/1 ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: 0.08em; }
        .phase-name { display: block; margin-top: 5px; color: var(--muted); font-size: 11px; font-weight: 680; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .phase.active { border-color: rgba(66, 212, 181, 0.45); background: var(--accent-soft); }
        .phase.active .phase-index, .phase.active .phase-name { color: var(--accent); }
        .phase.complete { border-color: rgba(101, 174, 247, 0.3); background: var(--blue-soft); }
        .phase.complete .phase-index, .phase.complete .phase-name { color: var(--blue); }

        .metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
        .metric { min-height: 86px; padding: 15px 16px; border: 1px solid var(--line); border-radius: 12px; background: rgba(14, 29, 39, 0.78); }
        .metric-label { display: block; color: var(--muted); font-size: 10px; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase; }
        .metric-value { display: block; margin-top: 9px; font: 680 25px/1 ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: -0.03em; }
        .metric-foot { display: block; margin-top: 6px; color: var(--subtle); font-size: 9px; }
        .metric.commands .metric-value { color: var(--blue); }
        .metric.anomalies .metric-value { color: var(--amber); }
        .metric.skipped .metric-value { color: var(--violet); }

        .campaign-card { min-width: 0; overflow: hidden; }
        .campaign-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; padding: 18px; border-bottom: 1px solid var(--line); }
        .campaign-header h2 { margin: 5px 0 4px; font-size: 15px; }
        .campaign-header p { margin: 0; max-width: 720px; color: var(--subtle); font-size: 10px; line-height: 1.5; }
        .campaign-version { color: var(--accent); font: 700 12px/1 ui-monospace, SFMono-Regular, Menlo, monospace; white-space: nowrap; }
        .campaign-controls { display: grid; grid-template-columns: minmax(220px, 1fr) minmax(160px, 0.6fr) auto; gap: 9px; padding: 12px 18px; border-bottom: 1px solid var(--line); }
        .campaign-controls select, .campaign-target { height: 38px; border: 1px solid var(--line); border-radius: 8px; padding: 0 10px; color: var(--text); background: rgba(7, 16, 23, 0.65); }
        .campaign-target { display: flex; align-items: center; color: var(--muted); font: 10px ui-monospace, SFMono-Regular, Menlo, monospace; }
        .campaign-run { min-width: 150px; min-height: 38px; }
        .campaign-body { display: grid; grid-template-columns: minmax(0, 1.2fr) minmax(240px, 0.8fr); min-height: 150px; }
        .campaign-result, .campaign-history { padding: 16px 18px; min-width: 0; }
        .campaign-history { border-left: 1px solid var(--line); }
        .campaign-section-label { margin-bottom: 10px; color: var(--subtle); font: 700 9px/1.2 ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: 0.1em; text-transform: uppercase; }
        .campaign-summary { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 7px; }
        .campaign-stat { padding: 9px; border: 1px solid var(--line); border-radius: 8px; background: rgba(7, 16, 23, 0.42); }
        .campaign-stat strong { display: block; color: var(--accent); font: 700 15px/1 ui-monospace, SFMono-Regular, Menlo, monospace; }
        .campaign-stat span { display: block; margin-top: 5px; color: var(--subtle); font-size: 9px; }
        .campaign-timeline { display: grid; gap: 5px; margin-top: 10px; }
        .campaign-event, .history-run { display: grid; grid-template-columns: 90px minmax(0, 1fr); gap: 8px; padding: 7px 8px; border: 1px solid rgba(32, 57, 71, 0.7); border-radius: 7px; color: var(--muted); font-size: 9px; }
        .campaign-event strong, .history-run strong { color: var(--blue); font: 700 9px/1.4 ui-monospace, SFMono-Regular, Menlo, monospace; }
        .history-list { display: grid; gap: 6px; }
        .history-run { grid-template-columns: 1fr auto; }
        .history-run > div { min-width: 0; display: grid; gap: 3px; }
        .history-run > div > strong,
        .history-run > div > span { display: block; min-width: 0; overflow-wrap: anywhere; }
        .history-run span { color: var(--subtle); }

        .debugger-card { min-width: 0; overflow: hidden; }
        .debugger-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; padding: 17px 18px 14px; border-bottom: 1px solid var(--line); }
        .debugger-header h2 { margin: 5px 0 4px; font-size: 15px; }
        .debugger-header p { margin: 0; color: var(--subtle); font-size: 10px; line-height: 1.5; }
        .debugger-score { flex: 0 0 auto; text-align: right; }
        .debugger-score strong { display: block; color: var(--accent); font: 700 18px/1 ui-monospace, SFMono-Regular, Menlo, monospace; }
        .debugger-score span { display: block; margin-top: 5px; color: var(--subtle); font-size: 9px; text-transform: uppercase; letter-spacing: 0.08em; }
        .debugger-toolbar { display: grid; grid-template-columns: 170px minmax(160px, 1fr) auto; gap: 8px; padding: 11px 13px; border-bottom: 1px solid var(--line); background: rgba(7, 16, 23, 0.28); }
        .debugger-toolbar select, .debugger-toolbar input { width: 100%; height: 32px; border: 1px solid var(--line); border-radius: 8px; padding: 0 10px; color: var(--text); background: rgba(7, 16, 23, 0.62); font-size: 10px; }
        .debugger-grid { display: grid; grid-template-columns: 285px minmax(0, 1fr); min-height: 390px; }
        .debug-trace-list { max-height: 470px; overflow: auto; border-right: 1px solid var(--line); padding: 7px; scrollbar-color: var(--line-strong) transparent; }
        .debug-placeholder { display: grid; place-items: center; min-height: 250px; padding: 28px; color: var(--subtle); font-size: 10px; line-height: 1.6; text-align: center; }
        .debug-trace { width: 100%; display: grid; grid-template-columns: 1fr auto; gap: 4px 8px; margin-bottom: 5px; padding: 9px 10px; border: 1px solid transparent; border-radius: 9px; color: var(--muted); background: transparent; cursor: pointer; text-align: left; }
        .debug-trace:hover { border-color: var(--line); background: rgba(23, 47, 59, 0.4); }
        .debug-trace.active { border-color: rgba(66, 212, 181, 0.36); background: var(--accent-soft); }
        .debug-trace-name { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 10px; font-weight: 700; }
        .debug-trace-meta { grid-column: 1 / -1; color: var(--subtle); font: 9px/1.4 ui-monospace, SFMono-Regular, Menlo, monospace; }
        .debug-badge { padding: 3px 6px; border-radius: 999px; color: var(--accent); background: var(--accent-soft); font-size: 8px; font-weight: 800; text-transform: uppercase; }
        .debug-badge.fail { color: var(--red); background: var(--red-soft); }
        .debug-detail { min-width: 0; padding: 16px; }
        .debug-detail-head { display: flex; justify-content: space-between; gap: 14px; margin-bottom: 13px; }
        .debug-detail-head h3 { margin: 0 0 5px; font-size: 13px; }
        .debug-detail-head p { margin: 0; color: var(--subtle); font: 9px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; overflow-wrap: anywhere; }
        .debug-outcome { flex: 0 0 auto; display: grid; grid-template-columns: repeat(3, auto); gap: 6px; }
        .debug-outcome span { padding: 6px 8px; border: 1px solid var(--line); border-radius: 8px; color: var(--muted); background: rgba(7, 16, 23, 0.36); font-size: 9px; }
        .debug-section-label { margin: 14px 0 7px; color: var(--subtle); font-size: 9px; font-weight: 800; letter-spacing: 0.08em; text-transform: uppercase; }
        .debug-rule { display: grid; gap: 5px; }
        .debug-condition { padding: 7px 9px; border: 1px solid var(--line); border-radius: 8px; color: #bdcdd3; background: rgba(7, 16, 23, 0.45); font: 9px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; overflow-wrap: anywhere; }
        .debug-timeline { display: grid; gap: 5px; }
        .debug-event { display: grid; grid-template-columns: 32px 88px minmax(0, 1fr); gap: 8px; padding: 7px 9px; border-left: 2px solid var(--line); border-radius: 6px; background: rgba(7, 16, 23, 0.3); }
        .debug-event.signal { border-left-color: var(--amber); background: var(--amber-soft); }
        .debug-event-sequence { color: var(--subtle); font: 9px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; }
        .debug-event-stage { color: var(--blue); font-size: 9px; font-weight: 750; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .debug-event-copy { min-width: 0; color: var(--muted); font-size: 9.5px; line-height: 1.45; overflow-wrap: anywhere; }

        .investigation-card { min-width: 0; overflow: hidden; }
        .investigation-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; padding: 18px; border-bottom: 1px solid var(--line); }
        .investigation-header h2 { margin: 5px 0 4px; font-size: 15px; }
        .investigation-header p { max-width: 760px; margin: 0; color: var(--subtle); font-size: 10px; line-height: 1.5; }
        .investigation-score { flex: 0 0 auto; text-align: right; }
        .investigation-score strong { display: block; color: var(--amber); font: 700 18px/1 ui-monospace, SFMono-Regular, Menlo, monospace; }
        .investigation-score span { display: block; margin-top: 5px; color: var(--subtle); font-size: 8px; font-weight: 800; letter-spacing: 0.08em; text-transform: uppercase; }
        .investigation-toolbar { display: grid; grid-template-columns: minmax(240px, 1fr) 170px auto; gap: 8px; padding: 11px 13px; border-bottom: 1px solid var(--line); background: rgba(7, 16, 23, 0.28); }
        .investigation-toolbar select { width: 100%; height: 34px; border: 1px solid var(--line); border-radius: 8px; padding: 0 10px; color: var(--text); background: rgba(7, 16, 23, 0.62); font-size: 10px; }
        .investigation-summary { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 7px; padding: 12px 13px; border-bottom: 1px solid var(--line); }
        .investigation-stat { min-width: 0; padding: 8px 9px; border: 1px solid var(--line); border-radius: 8px; background: rgba(7, 16, 23, 0.42); }
        .investigation-stat strong { display: block; color: var(--blue); font: 700 14px/1 ui-monospace, SFMono-Regular, Menlo, monospace; overflow: hidden; text-overflow: ellipsis; }
        .investigation-stat span { display: block; margin-top: 5px; color: var(--subtle); font-size: 8px; text-transform: uppercase; letter-spacing: 0.06em; }
        .investigation-grid { display: grid; grid-template-columns: 260px minmax(350px, 1fr) 300px; min-height: 440px; }
        .investigation-findings, .investigation-graph, .investigation-detail { min-width: 0; padding: 12px; }
        .investigation-findings { max-height: 560px; overflow: auto; border-right: 1px solid var(--line); }
        .investigation-graph { max-height: 560px; overflow: auto; }
        .investigation-detail { border-left: 1px solid var(--line); background: rgba(7, 16, 23, 0.2); }
        .investigation-label { margin: 2px 0 9px; color: var(--subtle); font: 800 8px/1.2 ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: 0.1em; text-transform: uppercase; }
        .investigation-finding { width: 100%; display: grid; gap: 5px; margin-bottom: 6px; padding: 10px; border: 1px solid var(--line); border-radius: 9px; color: var(--muted); background: rgba(7, 16, 23, 0.28); cursor: pointer; text-align: left; }
        .investigation-finding:hover { border-color: var(--line-strong); background: var(--panel-hover); }
        .investigation-finding.active { border-color: rgba(242, 185, 95, 0.48); background: var(--amber-soft); }
        .investigation-finding strong { color: var(--text); font-size: 10px; line-height: 1.35; }
        .investigation-finding span { color: var(--subtle); font: 8.5px/1.4 ui-monospace, SFMono-Regular, Menlo, monospace; }
        .severity-critical { color: var(--red) !important; }
        .severity-high { color: var(--amber) !important; }
        .severity-medium, .severity-low { color: var(--blue) !important; }
        .investigation-node { --depth: 0; display: grid; grid-template-columns: 72px minmax(118px, 0.7fr) minmax(160px, 1.3fr) auto; gap: 8px; align-items: center; margin: 0 0 6px; padding: 8px 9px; border: 1px solid var(--line); border-left: 3px solid var(--line-strong); border-radius: 8px; background: rgba(7, 16, 23, 0.34); }
        .investigation-node.highlight { border-color: rgba(242, 185, 95, 0.5); border-left-color: var(--amber); background: var(--amber-soft); }
        .investigation-node.untrusted { border-left-color: var(--red); }
        .investigation-node-agent { color: var(--blue); font: 700 8.5px/1.4 ui-monospace, SFMono-Regular, Menlo, monospace; overflow-wrap: anywhere; }
        .investigation-node-type { color: var(--text); font-size: 9.5px; font-weight: 700; overflow-wrap: anywhere; }
        .investigation-node-link { color: var(--subtle); font: 8px/1.4 ui-monospace, SFMono-Regular, Menlo, monospace; overflow-wrap: anywhere; }
        .investigation-node-flags { display: flex; justify-content: flex-end; gap: 4px; flex-wrap: wrap; }
        .investigation-node-flags span { padding: 3px 5px; border-radius: 999px; color: var(--muted); background: rgba(143, 166, 175, 0.09); font-size: 7px; font-weight: 800; }
        .investigation-detail h3 { margin: 0 0 7px; font-size: 13px; line-height: 1.35; }
        .investigation-detail p { margin: 0 0 12px; color: var(--muted); font-size: 9.5px; line-height: 1.6; }
        .investigation-evidence { display: grid; gap: 5px; margin-bottom: 13px; }
        .investigation-evidence div { display: grid; grid-template-columns: 100px minmax(0, 1fr); gap: 8px; padding: 6px 7px; border: 1px solid rgba(32, 57, 71, 0.72); border-radius: 7px; }
        .investigation-evidence strong { color: var(--subtle); font-size: 8px; overflow-wrap: anywhere; }
        .investigation-evidence span { color: #bdcdd3; font: 8px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace; overflow-wrap: anywhere; }
        .investigation-remediation { margin: 0; padding-left: 17px; color: var(--muted); font-size: 9px; line-height: 1.55; }
        .investigation-path { margin-top: 13px; padding: 9px; border: 1px solid rgba(101, 174, 247, 0.25); border-radius: 8px; color: var(--blue); background: var(--blue-soft); font: 8px/1.55 ui-monospace, SFMono-Regular, Menlo, monospace; overflow-wrap: anywhere; }

        .feedback-card { min-width: 0; overflow: hidden; }
        .feedback-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 11px 18px; border-bottom: 1px solid var(--line); background: rgba(7, 16, 23, 0.28); }
        .feedback-toolbar p { margin: 0; color: var(--subtle); font-size: 9.5px; line-height: 1.5; }
        .feedback-summary { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 7px; padding: 12px 13px; border-bottom: 1px solid var(--line); }
        .feedback-grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); min-height: 205px; }
        .feedback-panel { min-width: 0; padding: 14px 16px; }
        .feedback-panel + .feedback-panel { border-left: 1px solid var(--line); }
        .feedback-panel h3 { margin: 0 0 4px; font-size: 12px; }
        .feedback-panel > p { margin: 0 0 11px; color: var(--subtle); font-size: 9px; line-height: 1.5; }
        .feedback-list { display: grid; gap: 6px; }
        .feedback-row { display: grid; grid-template-columns: minmax(115px, 0.65fr) minmax(0, 1.35fr) auto; gap: 8px; align-items: start; padding: 8px 9px; border: 1px solid var(--line); border-radius: 8px; background: rgba(7, 16, 23, 0.34); }
        .feedback-row strong { color: var(--text); font: 700 8.5px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace; overflow-wrap: anywhere; }
        .feedback-row span { color: var(--muted); font-size: 8.5px; line-height: 1.45; overflow-wrap: anywhere; }
        .feedback-row em { color: var(--amber); font: 800 8px/1.4 ui-monospace, SFMono-Regular, Menlo, monospace; text-transform: uppercase; }

        .content-grid { min-width: 0; display: grid; grid-template-columns: minmax(0, 1fr) 260px; gap: 16px; align-items: stretch; }
        .events-card { min-width: 0; min-height: 510px; display: flex; flex-direction: column; overflow: hidden; }
        .events-header { padding: 16px 17px 13px; border-bottom: 1px solid var(--line); }
        .events-title-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 13px; }
        .events-title-row h2 { margin: 0; font-size: 14px; }
        .events-title-row span { color: var(--subtle); font-size: 10px; }
        .toolbar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
        .filter-group { display: flex; padding: 3px; border: 1px solid var(--line); border-radius: 9px; background: rgba(7, 16, 23, 0.5); }
        .filter-button {
            height: 27px;
            padding: 0 9px;
            border: 0;
            border-radius: 6px;
            color: var(--subtle);
            background: transparent;
            cursor: pointer;
            font-size: 10px;
            font-weight: 700;
        }
        .filter-button.active { color: var(--text); background: var(--panel-hover); }
        .search-wrap { position: relative; flex: 1 1 150px; }
        .search-wrap input { width: 100%; height: 34px; padding: 0 11px 0 29px; border: 1px solid var(--line); border-radius: 9px; color: var(--text); background: rgba(7, 16, 23, 0.5); font-size: 11px; }
        .search-wrap::before { content: "⌕"; position: absolute; left: 10px; top: 6px; color: var(--subtle); font-size: 16px; pointer-events: none; }
        .tool-button { height: 34px; padding: 0 10px; border: 1px solid var(--line); border-radius: 9px; color: var(--muted); background: var(--panel-soft); cursor: pointer; font-size: 10px; font-weight: 700; }
        .tool-button:hover:not(:disabled) { color: var(--text); border-color: var(--line-strong); }
        .tool-button:disabled { opacity: 0.38; cursor: not-allowed; }
        .events-list {
            flex: 1;
            height: 410px;
            overflow: auto;
            padding: 7px 0 12px;
            scrollbar-color: var(--line-strong) transparent;
        }
        .event-row {
            display: grid;
            grid-template-columns: 62px 84px minmax(0, 1fr);
            align-items: start;
            gap: 10px;
            padding: 8px 16px;
            border-left: 2px solid transparent;
            transition: background 120ms ease;
        }
        .event-row:hover { background: rgba(23, 47, 59, 0.45); }
        .event-row[data-category="command"] { border-left-color: rgba(101, 174, 247, 0.58); }
        .event-row[data-category="anomaly"] { border-left-color: rgba(242, 185, 95, 0.65); }
        .event-time { padding-top: 3px; color: var(--subtle); font: 10px/1.4 ui-monospace, SFMono-Regular, Menlo, monospace; }
        .event-kind { justify-self: start; padding: 3px 7px; border-radius: 999px; color: var(--muted); background: rgba(143, 166, 175, 0.09); font-size: 8px; font-weight: 800; letter-spacing: 0.05em; text-transform: uppercase; }
        .event-row[data-category="command"] .event-kind { color: var(--blue); background: var(--blue-soft); }
        .event-row[data-category="anomaly"] .event-kind { color: var(--amber); background: var(--amber-soft); }
        .event-row[data-kind="error"] .event-kind { color: var(--red); background: var(--red-soft); }
        .event-message { min-width: 0; color: #c9d7dc; font: 10.5px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; overflow-wrap: anywhere; white-space: pre-wrap; }
        .empty-state { display: grid; place-items: center; min-height: 320px; padding: 40px; text-align: center; }
        .empty-state.hidden { display: none; }
        .empty-icon { width: 48px; height: 48px; display: grid; place-items: center; margin: 0 auto 13px; border: 1px solid var(--line); border-radius: 14px; color: var(--accent); background: var(--accent-soft); font: 700 17px ui-monospace, SFMono-Regular, Menlo, monospace; }
        .empty-state h3 { margin: 0 0 7px; font-size: 13px; }
        .empty-state p { max-width: 310px; margin: 0; color: var(--subtle); font-size: 10.5px; line-height: 1.6; }
        .events-footer { min-height: 36px; padding: 0 16px; display: flex; align-items: center; justify-content: space-between; border-top: 1px solid var(--line); color: var(--subtle); font-size: 9px; }
        .auto-scroll { display: flex; align-items: center; gap: 6px; cursor: pointer; }
        .auto-scroll input { accent-color: var(--accent); }

        .run-details { padding: 17px; display: flex; flex-direction: column; }
        .run-details h2 { margin: 0 0 14px; font-size: 14px; }
        .detail-list { margin: 0; }
        .detail-row { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 9px 0; border-bottom: 1px solid rgba(32, 57, 71, 0.72); }
        .detail-row dt { color: var(--subtle); font-size: 10px; }
        .detail-row dd { margin: 0; color: var(--text); font: 650 10px/1 ui-monospace, SFMono-Regular, Menlo, monospace; text-align: right; }
        .layer-box { margin-top: 17px; padding: 13px; border: 1px solid var(--line); border-radius: 11px; background: rgba(7, 16, 23, 0.42); }
        .layer-box strong { display: block; margin-bottom: 5px; font-size: 11px; }
        .layer-box p { margin: 0 0 11px; color: var(--subtle); font-size: 9.5px; line-height: 1.5; }
        .download-button {
            width: 100%;
            min-height: 35px;
            display: flex;
            align-items: center;
            justify-content: center;
            border: 1px solid rgba(66, 212, 181, 0.35);
            border-radius: 8px;
            color: var(--accent);
            background: var(--accent-soft);
            text-decoration: none;
            font-size: 10px;
            font-weight: 750;
        }
        .download-button.disabled { opacity: 0.36; pointer-events: none; }
        .artifact-actions { display: grid; gap: 7px; }
        .watch-list { margin: 17px 0 0; padding: 0; list-style: none; }
        .watch-list li { position: relative; padding: 0 0 10px 14px; color: var(--muted); font-size: 9.5px; line-height: 1.45; }
        .watch-list li::before { content: ""; position: absolute; left: 0; top: 5px; width: 5px; height: 5px; border-radius: 50%; background: var(--accent); }
        .toast {
            position: fixed;
            right: 22px;
            bottom: 22px;
            z-index: 50;
            max-width: min(360px, calc(100vw - 32px));
            padding: 11px 14px;
            border: 1px solid var(--line-strong);
            border-radius: 10px;
            color: var(--text);
            background: #132731;
            box-shadow: var(--shadow);
            font-size: 11px;
            opacity: 0;
            transform: translateY(8px);
            pointer-events: none;
            transition: 180ms ease;
        }
        .toast.visible { opacity: 1; transform: translateY(0); }

        @media (max-width: 1180px) {
            .content-grid { grid-template-columns: minmax(0, 1fr); }
            .run-details { display: grid; grid-template-columns: 1fr 1fr; gap: 0 22px; }
            .run-details h2 { grid-column: 1 / -1; }
            .layer-box { margin-top: 0; }
            .watch-list { grid-column: 1 / -1; display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
            .investigation-grid { grid-template-columns: 230px minmax(330px, 1fr); }
            .investigation-detail { grid-column: 1 / -1; border-left: 0; border-top: 1px solid var(--line); }
            .feedback-summary { grid-template-columns: repeat(3, minmax(0, 1fr)); }
        }
        @media (max-width: 860px) {
            .topbar { padding: 0 18px; }
            .app-shell { padding: 16px 18px 26px; grid-template-columns: 1fr; }
            .config-panel { position: static; }
            .config-form { display: grid; grid-template-columns: 1fr 1fr; gap: 0 18px; }
            .run-mode-control, .scenario-controls, .profile-section, .control.iterations, details.advanced, .form-error, .action-row, .safety-note { grid-column: 1 / -1; }
            .toggle-stack { grid-column: 1 / -1; }
            .debugger-grid { grid-template-columns: 1fr; }
            .debug-trace-list { max-height: 230px; border-right: 0; border-bottom: 1px solid var(--line); }
            .campaign-controls { grid-template-columns: 1fr 1fr; }
            .campaign-run { grid-column: 1 / -1; }
            .campaign-body { grid-template-columns: 1fr; }
            .campaign-history { border-left: 0; border-top: 1px solid var(--line); }
            .investigation-grid { grid-template-columns: 1fr; }
            .investigation-findings { max-height: 240px; border-right: 0; border-bottom: 1px solid var(--line); }
            .investigation-detail { grid-column: auto; }
            .feedback-grid { grid-template-columns: 1fr; }
            .feedback-panel + .feedback-panel { border-left: 0; border-top: 1px solid var(--line); }
        }
        @media (max-width: 620px) {
            .topbar { height: 64px; padding: 0 14px; }
            .brand-subtitle, .host-chip { display: none; }
            .app-shell { padding: 12px; gap: 12px; }
            .config-form { display: block; }
            .overview-top { align-items: center; }
            .overview-top p { display: none; }
            .run-clock strong { font-size: 16px; }
            .phase-rail { gap: 5px; }
            .phase { padding: 9px 7px; }
            .phase-name { font-size: 9px; }
            .metrics { grid-template-columns: repeat(2, 1fr); gap: 8px; }
            .debugger-header, .debug-detail-head { display: block; }
            .debugger-score { margin-top: 12px; text-align: left; }
            .debugger-toolbar { grid-template-columns: 1fr; }
            .debug-outcome { margin-top: 10px; grid-template-columns: repeat(3, 1fr); }
            .debug-event { grid-template-columns: 28px 70px minmax(0, 1fr); gap: 5px; }
            .campaign-header { display: block; }
            .campaign-version { display: block; margin-top: 10px; }
            .campaign-controls { grid-template-columns: 1fr; }
            .campaign-run { grid-column: auto; }
            .campaign-summary { grid-template-columns: repeat(2, 1fr); }
            .investigation-header { display: block; }
            .investigation-score { margin-top: 12px; text-align: left; }
            .investigation-toolbar { grid-template-columns: 1fr; }
            .investigation-summary { grid-template-columns: repeat(3, 1fr); }
            .investigation-node { grid-template-columns: 62px minmax(95px, 0.7fr) minmax(130px, 1.3fr); margin-left: 0; }
            .investigation-node-flags { grid-column: 1 / -1; justify-content: flex-start; }
            .feedback-toolbar { align-items: stretch; flex-direction: column; }
            .feedback-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
            .feedback-row { grid-template-columns: 1fr; }
            .metric { min-height: 75px; }
            .event-row { grid-template-columns: 48px 70px minmax(0, 1fr); gap: 6px; padding: 8px 10px; }
            .events-header { padding: 14px 12px 12px; }
            .filter-group { width: 100%; }
            .filter-button { flex: 1; }
            .tool-button { flex: 1; }
            .run-details { display: block; }
            .layer-box { margin-top: 16px; }
            .watch-list { display: block; }
        }
    </style>
</head>
<body>
    <header class="topbar">
        <div class="brand">
            <div class="brand-mark">A›</div>
            <div class="brand-copy">
                <div class="brand-name">AgentSim</div>
                <div class="brand-subtitle">Detection-First Adversary Emulation</div>
            </div>
        </div>
        <div class="topbar-meta">
            <div class="host-chip"><span id="host-os">Detecting host</span></div>
            <div class="status-pill{% if is_running %} running{% endif %}" id="status-pill">
                <span class="status-dot"></span>
                <span id="status-text">{% if is_running %}Running{% else %}Ready{% endif %}</span>
            </div>
        </div>
    </header>

    <main class="app-shell">
        <aside class="card config-panel">
            <div class="panel-header">
                <div class="eyebrow">Run configuration</div>
                <h2>Emulate, observe, detect</h2>
                <p>Preview bounded endpoint behavior, replay synthetic agentic attacks, or run an authorized campaign.</p>
            </div>

            <form class="config-form" id="simulation-form" action="/start" method="post">
                <input type="hidden" name="form_token" value="{{ form_token }}">

                <div class="run-mode-control">
                    <label for="run-mode">Lab mode</label>
                    <select class="mode-select" id="run-mode" name="run_mode">
                        <option value="behavior">Endpoint behavior</option>
                        <option value="scenario">Agentic attack scenarios</option>
                    </select>
                </div>

                <section class="scenario-controls hidden" id="scenario-controls">
                    <div class="field-block">
                        <label for="scenario">Scenario</label>
                        <select class="scenario-select" id="scenario" name="scenario">
                            <option value="all">All scenarios</option>
                            {% for scenario in scenarios %}
                            <option value="{{ scenario.scenario_id }}">{{ scenario.name }}</option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="field-block">
                        <label for="variant">Control set</label>
                        <select class="scenario-select" id="variant" name="variant">
                            <option value="both">Malicious + benign twins</option>
                            <option value="malicious">Malicious only</option>
                            <option value="benign">Benign controls only</option>
                        </select>
                    </div>
                    <div class="field-block">
                        <label for="mutations">Mutations per trace</label>
                        <select class="scenario-select" id="mutations" name="mutations">
                            <option value="0">Baseline only</option>
                            <option value="1">1 mutation</option>
                            <option value="3">3 mutations</option>
                            <option value="5">5 mutations</option>
                            <option value="10">10 mutations</option>
                        </select>
                    </div>
                    <div class="field-block">
                        <label for="mutation-seed">Mutation seed (optional)</label>
                        <input class="scenario-select" type="number" id="mutation-seed" name="mutation_seed" step="1" placeholder="Random">
                    </div>
                    <p class="scenario-copy">Simulation-only checkpoints. No tools, credentials, files, or network requests are executed.</p>
                </section>

                <section class="profile-section behavior-control">
                    <div class="section-label">Behavior profile <span id="profile-name">Balanced</span></div>
                    <div class="preset-grid" role="group" aria-label="Behavior presets">
                        <button class="preset active" type="button" data-preset="balanced">Balanced</button>
                        <button class="preset" type="button" data-preset="chaos">Chaos burst</button>
                        <button class="preset" type="button" data-preset="lineage">Lineage stress</button>
                        <button class="preset" type="button" data-preset="preview">Safe preview</button>
                    </div>
                    <p class="preset-description" id="preset-description">A safe preview with moderate retries and occasional agent mistakes.</p>
                </section>

                <div class="control iterations behavior-control">
                    <div class="control-head">
                        <label for="iterations">Agent cycles</label>
                        <output id="iterations-output" for="iterations">30</output>
                    </div>
                    <input type="range" id="iterations" name="iterations" min="1" max="100" value="30">
                    <div class="range-scale"><span>1</span><span>100 cycles</span></div>
                </div>

                <div class="control">
                    <div class="control-head">
                        <label for="speed">Delay between actions</label>
                        <output id="speed-output" for="speed">100 ms</output>
                    </div>
                    <input type="range" id="speed" name="speed" min="0" max="1000" step="10" value="100">
                    <div class="range-scale"><span>machine speed</span><span>1 second</span></div>
                </div>

                <details class="advanced behavior-control">
                    <summary>Behavior probabilities</summary>
                    <div class="advanced-content">
                        <div class="control">
                            <div class="control-head">
                                <label for="hallucination-rate">Cross-OS hallucination</label>
                                <output id="hallucination-output" for="hallucination-rate">15%</output>
                            </div>
                            <input type="range" id="hallucination-rate" name="hallucination_rate" min="0" max="1" step="0.05" value="0.15">
                        </div>
                        <div class="control">
                            <div class="control-head">
                                <label for="context-loss-rate">Context loss</label>
                                <output id="context-output" for="context-loss-rate">5%</output>
                            </div>
                            <input type="range" id="context-loss-rate" name="context_loss_rate" min="0" max="1" step="0.05" value="0.05">
                        </div>
                        <div class="control">
                            <div class="control-head">
                                <label for="retry-rate">Error retry / shell pivot</label>
                                <output id="retry-output" for="retry-rate">30%</output>
                            </div>
                            <input type="range" id="retry-rate" name="retry_rate" min="0" max="1" step="0.05" value="0.30">
                        </div>
                        <div class="control">
                            <div class="control-head">
                                <label for="evasion-rate">Nested-shell lineage</label>
                                <output id="evasion-output" for="evasion-rate">10%</output>
                            </div>
                            <input type="range" id="evasion-rate" name="evasion_rate" min="0" max="1" step="0.05" value="0.10">
                        </div>
                    </div>
                </details>

                <div class="field-row behavior-control">
                    <label for="seed">Reproducible seed</label>
                    <div class="seed-wrap">
                        <input class="seed-input" type="number" id="seed" name="seed" step="1" placeholder="Random">
                        <button class="icon-button" id="seed-button" type="button" title="Generate seed">New</button>
                    </div>
                </div>

                <div class="toggle-stack behavior-control">
                    <div class="toggle-row">
                        <div class="toggle-copy">
                            <strong>Dry run</strong>
                            <span>Select and log commands without executing them.</span>
                        </div>
                        <label class="switch">
                            <input type="checkbox" id="dry-run" name="dry_run" aria-label="Dry run" checked>
                            <span class="switch-track"></span>
                        </label>
                    </div>
                    <div class="toggle-row">
                        <div class="toggle-copy">
                            <strong>Cloud network actions</strong>
                            <span>Permit authenticated, read-only cloud CLI requests.</span>
                        </div>
                        <label class="switch">
                            <input type="checkbox" id="allow-network" name="allow_network" aria-label="Allow cloud network actions">
                            <span class="switch-track"></span>
                        </label>
                    </div>
                    <div class="network-warning" id="network-warning">Cloud CLIs may use your current AWS, Azure, or Google Cloud credentials. Enable only in an authorized test environment.</div>
                </div>

                <div class="form-error" id="form-error" role="alert"></div>
                <div class="action-row">
                    <button class="primary-button" id="start-button" type="submit" {% if is_running %}disabled{% endif %}>
                        {% if is_running %}Simulation running{% else %}Start simulation{% endif %}
                    </button>
                    <button class="danger-button" id="stop-button" type="button" {% if not is_running %}disabled{% endif %}>Stop</button>
                </div>
                <p class="safety-note" id="safety-note">Safe preview is the default. Local execution requires an explicit opt-in; directed campaigns additionally require scoped authorization.</p>
            </form>
        </aside>

        <section class="workspace">
            <section class="card run-overview">
                <div class="overview-top">
                    <div>
                        <div class="eyebrow">Live run</div>
                        <h1 id="run-heading">Ready for a simulation</h1>
                        <p id="run-subtitle">Configure a behavior profile and start generating endpoint process telemetry.</p>
                    </div>
                    <div class="run-clock">
                        <span>Elapsed</span>
                        <strong id="elapsed-time">00:00</strong>
                    </div>
                </div>
                <div class="progress-track" aria-label="Run progress">
                    <div class="progress-value" id="progress-value"></div>
                </div>
                <div class="phase-rail">
                    <div class="phase" data-phase-index="0">
                        <span class="phase-index">01</span>
                        <span class="phase-name" id="phase-name-0">Host discovery</span>
                    </div>
                    <div class="phase" data-phase-index="1">
                        <span class="phase-index">02</span>
                        <span class="phase-name" id="phase-name-1">Privilege &amp; network</span>
                    </div>
                    <div class="phase" data-phase-index="2">
                        <span class="phase-index">03</span>
                        <span class="phase-name" id="phase-name-2">Cloud services</span>
                    </div>
                </div>
            </section>

            <section class="metrics" aria-label="Run metrics">
                <div class="metric cycles">
                    <span class="metric-label" id="cycles-label">Cycles</span>
                    <strong class="metric-value" id="cycles-metric">0 / 30</strong>
                    <span class="metric-foot" id="cycles-foot">OODA loops observed</span>
                </div>
                <div class="metric commands">
                    <span class="metric-label" id="commands-label">Commands</span>
                    <strong class="metric-value" id="commands-metric">0</strong>
                    <span class="metric-foot" id="commands-foot">process actions selected</span>
                </div>
                <div class="metric anomalies">
                    <span class="metric-label" id="anomalies-label">Agent signals</span>
                    <strong class="metric-value" id="anomalies-metric">0</strong>
                    <span class="metric-foot" id="anomalies-foot">mistakes, pivots, lineage</span>
                </div>
                <div class="metric skipped">
                    <span class="metric-label" id="skipped-label">Guarded</span>
                    <strong class="metric-value" id="skipped-metric">0</strong>
                    <span class="metric-foot" id="skipped-foot">network actions blocked</span>
                </div>
            </section>

            <section class="card campaign-card" id="campaign-foundation" aria-label="Adversary campaign foundation">
                <div class="campaign-header">
                    <div>
                        <div class="eyebrow">Emulate → Observe → Detect → Defend → Retest</div>
                        <h2>Authorized campaign foundation</h2>
                        <p>Run a directed campaign through authorization, provider preparation, lifecycle-v3 ground truth, cleanup verification, defense recommendations, and persistent history. The dashboard exposes simulation only.</p>
                    </div>
                    <span class="campaign-version">v1.5.0</span>
                </div>
                <div class="campaign-controls">
                    <select id="campaign-select" aria-label="Campaign">
                        {% for campaign in campaigns %}
                        <option value="{{ campaign.campaign_id }}"{% if campaign.campaign_id == "endpoint-discovery-baseline" %} selected{% endif %}>{{ campaign.name }} · {{ campaign.steps|length }} abilities</option>
                        {% endfor %}
                    </select>
                    <div class="campaign-target">synthetic://dashboard</div>
                    <button class="primary-button campaign-run" id="campaign-run" type="button">Run safe campaign</button>
                </div>
                <div class="campaign-body">
                    <div class="campaign-result" id="campaign-result">
                        <div class="debug-placeholder">Choose a campaign to generate an authorized, non-executing lifecycle trace.</div>
                    </div>
                    <div class="campaign-history">
                        <div class="campaign-section-label">Persistent run history</div>
                        <div class="history-list" id="campaign-history">
                            <div class="debug-placeholder">No campaign runs recorded yet.</div>
                        </div>
                    </div>
                </div>
            </section>

            <section class="card campaign-card" id="defense-validation" aria-label="Detection and agentic validation">
                <div class="campaign-header">
                    <div>
                        <div class="eyebrow">Detection validation engine</div>
                        <h2>Validate visibility and agent safeguards</h2>
                        <p>Exercise a generated candidate against redacted synthetic telemetry, inspect field coverage and gaps, or run twenty-two instrumented malicious/benign agentic control pairs. Nothing here starts a host process or opens an external network connection.</p>
                    </div>
                    <span class="campaign-version">v1.5 feedback-aware</span>
                </div>
                <div class="campaign-controls">
                    <select id="v1-ability-select" aria-label="Detection validation ability">
                        {% for ability in abilities %}
                        <option value="{{ ability.ability_id }}"{% if ability.ability_id == "endpoint.discovery.processes" %} selected{% endif %}>{{ ability.name }}</option>
                        {% endfor %}
                    </select>
                    <button class="primary-button campaign-run" id="v1-detection-run" type="button">Validate detection</button>
                    <button class="tool-button" id="v1-assurance-run" type="button">Check telemetry assurance</button>
                    <button class="tool-button" id="v1-lab-run" type="button">Run reference lab</button>
                </div>
                <div class="campaign-result" id="v1-validation-result">
                    <div class="debug-placeholder">Choose an ability to inspect a candidate rule, evidence, field coverage, and defensive guidance.</div>
                </div>
            </section>

            <section class="card feedback-card" id="feedback-integrity" aria-label="Detection feedback integrity and drift">
                <div class="campaign-header">
                    <div>
                        <div class="eyebrow">Human verdict integrity</div>
                        <h2>Detection feedback and tuning drift</h2>
                        <p>Reconcile alerts to causal traces, verify structured operator annotations, and compare offline tuning candidates against malicious and benign baselines before any suppression is accepted.</p>
                    </div>
                    <span class="campaign-version">v1.5 feedback-aware</span>
                </div>
                <div class="feedback-toolbar">
                    <p>Fixed synthetic corpus · no prompts, free-form notes, processes, network, or configuration deployment.</p>
                    <button class="primary-button campaign-run" id="feedback-run" type="button">Analyze feedback loop</button>
                </div>
                <div class="feedback-summary" id="feedback-summary">
                    <div class="investigation-stat"><strong>—</strong><span>alert match</span></div>
                    <div class="investigation-stat"><strong>—</strong><span>annotation coverage</span></div>
                    <div class="investigation-stat"><strong>—</strong><span>conflicts</span></div>
                    <div class="investigation-stat"><strong>—</strong><span>feedback score</span></div>
                    <div class="investigation-stat"><strong>—</strong><span>drift score</span></div>
                    <div class="investigation-stat"><strong>—</strong><span>candidate status</span></div>
                </div>
                <div class="feedback-grid">
                    <div class="feedback-panel">
                        <h3>Verdict conflicts</h3>
                        <p>Identity, evidence, trace, and reviewer checks that must resolve before tuning.</p>
                        <div class="feedback-list" id="feedback-conflicts">
                            <div class="debug-placeholder">Analyze the fixed fixture to inspect feedback conflicts.</div>
                        </div>
                    </div>
                    <div class="feedback-panel">
                        <h3>Offline drift gate</h3>
                        <p>Candidate deltas measured against the reviewed malicious and benign baseline.</p>
                        <div class="feedback-list" id="feedback-drift">
                            <div class="debug-placeholder">Recall, false-positive rate, reconciliation, and latency deltas will appear here.</div>
                        </div>
                    </div>
                </div>
            </section>

            <section class="card investigation-card" id="multi-agent-investigation" aria-label="Multi-agent investigation workbench">
                <div class="investigation-header">
                    <div>
                        <div class="eyebrow">Causal graph investigation</div>
                        <h2>Multi-agent investigation workbench</h2>
                        <p>Reconstruct agent handoffs, shared-memory lineage, goal fingerprints, and policy outcomes. Select a finding to highlight its causal evidence and operator remediation without exposing prompts, arguments, or tool results.</p>
                    </div>
                    <div class="investigation-score">
                        <strong id="investigation-score">—</strong>
                        <span id="investigation-status">Build the graph</span>
                    </div>
                </div>
                <div class="investigation-toolbar">
                    <select id="investigation-trace" aria-label="Investigation trace">
                        <option value="">Build an investigation to select a trace</option>
                    </select>
                    <select id="investigation-severity" aria-label="Finding severity">
                        <option value="all">All severities</option>
                        <option value="critical">Critical only</option>
                        <option value="high">High only</option>
                    </select>
                    <button class="primary-button campaign-run" id="investigation-run" type="button">Build investigation</button>
                </div>
                <div class="investigation-summary" id="investigation-summary">
                    <div class="investigation-stat"><strong>—</strong><span>events</span></div>
                    <div class="investigation-stat"><strong>—</strong><span>agents</span></div>
                    <div class="investigation-stat"><strong>—</strong><span>delegations</span></div>
                    <div class="investigation-stat"><strong>—</strong><span>graph depth</span></div>
                    <div class="investigation-stat"><strong>—</strong><span>findings</span></div>
                    <div class="investigation-stat"><strong>—</strong><span>attack paths</span></div>
                </div>
                <div class="investigation-grid">
                    <div class="investigation-findings" id="investigation-findings">
                        <div class="debug-placeholder">Build the reference graph to review invariant failures.</div>
                    </div>
                    <div class="investigation-graph" id="investigation-graph">
                        <div class="debug-placeholder">Agent lanes and causal relationships will appear here.</div>
                    </div>
                    <div class="investigation-detail" id="investigation-detail">
                        <div class="debug-placeholder">Select a finding to inspect evidence and remediation.</div>
                    </div>
                </div>
            </section>

            <section class="card debugger-card hidden" id="detection-debugger" aria-label="Detection debugger">
                <div class="debugger-header">
                    <div>
                        <div class="eyebrow">Human analysis</div>
                        <h2>Detection debugger</h2>
                        <p>Inspect reference-rule conditions, signal checkpoints, control outcomes, and detection latency for each trace.</p>
                    </div>
                    <div class="debugger-score">
                        <strong id="debugger-score">—</strong>
                        <span id="debugger-score-label">Run a scenario suite</span>
                    </div>
                </div>
                <div class="debugger-toolbar">
                    <select id="debug-result-filter" aria-label="Detection result filter">
                        <option value="all">All trace results</option>
                        <option value="failed">Detection mismatches</option>
                        <option value="malicious">Malicious traces</option>
                        <option value="benign">Benign controls</option>
                        <option value="mutated">Mutations only</option>
                    </select>
                    <input type="search" id="debug-search" aria-label="Search detection traces" placeholder="Search scenario or trace ID">
                    <button class="tool-button" id="debug-refresh" type="button">Refresh results</button>
                </div>
                <div class="debugger-grid">
                    <div class="debug-trace-list" id="debug-trace-list">
                        <div class="debug-placeholder">Run a scenario suite to inspect detection decisions.</div>
                    </div>
                    <div class="debug-detail" id="debug-detail">
                        <div class="debug-placeholder">Select a trace to explain why its reference detector did or did not fire.</div>
                    </div>
                </div>
            </section>

            <section class="content-grid">
                <section class="card events-card">
                    <div class="events-header">
                        <div class="events-title-row">
                            <h2 id="event-stream-heading">Behavior event stream</h2>
                            <span id="event-count">0 events</span>
                        </div>
                        <div class="toolbar">
                            <div class="filter-group" role="group" aria-label="Event filters">
                                <button class="filter-button active" type="button" data-filter="all">All</button>
                                <button class="filter-button" id="command-filter" type="button" data-filter="command">Commands</button>
                                <button class="filter-button" type="button" data-filter="anomaly">Signals</button>
                                <button class="filter-button" type="button" data-filter="system">System</button>
                            </div>
                            <label class="search-wrap">
                                <span hidden>Search events</span>
                                <input type="search" id="event-search" aria-label="Search events" placeholder="Filter command or message">
                            </label>
                            <button class="tool-button" id="copy-button" type="button">Copy log</button>
                            <button class="tool-button" id="clear-button" type="button" {% if is_running %}disabled{% endif %}>Clear</button>
                        </div>
                    </div>
                    <div class="events-list" id="events-list" role="log" aria-live="polite">
                        <div class="empty-state" id="empty-state">
                            <div>
                                <div class="empty-icon">_›</div>
                                <h3 id="empty-heading">No telemetry yet</h3>
                                <p id="empty-copy">Start a run to see phase transitions, selected commands, context loss, retries, and safety-gate events as they happen.</p>
                            </div>
                        </div>
                    </div>
                    <div class="events-footer">
                        <span id="connection-status">Connecting to local stream…</span>
                        <label class="auto-scroll"><input type="checkbox" id="auto-scroll" checked> Follow latest</label>
                    </div>
                </section>

                <aside class="card run-details">
                    <h2>Run details</h2>
                    <dl class="detail-list">
                        <div class="detail-row"><dt id="detail-profile-label">Profile</dt><dd id="detail-profile">Balanced</dd></div>
                        <div class="detail-row"><dt>Mode</dt><dd id="detail-mode">Execute local</dd></div>
                        <div class="detail-row"><dt id="detail-seed-label">Seed</dt><dd id="detail-seed">Random</dd></div>
                        <div class="detail-row"><dt>Speed</dt><dd id="detail-speed">100 ms</dd></div>
                        <div class="detail-row"><dt>Cloud</dt><dd id="detail-cloud">Guarded</dd></div>
                    </dl>
                    <div class="layer-box" id="layer-artifact">
                        <strong>ATT&amp;CK Navigator layer</strong>
                        <p id="layer-status">Available after the run completes or is stopped.</p>
                        <a class="download-button disabled" id="download-layer" href="/download-layer" aria-disabled="true">Download layer JSON</a>
                    </div>
                    <div class="layer-box hidden" id="scenario-artifacts">
                        <strong>Scenario evidence</strong>
                        <p id="scenario-artifact-status">Available after the scenario suite completes or is stopped.</p>
                        <div class="artifact-actions">
                            <a class="download-button disabled" id="download-bundle" href="/download-bundle" aria-disabled="true">Download evidence bundle</a>
                            <a class="download-button disabled" id="download-ground-truth" href="/download-ground-truth" aria-disabled="true">Download ground truth JSONL</a>
                            <a class="download-button disabled" id="download-validation" href="/download-validation" aria-disabled="true">Download validation report</a>
                        </div>
                    </div>
                    <ul class="watch-list">
                        <li id="watch-item-0">Use Signals to isolate hallucinations, context loss, and retry behavior.</li>
                        <li id="watch-item-1">Use Commands to compare process telemetry with your EDR or SIEM.</li>
                        <li id="watch-item-2">Reuse a seed when validating detection changes against the same run.</li>
                    </ul>
                </aside>
            </section>
        </section>
    </main>

    <div class="toast" id="toast" role="status"></div>

    <script>
        const FORM_TOKEN = {{ form_token | tojson }};
        const INITIAL_RUNNING = {{ is_running | tojson }};
        const SCENARIO_COUNTS = {{ scenario_counts | tojson }};

        const profiles = {
            balanced: {
                label: "Balanced",
                description: "A safe preview with moderate retries and occasional agent mistakes.",
                iterations: 30, speed: 100, hallucination: 0.15, context: 0.05, retry: 0.30, evasion: 0.10, dryRun: true
            },
            chaos: {
                label: "Chaos burst",
                description: "High-velocity mistakes and context loss for burst and cross-OS detections.",
                iterations: 60, speed: 30, hallucination: 0.40, context: 0.25, retry: 0.65, evasion: 0.25, dryRun: false
            },
            lineage: {
                label: "Lineage stress",
                description: "Frequent nested shells to exercise process-tree and parent-child analytics.",
                iterations: 50, speed: 70, hallucination: 0.05, context: 0.05, retry: 0.25, evasion: 0.70, dryRun: false
            },
            preview: {
                label: "Safe preview",
                description: "Explore every phase quickly without executing any operating-system command.",
                iterations: 30, speed: 0, hallucination: 0.15, context: 0.05, retry: 0.30, evasion: 0.10, dryRun: true
            }
        };

        const elements = {
            form: document.getElementById("simulation-form"),
            start: document.getElementById("start-button"),
            stop: document.getElementById("stop-button"),
            clear: document.getElementById("clear-button"),
            copy: document.getElementById("copy-button"),
            error: document.getElementById("form-error"),
            statusPill: document.getElementById("status-pill"),
            statusText: document.getElementById("status-text"),
            hostOs: document.getElementById("host-os"),
            runHeading: document.getElementById("run-heading"),
            runSubtitle: document.getElementById("run-subtitle"),
            elapsed: document.getElementById("elapsed-time"),
            progress: document.getElementById("progress-value"),
            events: document.getElementById("events-list"),
            empty: document.getElementById("empty-state"),
            eventCount: document.getElementById("event-count"),
            connection: document.getElementById("connection-status"),
            search: document.getElementById("event-search"),
            autoScroll: document.getElementById("auto-scroll"),
            network: document.getElementById("allow-network"),
            networkWarning: document.getElementById("network-warning"),
            dryRun: document.getElementById("dry-run"),
            seed: document.getElementById("seed"),
            runMode: document.getElementById("run-mode"),
            scenario: document.getElementById("scenario"),
            variant: document.getElementById("variant"),
            mutations: document.getElementById("mutations"),
            mutationSeed: document.getElementById("mutation-seed"),
            scenarioControls: document.getElementById("scenario-controls"),
            download: document.getElementById("download-layer"),
            layerStatus: document.getElementById("layer-status"),
            layerArtifact: document.getElementById("layer-artifact"),
            scenarioArtifacts: document.getElementById("scenario-artifacts"),
            groundTruthDownload: document.getElementById("download-ground-truth"),
            validationDownload: document.getElementById("download-validation"),
            bundleDownload: document.getElementById("download-bundle"),
            scenarioArtifactStatus: document.getElementById("scenario-artifact-status"),
            debugger: document.getElementById("detection-debugger"),
            debuggerScore: document.getElementById("debugger-score"),
            debuggerScoreLabel: document.getElementById("debugger-score-label"),
            debugResultFilter: document.getElementById("debug-result-filter"),
            debugSearch: document.getElementById("debug-search"),
            debugRefresh: document.getElementById("debug-refresh"),
            debugTraceList: document.getElementById("debug-trace-list"),
            debugDetail: document.getElementById("debug-detail"),
            campaignSelect: document.getElementById("campaign-select"),
            campaignRun: document.getElementById("campaign-run"),
            campaignResult: document.getElementById("campaign-result"),
            campaignHistory: document.getElementById("campaign-history"),
            v1Ability: document.getElementById("v1-ability-select"),
            v1DetectionRun: document.getElementById("v1-detection-run"),
            v1AssuranceRun: document.getElementById("v1-assurance-run"),
            v1LabRun: document.getElementById("v1-lab-run"),
            v1Result: document.getElementById("v1-validation-result"),
            feedbackRun: document.getElementById("feedback-run"),
            feedbackSummary: document.getElementById("feedback-summary"),
            feedbackConflicts: document.getElementById("feedback-conflicts"),
            feedbackDrift: document.getElementById("feedback-drift"),
            investigationRun: document.getElementById("investigation-run"),
            investigationTrace: document.getElementById("investigation-trace"),
            investigationSeverity: document.getElementById("investigation-severity"),
            investigationScore: document.getElementById("investigation-score"),
            investigationStatus: document.getElementById("investigation-status"),
            investigationSummary: document.getElementById("investigation-summary"),
            investigationFindings: document.getElementById("investigation-findings"),
            investigationGraph: document.getElementById("investigation-graph"),
            investigationDetail: document.getElementById("investigation-detail"),
            eventStreamHeading: document.getElementById("event-stream-heading"),
            commandFilter: document.getElementById("command-filter"),
            emptyHeading: document.getElementById("empty-heading"),
            emptyCopy: document.getElementById("empty-copy"),
            toast: document.getElementById("toast")
        };

        const state = {
            running: INITIAL_RUNNING,
            events: [],
            seenIds: new Set(),
            filter: "all",
            search: "",
            mode: "behavior",
            profile: "balanced",
            totalIterations: Number(document.getElementById("iterations").value),
            currentCycle: 0,
            commandCount: 0,
            anomalyCount: 0,
            skippedCount: 0,
            currentPhase: -1,
            startedAt: null,
            elapsedTimer: null,
            debugData: null,
            debugRunId: null,
            selectedDebugTrace: null,
            debugLoading: false,
            campaignLoading: false,
            feedbackLoading: false,
            investigationData: null,
            selectedInvestigationTrace: null,
            selectedInvestigationFinding: null,
            investigationLoading: false
        };

        const rateControls = [
            ["hallucination-rate", "hallucination-output"],
            ["context-loss-rate", "context-output"],
            ["retry-rate", "retry-output"],
            ["evasion-rate", "evasion-output"]
        ];

        const kindLabels = {
            cycle: "Cycle", phase: "Phase", command: "Execute", dry_command: "Preview",
            hallucination: "Wrong OS", context_loss: "Context", evasion: "Lineage",
            retry: "Retry", skipped: "Guarded", stop_requested: "Stop",
            stopped: "Stopped", error: "Error", complete: "Complete", export: "Export",
            scenario: "Scenario", checkpoint: "Check", tool: "Tool", blocked: "Blocked",
            start: "Start", environment: "Host", warning: "Notice", info: "System"
        };

        function selectedScenarioCount() {
            const counts = SCENARIO_COUNTS[elements.scenario.value] || SCENARIO_COUNTS.all;
            const baseline = Number(counts[elements.variant.value] || counts.both || 1);
            const mutationCount = Number(elements.mutations.value || 0);
            const scenarioCount = elements.scenario.value === "all" ? {{ scenario_total }} : 1;
            const variantsPerScenario = elements.variant.value === "both" ? 2 : 1;
            return baseline * (mutationCount + 1) + scenarioCount * variantsPerScenario * mutationCount;
        }

        function textNode(tag, className, value) {
            const node = document.createElement(tag);
            if (className) node.className = className;
            node.textContent = value == null ? "—" : String(value);
            return node;
        }

        function setCampaignPlaceholder(container, message) {
            container.replaceChildren(textNode("div", "debug-placeholder", message));
        }

        function renderCampaignHistory(runs) {
            if (!Array.isArray(runs) || !runs.length) {
                setCampaignPlaceholder(elements.campaignHistory, "No campaign runs recorded yet.");
                return;
            }
            const fragment = document.createDocumentFragment();
            runs.slice(0, 8).forEach(function (run) {
                const row = document.createElement("div");
                row.className = "history-run";
                const identity = document.createElement("div");
                identity.appendChild(textNode("strong", "", run.campaign_id));
                identity.appendChild(textNode("span", "", run.mode + " · " + run.run_id.slice(0, 10)));
                row.appendChild(identity);
                row.appendChild(textNode("span", "", run.status));
                fragment.appendChild(row);
            });
            elements.campaignHistory.replaceChildren(fragment);
        }

        function renderCampaignResult(payload) {
            const summary = payload.summary || {};
            const container = document.createDocumentFragment();
            container.appendChild(textNode("div", "campaign-section-label", payload.campaign_name || payload.campaign_id));
            const stats = document.createElement("div");
            stats.className = "campaign-summary";
            [
                [summary.verified_actions || 0, "verified"],
                [summary.executed_actions || 0, "executed"],
                [summary.pending_detection_results || 0, "awaiting SIEM"],
                [summary.cleanup_failures || 0, "cleanup gaps"]
            ].forEach(function (item) {
                const stat = document.createElement("div");
                stat.className = "campaign-stat";
                stat.appendChild(textNode("strong", "", item[0]));
                stat.appendChild(textNode("span", "", item[1]));
                stats.appendChild(stat);
            });
            container.appendChild(stats);
            const timeline = document.createElement("div");
            timeline.className = "campaign-timeline";
            const keyStates = new Set(["authorized", "simulated", "executed", "prevented", "detection_pending", "detected", "missed", "cleaned", "cleanup_failed", "verified", "failed"]);
            const events = (Array.isArray(payload.events) ? payload.events : []).filter(function (event) {
                return keyStates.has(event.lifecycle_state);
            }).slice(-12);
            events.forEach(function (event) {
                const row = document.createElement("div");
                row.className = "campaign-event";
                row.appendChild(textNode("strong", "", event.lifecycle_state));
                row.appendChild(textNode("span", "", event.ability_id + " · " + event.outcome));
                timeline.appendChild(row);
            });
            container.appendChild(timeline);
            elements.campaignResult.replaceChildren(container);
            renderCampaignHistory(payload.history);
        }

        async function loadCampaignFoundation() {
            try {
                const response = await fetch("/api/v1/catalog", {headers: {"Accept": "application/json"}});
                if (!response.ok) throw new Error();
                const payload = await response.json();
                renderCampaignHistory(payload.history);
            } catch (_error) {
                setCampaignPlaceholder(elements.campaignHistory, "Unable to read persistent campaign history.");
            }
        }

        async function runSafeCampaign() {
            if (state.campaignLoading) return;
            state.campaignLoading = true;
            elements.campaignRun.disabled = true;
            elements.campaignRun.textContent = "Running lifecycle…";
            setCampaignPlaceholder(elements.campaignResult, "Authorizing and simulating the campaign…");
            try {
                const response = await fetch("/api/v1/campaign/simulate", {
                    method: "POST",
                    headers: {
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "X-AgentSim-Form-Token": FORM_TOKEN
                    },
                    body: JSON.stringify({campaign_id: elements.campaignSelect.value})
                });
                if (!response.ok) throw new Error();
                renderCampaignResult(await response.json());
                showToast("Safe campaign lifecycle recorded");
            } catch (_error) {
                setCampaignPlaceholder(elements.campaignResult, "Campaign simulation failed inside the safety boundary.");
            } finally {
                state.campaignLoading = false;
                elements.campaignRun.disabled = false;
                elements.campaignRun.textContent = "Run safe campaign";
            }
        }

        function renderV1Detection(payload) {
            const container = document.createDocumentFragment();
            const evaluation = payload.evaluation || {};
            const coverage = payload.coverage || {};
            const findings = Array.isArray(payload.findings) ? payload.findings : [];
            container.appendChild(textNode("div", "campaign-section-label", "Synthetic validation · human review candidate"));
            const stats = document.createElement("div");
            stats.className = "campaign-summary";
            [
                [evaluation.matched ? "yes" : "no", "candidate matched"],
                [coverage.coverage_percent || 0, "field coverage %"],
                [evaluation.match_count || 0, "evidence events"],
                [findings.length, "open gaps"]
            ].forEach(function (item) {
                const stat = document.createElement("div");
                stat.className = "campaign-stat";
                stat.appendChild(textNode("strong", "", item[0]));
                stat.appendChild(textNode("span", "", item[1]));
                stats.appendChild(stat);
            });
            container.appendChild(stats);
            container.appendChild(textNode("div", "debug-placeholder", findings.length
                ? findings.map(function (item) { return item.title; }).join(" · ")
                : "Expected telemetry fields are present and the candidate matched. Tune against real benign baselines before deployment."));
            elements.v1Result.replaceChildren(container);
        }

        async function runV1Detection() {
            elements.v1DetectionRun.disabled = true;
            setCampaignPlaceholder(elements.v1Result, "Evaluating a candidate against redacted synthetic telemetry…");
            try {
                const response = await fetch("/api/v1/detection/demo", {
                    method: "POST",
                    headers: {"Accept": "application/json", "Content-Type": "application/json", "X-AgentSim-Form-Token": FORM_TOKEN},
                    body: JSON.stringify({ability_id: elements.v1Ability.value})
                });
                if (!response.ok) throw new Error();
                renderV1Detection(await response.json());
            } catch (_error) {
                setCampaignPlaceholder(elements.v1Result, "Detection validation failed inside the synthetic boundary.");
            } finally {
                elements.v1DetectionRun.disabled = false;
            }
        }

        function renderV1Assurance(payload) {
            const assurance = payload.assurance || {};
            const sweep = payload.sweep || {};
            const summary = sweep.summary || {};
            const findings = Array.isArray(assurance.findings) ? assurance.findings : [];
            const container = document.createDocumentFragment();
            container.appendChild(textNode("div", "campaign-section-label", "Telemetry assurance · synthetic reference corpus"));
            const stats = document.createElement("div");
            stats.className = "campaign-summary";
            [
                [assurance.score || 0, "assurance score"],
                [assurance.status || "unknown", "evidence status"],
                [summary.detected || 0, "pack rules detected"],
                [summary.visibility_gap || 0, "visibility gaps"]
            ].forEach(function (item) {
                const stat = document.createElement("div");
                stat.className = "campaign-stat";
                stat.appendChild(textNode("strong", "", item[0]));
                stat.appendChild(textNode("span", "", item[1]));
                stats.appendChild(stat);
            });
            container.appendChild(stats);
            container.appendChild(textNode("div", "debug-placeholder", findings.length
                ? findings.map(function (item) { return item.title; }).join(" · ")
                : "Correlation links, source identities, timestamps, and content-redaction boundaries passed. Visibility gaps identify fields the corpus does not provide; they are not treated as clean results."));
            elements.v1Result.replaceChildren(container);
        }

        async function runV1Assurance() {
            elements.v1AssuranceRun.disabled = true;
            setCampaignPlaceholder(elements.v1Result, "Checking trace integrity and sweeping the built-in agent-security detection pack…");
            try {
                const response = await fetch("/api/v1/telemetry/assurance", {
                    method: "POST",
                    headers: {"Accept": "application/json", "Content-Type": "application/json", "X-AgentSim-Form-Token": FORM_TOKEN},
                    body: JSON.stringify({corpus: "reference-agent"})
                });
                if (!response.ok) throw new Error();
                renderV1Assurance(await response.json());
            } catch (_error) {
                setCampaignPlaceholder(elements.v1Result, "Telemetry assurance failed inside the synthetic boundary.");
            } finally {
                elements.v1AssuranceRun.disabled = false;
            }
        }

        function feedbackRow(identity, detail, status) {
            const row = document.createElement("div");
            row.className = "feedback-row";
            row.appendChild(textNode("strong", "", identity));
            row.appendChild(textNode("span", "", detail));
            row.appendChild(textNode("em", "", status));
            return row;
        }

        function renderFeedbackAnalysis(payload) {
            const feedback = payload.feedback || {};
            const drift = payload.drift || {};
            const summary = feedback.summary || {};
            const summaryValues = [
                [String(summary.match_rate_percent || 0) + "%", "alert match"],
                [String(summary.annotation_coverage_percent || 0) + "%", "annotation coverage"],
                [summary.conflicts || 0, "conflicts"],
                [String(feedback.score || 0) + " / 100", "feedback score"],
                [String(drift.score || 0) + " / 100", "drift score"],
                [drift.status || "unknown", "candidate status"]
            ];
            const stats = document.createDocumentFragment();
            summaryValues.forEach(function (item) {
                const stat = document.createElement("div");
                stat.className = "investigation-stat";
                stat.appendChild(textNode("strong", "", item[0]));
                stat.appendChild(textNode("span", "", item[1]));
                stats.appendChild(stat);
            });
            elements.feedbackSummary.replaceChildren(stats);

            const conflicts = Array.isArray(feedback.conflicts) ? feedback.conflicts : [];
            if (!conflicts.length) {
                setCampaignPlaceholder(elements.feedbackConflicts, "No feedback integrity conflicts were found.");
            } else {
                const values = document.createDocumentFragment();
                conflicts.forEach(function (item) {
                    values.appendChild(feedbackRow(
                        item.code,
                        (item.remediation || ["Review the structured evidence binding."])[0],
                        item.severity
                    ));
                });
                elements.feedbackConflicts.replaceChildren(values);
            }

            const findings = Array.isArray(drift.findings) ? drift.findings : [];
            if (!findings.length) {
                setCampaignPlaceholder(elements.feedbackDrift, "The tuning candidate remained inside every regression threshold.");
            } else {
                const values = document.createDocumentFragment();
                findings.forEach(function (item) {
                    const direction = Number(item.delta) >= 0 ? "+" : "";
                    values.appendChild(feedbackRow(
                        item.metric.replaceAll("_", " "),
                        "baseline " + item.baseline + " → candidate " + item.candidate
                            + " · delta " + direction + item.delta + " · limit " + item.threshold,
                        item.severity
                    ));
                });
                elements.feedbackDrift.replaceChildren(values);
            }
        }

        async function runFeedbackAnalysis() {
            if (state.feedbackLoading) return;
            state.feedbackLoading = true;
            elements.feedbackRun.disabled = true;
            elements.feedbackRun.textContent = "Reconciling…";
            setCampaignPlaceholder(elements.feedbackConflicts, "Binding alerts, evidence, traces, and structured verdicts…");
            setCampaignPlaceholder(elements.feedbackDrift, "Comparing the offline tuning candidate to both baselines…");
            try {
                const response = await fetch("/api/v1/defense/feedback-demo", {
                    method: "POST",
                    headers: {"Accept": "application/json", "Content-Type": "application/json", "X-AgentSim-Form-Token": FORM_TOKEN},
                    body: JSON.stringify({corpus: "detection-feedback-integrity"})
                });
                if (!response.ok) throw new Error();
                renderFeedbackAnalysis(await response.json());
                showToast("Feedback reconciliation and drift report ready");
            } catch (_error) {
                setCampaignPlaceholder(elements.feedbackConflicts, "Unable to reconcile the synthetic feedback fixture.");
                setCampaignPlaceholder(elements.feedbackDrift, "Unable to compare the offline tuning candidate.");
            } finally {
                state.feedbackLoading = false;
                elements.feedbackRun.disabled = false;
                elements.feedbackRun.textContent = "Analyze feedback loop";
            }
        }

        async function runV1Lab() {
            elements.v1LabRun.disabled = true;
            setCampaignPlaceholder(elements.v1Result, "Running twenty-two instrumented reference-agent fixtures…");
            try {
                const response = await fetch("/api/v1/lab/reference", {
                    method: "POST",
                    headers: {"Accept": "application/json", "Content-Type": "application/json", "X-AgentSim-Form-Token": FORM_TOKEN},
                    body: JSON.stringify({fixture_id: "all"})
                });
                if (!response.ok) throw new Error();
                const payload = await response.json();
                const results = Array.isArray(payload.results) ? payload.results : [];
                setCampaignPlaceholder(elements.v1Result, results.filter(function (item) { return item.passed; }).length
                    + " / " + results.length + " reference-agent controls passed; only resettable in-memory synthetic effects were applied.");
            } catch (_error) {
                setCampaignPlaceholder(elements.v1Result, "Agentic lab validation failed inside the disposable fixture boundary.");
            } finally {
                elements.v1LabRun.disabled = false;
            }
        }

        function setInvestigationPlaceholder(container, message) {
            container.replaceChildren(textNode("div", "debug-placeholder", message));
        }

        function investigationTrace() {
            if (!state.investigationData) return null;
            return (state.investigationData.traces || []).find(function (trace) {
                return trace.trace_id === state.selectedInvestigationTrace;
            }) || null;
        }

        function investigationFinding() {
            if (!state.investigationData) return null;
            return (state.investigationData.findings || []).find(function (finding) {
                return finding.finding_id === state.selectedInvestigationFinding;
            }) || null;
        }

        function renderInvestigationSummary() {
            const report = state.investigationData;
            const trace = investigationTrace();
            if (!report || !trace) return;
            const nodes = report.nodes.filter(function (node) { return node.trace_id === trace.trace_id; });
            const findings = report.findings.filter(function (finding) { return finding.trace_id === trace.trace_id; });
            const paths = report.paths.filter(function (path) {
                return findings.some(function (finding) { return finding.finding_id === path.finding_id; });
            });
            const values = [
                [nodes.length, "trace events"],
                [trace.agent_ids.length, "agents"],
                [trace.delegation_ids.length, "delegations"],
                [trace.max_depth, "graph depth"],
                [findings.length, "findings"],
                [paths.length, "attack paths"]
            ];
            const fragment = document.createDocumentFragment();
            values.forEach(function (item) {
                const stat = document.createElement("div");
                stat.className = "investigation-stat";
                stat.appendChild(textNode("strong", "", item[0]));
                stat.appendChild(textNode("span", "", item[1]));
                fragment.appendChild(stat);
            });
            elements.investigationSummary.replaceChildren(fragment);
        }

        function renderInvestigationTraceOptions() {
            const report = state.investigationData;
            if (!report) return;
            const traces = report.traces.slice().sort(function (left, right) {
                const preferredLeft = left.fixture_id === "multi-agent-delegation-cascade" && left.variant === "malicious" ? 1 : 0;
                const preferredRight = right.fixture_id === "multi-agent-delegation-cascade" && right.variant === "malicious" ? 1 : 0;
                return preferredRight - preferredLeft || right.finding_count - left.finding_count || right.max_depth - left.max_depth;
            });
            if (!traces.some(function (trace) { return trace.trace_id === state.selectedInvestigationTrace; })) {
                state.selectedInvestigationTrace = traces.length ? traces[0].trace_id : null;
            }
            const fragment = document.createDocumentFragment();
            traces.forEach(function (trace) {
                const option = document.createElement("option");
                option.value = trace.trace_id;
                const identity = trace.fixture_id || trace.trace_id.slice(0, 12);
                option.textContent = identity + " · " + (trace.variant || "observed") + " · " + trace.agent_ids.length + " agents · " + trace.finding_count + " findings";
                option.selected = trace.trace_id === state.selectedInvestigationTrace;
                fragment.appendChild(option);
            });
            elements.investigationTrace.replaceChildren(fragment);
        }

        function visibleInvestigationFindings() {
            if (!state.investigationData || !state.selectedInvestigationTrace) return [];
            const severity = elements.investigationSeverity.value;
            return state.investigationData.findings.filter(function (finding) {
                return finding.trace_id === state.selectedInvestigationTrace
                    && (severity === "all" || finding.severity === severity);
            });
        }

        function renderInvestigationFindings() {
            const findings = visibleInvestigationFindings();
            if (!findings.length) {
                state.selectedInvestigationFinding = null;
                setInvestigationPlaceholder(elements.investigationFindings, "No invariant failures match this trace and severity filter.");
                return;
            }
            if (!findings.some(function (finding) { return finding.finding_id === state.selectedInvestigationFinding; })) {
                state.selectedInvestigationFinding = findings[0].finding_id;
            }
            const fragment = document.createDocumentFragment();
            fragment.appendChild(textNode("div", "investigation-label", findings.length + " invariant failures"));
            findings.forEach(function (finding) {
                const button = document.createElement("button");
                button.type = "button";
                button.className = "investigation-finding" + (finding.finding_id === state.selectedInvestigationFinding ? " active" : "");
                button.appendChild(textNode("span", "severity-" + finding.severity, finding.severity + " · " + finding.code));
                button.appendChild(textNode("strong", "", finding.title));
                button.appendChild(textNode("span", "", finding.event_ids.length + " evidence checkpoint" + (finding.event_ids.length === 1 ? "" : "s")));
                button.addEventListener("click", function () {
                    state.selectedInvestigationFinding = finding.finding_id;
                    renderInvestigationFindings();
                    renderInvestigationGraph();
                    renderInvestigationDetail();
                });
                fragment.appendChild(button);
            });
            elements.investigationFindings.replaceChildren(fragment);
        }

        function renderInvestigationGraph() {
            const report = state.investigationData;
            const trace = investigationTrace();
            if (!report || !trace) {
                setInvestigationPlaceholder(elements.investigationGraph, "No trace graph is available.");
                return;
            }
            const finding = investigationFinding();
            const highlighted = new Set(finding ? finding.event_ids : []);
            const incoming = {};
            report.edges.filter(function (edge) { return edge.trace_id === trace.trace_id; }).forEach(function (edge) {
                if (!incoming[edge.target_event_id]) incoming[edge.target_event_id] = [];
                incoming[edge.target_event_id].push(edge.relationship);
            });
            const nodes = report.nodes.filter(function (node) { return node.trace_id === trace.trace_id; })
                .sort(function (left, right) { return left.index - right.index; });
            const fragment = document.createDocumentFragment();
            fragment.appendChild(textNode("div", "investigation-label", "Causal checkpoints · indentation follows graph depth"));
            nodes.forEach(function (node) {
                const row = document.createElement("div");
                const untrusted = (node.flags || []).includes("untrusted_input");
                row.className = "investigation-node" + (highlighted.has(node.event_id) ? " highlight" : "") + (untrusted ? " untrusted" : "");
                row.style.setProperty("--depth", String(Math.min(Number(node.depth) || 0, 8)));
                if (window.innerWidth > 620) row.style.marginLeft = String(Math.min(Number(node.depth) || 0, 8) * 10) + "px";
                row.appendChild(textNode("span", "investigation-node-agent", node.agent_id || "unknown-agent"));
                row.appendChild(textNode("span", "investigation-node-type", node.event_type));
                const relationships = incoming[node.event_id] || [];
                row.appendChild(textNode("span", "investigation-node-link", "depth " + node.depth + (relationships.length ? " · " + relationships.join(" + ") : " · root")));
                const flags = document.createElement("span");
                flags.className = "investigation-node-flags";
                (node.flags || []).slice(0, 3).forEach(function (flag) {
                    flags.appendChild(textNode("span", "", flag.replaceAll("_", " ")));
                });
                if (!(node.flags || []).length && node.outcome) flags.appendChild(textNode("span", "", node.outcome));
                row.appendChild(flags);
                fragment.appendChild(row);
            });
            elements.investigationGraph.replaceChildren(fragment);
        }

        function renderInvestigationDetail() {
            const report = state.investigationData;
            const trace = investigationTrace();
            const finding = investigationFinding();
            if (!report || !trace) {
                setInvestigationPlaceholder(elements.investigationDetail, "Select a trace to inspect its defensive context.");
                return;
            }
            if (!finding) {
                const container = document.createDocumentFragment();
                container.appendChild(textNode("div", "investigation-label", "Trace assessment"));
                container.appendChild(textNode("h3", "", trace.highest_severity === "none" ? "No invariant failures" : "Review the filtered findings"));
                container.appendChild(textNode("p", "", trace.highest_severity === "none"
                    ? "Agent identities, delegation envelopes, goal fingerprints, and memory lineage remained continuous in this synthetic control trace."
                    : "Change the severity filter or select a finding to inspect its evidence."));
                elements.investigationDetail.replaceChildren(container);
                return;
            }
            const container = document.createDocumentFragment();
            container.appendChild(textNode("div", "investigation-label severity-" + finding.severity, finding.severity + " · " + finding.finding_id));
            container.appendChild(textNode("h3", "", finding.title));
            container.appendChild(textNode("p", "", finding.description));
            container.appendChild(textNode("div", "investigation-label", "Evidence"));
            const evidence = document.createElement("div");
            evidence.className = "investigation-evidence";
            Object.keys(finding.evidence || {}).sort().forEach(function (key) {
                const row = document.createElement("div");
                row.appendChild(textNode("strong", "", key.replaceAll("_", " ")));
                const value = finding.evidence[key];
                row.appendChild(textNode("span", "", typeof value === "string" ? value : JSON.stringify(value)));
                evidence.appendChild(row);
            });
            container.appendChild(evidence);
            container.appendChild(textNode("div", "investigation-label", "Operator response"));
            const remediation = document.createElement("ul");
            remediation.className = "investigation-remediation";
            (finding.remediation || []).forEach(function (item) {
                remediation.appendChild(textNode("li", "", item));
            });
            container.appendChild(remediation);
            const path = (report.paths || []).find(function (item) { return item.finding_id === finding.finding_id; });
            if (path) {
                const byId = new Map(report.nodes.map(function (node) { return [node.event_id, node]; }));
                const labels = path.event_ids.map(function (eventId) {
                    const node = byId.get(eventId);
                    return node ? (node.agent_id || "agent") + " → " + node.event_type : eventId;
                });
                container.appendChild(textNode("div", "investigation-path", "Causal path\\n" + labels.join("\\n")));
            }
            elements.investigationDetail.replaceChildren(container);
        }

        function refreshInvestigation() {
            renderInvestigationSummary();
            renderInvestigationFindings();
            renderInvestigationGraph();
            renderInvestigationDetail();
        }

        async function runInvestigation() {
            if (state.investigationLoading) return;
            state.investigationLoading = true;
            elements.investigationRun.disabled = true;
            elements.investigationRun.textContent = "Building graph…";
            setInvestigationPlaceholder(elements.investigationFindings, "Evaluating delegation, identity, goal, and memory invariants…");
            setInvestigationPlaceholder(elements.investigationGraph, "Reconstructing causal paths from content-safe record identifiers…");
            setInvestigationPlaceholder(elements.investigationDetail, "Preparing operator evidence and remediation…");
            try {
                const response = await fetch("/api/v1/telemetry/investigation", {
                    method: "POST",
                    headers: {"Accept": "application/json", "Content-Type": "application/json", "X-AgentSim-Form-Token": FORM_TOKEN},
                    body: JSON.stringify({corpus: "reference-agent"})
                });
                if (!response.ok) throw new Error();
                const payload = await response.json();
                state.investigationData = payload.report;
                state.selectedInvestigationTrace = null;
                state.selectedInvestigationFinding = null;
                elements.investigationScore.textContent = String(payload.report.score) + " / 100";
                elements.investigationStatus.textContent = payload.report.status + " · mixed malicious and benign corpus";
                renderInvestigationTraceOptions();
                refreshInvestigation();
                showToast("Multi-agent investigation graph ready");
            } catch (_error) {
                state.investigationData = null;
                elements.investigationScore.textContent = "—";
                elements.investigationStatus.textContent = "Graph unavailable";
                setInvestigationPlaceholder(elements.investigationGraph, "Unable to build the synthetic investigation graph.");
            } finally {
                state.investigationLoading = false;
                elements.investigationRun.disabled = false;
                elements.investigationRun.textContent = "Build investigation";
            }
        }

        function setDebugPlaceholder(container, message) {
            container.replaceChildren(textNode("div", "debug-placeholder", message));
        }

        function resetDebugger() {
            state.debugData = null;
            state.debugRunId = null;
            state.selectedDebugTrace = null;
            elements.debuggerScore.textContent = "—";
            elements.debuggerScoreLabel.textContent = "Run a scenario suite";
            setDebugPlaceholder(elements.debugTraceList, "Run a scenario suite to inspect detection decisions.");
            setDebugPlaceholder(elements.debugDetail, "Select a trace to explain why its reference detector did or did not fire.");
        }

        function debugTraceMatches(trace) {
            const filter = elements.debugResultFilter.value;
            const filterMatch = filter === "all"
                || (filter === "failed" && !trace.passed)
                || (filter === "malicious" && trace.variant === "malicious")
                || (filter === "benign" && trace.variant === "benign")
                || (filter === "mutated" && Boolean(trace.mutation_id));
            const query = elements.debugSearch.value.trim().toLowerCase();
            const haystack = [trace.scenario_name, trace.scenario_id, trace.trace_id, trace.variant, trace.mutation_id]
                .filter(Boolean).join(" ").toLowerCase();
            return filterMatch && (!query || haystack.includes(query));
        }

        function renderDebugTraceList() {
            if (!state.debugData) {
                setDebugPlaceholder(elements.debugTraceList, "Run a scenario suite to inspect detection decisions.");
                return;
            }
            const traces = state.debugData.traces.filter(debugTraceMatches);
            if (!traces.length) {
                state.selectedDebugTrace = null;
                setDebugPlaceholder(elements.debugTraceList, "No traces match the current debugger filters.");
                setDebugPlaceholder(elements.debugDetail, "No trace explanation is available for the current filters.");
                return;
            }
            if (!traces.some(function (trace) { return trace.trace_id === state.selectedDebugTrace; })) {
                state.selectedDebugTrace = traces[0].trace_id;
            }
            const fragment = document.createDocumentFragment();
            traces.forEach(function (trace) {
                const button = document.createElement("button");
                button.type = "button";
                button.className = "debug-trace" + (trace.trace_id === state.selectedDebugTrace ? " active" : "");
                button.appendChild(textNode("span", "debug-trace-name", trace.scenario_name || trace.scenario_id));
                button.appendChild(textNode("span", "debug-badge" + (trace.passed ? "" : " fail"), trace.passed ? "pass" : "mismatch"));
                const mutation = trace.mutation_id ? " · " + trace.mutation_id : " · baseline";
                button.appendChild(textNode("span", "debug-trace-meta", trace.variant + mutation + " · " + trace.signal_count + " signals"));
                button.addEventListener("click", function () {
                    state.selectedDebugTrace = trace.trace_id;
                    renderDebugTraceList();
                    loadDebugTrace(trace.trace_id);
                });
                fragment.appendChild(button);
            });
            elements.debugTraceList.replaceChildren(fragment);
        }

        function renderDebugDetail(payload) {
            const result = payload.result || {};
            const detector = payload.detector || {};
            const events = Array.isArray(payload.events) ? payload.events : [];
            const signals = new Set(Array.isArray(result.signal_event_ids) ? result.signal_event_ids : []);
            const container = document.createDocumentFragment();
            const head = document.createElement("div");
            head.className = "debug-detail-head";
            const identity = document.createElement("div");
            identity.appendChild(textNode("h3", "", result.scenario_name || result.scenario_id));
            identity.appendChild(textNode("p", "", result.trace_id));
            head.appendChild(identity);
            const outcome = document.createElement("div");
            outcome.className = "debug-outcome";
            outcome.appendChild(textNode("span", "", "Expected " + (result.expected_detected ? "alert" : "quiet")));
            outcome.appendChild(textNode("span", "", "Observed " + (result.detected ? "alert" : "quiet")));
            outcome.appendChild(textNode("span", "", result.detected_at_sequence ? "Detected at #" + result.detected_at_sequence : "No alert"));
            head.appendChild(outcome);
            container.appendChild(head);

            container.appendChild(textNode("div", "debug-section-label", "Ordered detector conditions"));
            const rule = document.createElement("div");
            rule.className = "debug-rule";
            const conditions = Array.isArray(detector.conditions) ? detector.conditions : [];
            if (!conditions.length) {
                rule.appendChild(textNode("div", "debug-condition", "No reference detector definition is available."));
            } else {
                conditions.forEach(function (condition, index) {
                    rule.appendChild(textNode("div", "debug-condition", String(index + 1).padStart(2, "0") + "  " + JSON.stringify(condition)));
                });
            }
            container.appendChild(rule);

            container.appendChild(textNode("div", "debug-section-label", "Trace timeline · highlighted rows contributed to the alert"));
            const timeline = document.createElement("div");
            timeline.className = "debug-timeline";
            events.forEach(function (event) {
                const row = document.createElement("div");
                row.className = "debug-event" + (signals.has(event.event_id) ? " signal" : "");
                row.appendChild(textNode("span", "debug-event-sequence", "#" + event.sequence));
                row.appendChild(textNode("span", "debug-event-stage", event.stage));
                row.appendChild(textNode("span", "debug-event-copy", event.event_type + " · " + event.message));
                timeline.appendChild(row);
            });
            container.appendChild(timeline);
            elements.debugDetail.replaceChildren(container);
        }

        async function loadDebugTrace(traceId) {
            if (!traceId) return;
            setDebugPlaceholder(elements.debugDetail, "Loading trace explanation…");
            try {
                const response = await fetch("/api/detection-debug/trace?trace_id=" + encodeURIComponent(traceId), {headers: {"Accept": "application/json"}});
                if (!response.ok) throw new Error();
                renderDebugDetail(await response.json());
            } catch (_error) {
                setDebugPlaceholder(elements.debugDetail, "Unable to load this trace from the current evidence artifacts.");
            }
        }

        async function loadDebugSummary(force) {
            if (state.debugLoading || (state.debugData && !force)) return;
            state.debugLoading = true;
            elements.debugRefresh.disabled = true;
            try {
                const response = await fetch("/api/detection-debug", {headers: {"Accept": "application/json"}});
                if (!response.ok) throw new Error();
                const payload = await response.json();
                state.debugData = payload;
                state.debugRunId = payload.run_id;
                const summary = payload.summary || {};
                elements.debuggerScore.textContent = String(summary.passed || 0) + " / " + String(summary.checks || 0);
                elements.debuggerScoreLabel.textContent = summary.all_passed ? "Checks passed" : "Review mismatches";
                renderDebugTraceList();
                if (state.selectedDebugTrace) await loadDebugTrace(state.selectedDebugTrace);
            } catch (_error) {
                resetDebugger();
            } finally {
                state.debugLoading = false;
                elements.debugRefresh.disabled = false;
            }
        }

        function setRunMode(mode) {
            state.mode = mode === "scenario" ? "scenario" : "behavior";
            elements.runMode.value = state.mode;
            const scenarioMode = state.mode === "scenario";
            elements.scenarioControls.classList.toggle("hidden", !scenarioMode);
            document.querySelectorAll(".behavior-control").forEach(function (item) {
                item.classList.toggle("hidden", scenarioMode);
            });
            elements.layerArtifact.classList.toggle("hidden", scenarioMode);
            elements.scenarioArtifacts.classList.toggle("hidden", !scenarioMode);
            elements.debugger.classList.toggle("hidden", !scenarioMode);
            document.getElementById("phase-name-0").textContent = scenarioMode ? "Agent input" : "Host discovery";
            document.getElementById("phase-name-1").textContent = scenarioMode ? "Tool boundary" : "Privilege & network";
            document.getElementById("phase-name-2").textContent = scenarioMode ? "Policy outcome" : "Cloud services";
            document.getElementById("cycles-label").textContent = scenarioMode ? "Checkpoints" : "Cycles";
            document.getElementById("cycles-foot").textContent = scenarioMode ? "labeled events emitted" : "OODA loops observed";
            document.getElementById("commands-label").textContent = scenarioMode ? "Tool signals" : "Commands";
            document.getElementById("commands-foot").textContent = scenarioMode ? "tool-boundary events" : "process actions selected";
            document.getElementById("anomalies-label").textContent = scenarioMode ? "Risk signals" : "Agent signals";
            document.getElementById("anomalies-foot").textContent = scenarioMode ? "untrusted or sensitive context" : "mistakes, pivots, lineage";
            document.getElementById("skipped-label").textContent = scenarioMode ? "Blocked" : "Guarded";
            document.getElementById("skipped-foot").textContent = scenarioMode ? "policy denials" : "network actions blocked";
            elements.eventStreamHeading.textContent = scenarioMode ? "Agent workflow event stream" : "Behavior event stream";
            elements.commandFilter.textContent = scenarioMode ? "Tools" : "Commands";
            elements.search.placeholder = scenarioMode ? "Filter tool or checkpoint" : "Filter command or message";
            elements.emptyHeading.textContent = scenarioMode ? "No scenario evidence yet" : "No telemetry yet";
            elements.emptyCopy.textContent = scenarioMode
                ? "Run a scenario to see trusted and untrusted input, tool-boundary, network-intent, and policy checkpoints."
                : "Start a run to see phase transitions, selected commands, context loss, retries, and safety-gate events as they happen.";
            document.getElementById("detail-profile-label").textContent = scenarioMode ? "Scenario" : "Profile";
            document.getElementById("detail-seed-label").textContent = scenarioMode ? "Controls" : "Seed";
            document.getElementById("watch-item-0").textContent = scenarioMode
                ? "Use Signals to isolate untrusted input, definition changes, decoy data, and policy blocks."
                : "Use Signals to isolate hallucinations, context loss, and retry behavior.";
            document.getElementById("watch-item-1").textContent = scenarioMode
                ? "Use Tools to inspect proposed calls without exposing arguments or results."
                : "Use Commands to compare process telemetry with your EDR or SIEM.";
            document.getElementById("watch-item-2").textContent = scenarioMode
                ? "Score your SIEM against both malicious traces and their benign twins."
                : "Reuse a seed when validating detection changes against the same run.";
            document.getElementById("safety-note").textContent = scenarioMode
                ? "Scenario mode only writes synthetic, redacted evidence. It never invokes a tool or opens a network connection."
                : "Safe preview is the default. Select a non-preview profile to explicitly run reviewed local commands.";
            elements.start.textContent = state.running
                ? (scenarioMode ? "Scenario suite running" : "Simulation running")
                : (scenarioMode ? "Run scenario suite" : "Start simulation");
            if (!state.running) {
                state.totalIterations = scenarioMode ? selectedScenarioCount() : Number(document.getElementById("iterations").value);
                elements.runHeading.textContent = scenarioMode ? "Ready for a scenario suite" : "Ready for a simulation";
                elements.runSubtitle.textContent = scenarioMode
                    ? "Select a scenario and run malicious plus benign control traces."
                    : "Configure a behavior profile and start generating endpoint process telemetry.";
            }
            updateRunDetails();
            updateMetrics();
        }

        function showToast(message) {
            elements.toast.textContent = message;
            elements.toast.classList.add("visible");
            window.clearTimeout(showToast.timeout);
            showToast.timeout = window.setTimeout(function () {
                elements.toast.classList.remove("visible");
            }, 2200);
        }

        function setRunning(running, failed) {
            state.running = running;
            elements.start.disabled = running;
            elements.stop.disabled = !running;
            elements.clear.disabled = running;
            elements.start.textContent = running
                ? (state.mode === "scenario" ? "Scenario suite running" : "Simulation running")
                : (state.mode === "scenario" ? "Run scenario suite" : "Start simulation");
            elements.statusPill.classList.toggle("running", running);
            elements.statusPill.classList.toggle("error", Boolean(failed));
            elements.statusText.textContent = failed ? "Needs attention" : (running ? "Running" : "Ready");
            if (running) {
                elements.runHeading.textContent = state.mode === "scenario" ? "Scenario suite in progress" : "Simulation in progress";
                elements.runSubtitle.textContent = state.mode === "scenario"
                    ? "Safe, labeled checkpoints are streaming from the scenario runner."
                    : "Events are streaming from the local AgentSim worker.";
            }
        }

        function syncControlOutputs() {
            document.getElementById("iterations-output").textContent = document.getElementById("iterations").value;
            document.getElementById("speed-output").textContent = document.getElementById("speed").value + " ms";
            rateControls.forEach(function (pair) {
                const percentage = Math.round(Number(document.getElementById(pair[0]).value) * 100);
                document.getElementById(pair[1]).textContent = percentage + "%";
            });
            elements.networkWarning.classList.toggle("visible", elements.network.checked);
            updateRunDetails();
        }

        function updateRunDetails() {
            const scenarioMode = state.mode === "scenario";
            const selectedScenario = elements.scenario.options[elements.scenario.selectedIndex];
            document.getElementById("detail-profile").textContent = scenarioMode ? selectedScenario.textContent : document.getElementById("profile-name").textContent;
            document.getElementById("detail-mode").textContent = scenarioMode ? "Simulation only" : (elements.dryRun.checked ? "Dry run" : "Execute local");
            document.getElementById("detail-seed").textContent = scenarioMode
                ? elements.variant.options[elements.variant.selectedIndex].textContent + " · "
                    + elements.mutations.value + " mutation"
                    + (elements.mutations.value === "1" ? "" : "s")
                : (elements.seed.value || "Random");
            document.getElementById("detail-speed").textContent = document.getElementById("speed").value + " ms";
            document.getElementById("detail-cloud").textContent = scenarioMode ? "Never executed" : (elements.network.checked ? "Allowed" : "Guarded");
        }

        function markCustomProfile() {
            document.querySelectorAll(".preset").forEach(function (button) {
                button.classList.remove("active");
            });
            document.getElementById("profile-name").textContent = "Custom";
            document.getElementById("preset-description").textContent = "Custom parameters for this run.";
            state.profile = "custom";
            syncControlOutputs();
        }

        function applyProfile(name) {
            const profile = profiles[name];
            if (!profile) return;
            state.profile = name;
            document.getElementById("iterations").value = profile.iterations;
            document.getElementById("speed").value = profile.speed;
            document.getElementById("hallucination-rate").value = profile.hallucination;
            document.getElementById("context-loss-rate").value = profile.context;
            document.getElementById("retry-rate").value = profile.retry;
            document.getElementById("evasion-rate").value = profile.evasion;
            elements.dryRun.checked = profile.dryRun;
            if (profile.dryRun) elements.network.checked = false;
            document.getElementById("profile-name").textContent = profile.label;
            document.getElementById("preset-description").textContent = profile.description;
            document.querySelectorAll(".preset").forEach(function (button) {
                button.classList.toggle("active", button.dataset.preset === name);
            });
            syncControlOutputs();
        }

        function resetRunMetrics(clearEvents) {
            state.currentCycle = 0;
            state.commandCount = 0;
            state.anomalyCount = 0;
            state.skippedCount = 0;
            state.currentPhase = -1;
            if (clearEvents) {
                state.events = [];
                state.seenIds.clear();
            }
            updateMetrics();
            updatePhase(-1);
            elements.progress.style.width = "0%";
            if (clearEvents) renderEvents();
        }

        function updateMetrics() {
            document.getElementById("cycles-metric").textContent = state.currentCycle + " / " + state.totalIterations;
            document.getElementById("commands-metric").textContent = state.commandCount;
            document.getElementById("anomalies-metric").textContent = state.anomalyCount;
            document.getElementById("skipped-metric").textContent = state.skippedCount;
            elements.eventCount.textContent = state.events.length + (state.events.length === 1 ? " event" : " events");
            const progress = state.totalIterations ? Math.min(100, state.currentCycle / state.totalIterations * 100) : 0;
            elements.progress.style.width = progress + "%";
        }

        function phaseIndex(phase) {
            if (!phase) return -1;
            if (phase.indexOf("Host Discovery") !== -1) return 0;
            if (phase.indexOf("Privilege and Network") !== -1) return 1;
            if (phase.indexOf("Cloud Service") !== -1) return 2;
            return -1;
        }

        function checkpointPhase(stage) {
            if (["input", "decision", "retrieval", "memory", "observation"].includes(stage)) return 0;
            if (["tool_discovery", "pre_tool", "post_tool", "inter_agent", "delegation", "approval"].includes(stage)) return 1;
            if (["network", "policy", "authorization", "budget", "configuration"].includes(stage)) return 2;
            return -1;
        }

        function updatePhase(index) {
            state.currentPhase = index;
            document.querySelectorAll(".phase").forEach(function (phase) {
                const itemIndex = Number(phase.dataset.phaseIndex);
                phase.classList.toggle("active", itemIndex === index);
                phase.classList.toggle("complete", index >= 0 && itemIndex < index);
            });
        }

        function eventMatches(event) {
            const categoryMatch = state.filter === "all" || event.category === state.filter;
            const searchMatch = !state.search || event.message.toLowerCase().indexOf(state.search) !== -1;
            return categoryMatch && searchMatch;
        }

        function createEventRow(event) {
            const row = document.createElement("article");
            row.className = "event-row";
            row.dataset.category = event.category || "system";
            row.dataset.kind = event.kind || "info";

            const timestamp = document.createElement("time");
            timestamp.className = "event-time";
            timestamp.textContent = event.time || "--:--:--";

            const kind = document.createElement("span");
            kind.className = "event-kind";
            kind.textContent = kindLabels[event.kind] || "System";

            const message = document.createElement("div");
            message.className = "event-message";
            message.textContent = event.message;

            row.append(timestamp, kind, message);
            return row;
        }

        function renderEvents() {
            elements.events.querySelectorAll(".event-row").forEach(function (row) { row.remove(); });
            const visibleEvents = state.events.filter(eventMatches);
            elements.empty.classList.toggle("hidden", visibleEvents.length > 0);
            const fragment = document.createDocumentFragment();
            visibleEvents.forEach(function (event) { fragment.appendChild(createEventRow(event)); });
            elements.events.appendChild(fragment);
            if (elements.autoScroll.checked) elements.events.scrollTop = elements.events.scrollHeight;
        }

        function ingestEvent(event) {
            if (!event || state.seenIds.has(event.id)) return;
            state.seenIds.add(event.id);
            state.events.push(event);

            if (event.kind === "cycle") {
                state.currentCycle = Math.max(state.currentCycle, Number(event.cycle || 0));
                updatePhase(phaseIndex(event.phase));
            }
            if (event.kind === "phase") updatePhase(phaseIndex(event.phase));
            if (event.kind === "checkpoint" || event.kind === "tool" || event.kind === "blocked") {
                state.currentCycle += 1;
                updatePhase(checkpointPhase(event.stage));
            }
            if (event.kind === "command" || event.kind === "dry_command" || event.kind === "hallucination" || event.kind === "tool") {
                state.commandCount += 1;
            }
            if (event.category === "anomaly" && event.kind !== "skipped" && event.kind !== "stopped") {
                state.anomalyCount += 1;
            }
            if (event.kind === "skipped" || event.kind === "blocked") state.skippedCount += 1;
            if (event.kind === "start" && event.params) {
                setRunMode(event.params.run_mode || "behavior");
                state.totalIterations = Number(event.params.iterations || event.params.checkpoints || state.totalIterations);
            }
            if (event.kind === "complete" || event.kind === "stopped") {
                setRunning(false, false);
                elements.runHeading.textContent = event.kind === "stopped"
                    ? (state.mode === "scenario" ? "Scenario suite stopped" : "Simulation stopped")
                    : (state.mode === "scenario" ? "Scenario suite complete" : "Simulation complete");
                elements.runSubtitle.textContent = state.mode === "scenario"
                    ? "Review the checkpoint stream, ground truth, and detection validation report."
                    : "Review the event stream or download the generated Navigator layer.";
                window.setTimeout(syncStatus, 100);
            }
            if (event.kind === "error") {
                setRunning(false, true);
                elements.runHeading.textContent = "Simulation failed";
                elements.runSubtitle.textContent = "Review the final event for details, adjust the run, and try again.";
                window.setTimeout(syncStatus, 100);
            }

            if (eventMatches(event)) {
                elements.empty.classList.add("hidden");
                elements.events.appendChild(createEventRow(event));
                if (elements.autoScroll.checked) elements.events.scrollTop = elements.events.scrollHeight;
            }
            updateMetrics();
        }

        function updateElapsed() {
            if (!state.startedAt) {
                elements.elapsed.textContent = "00:00";
                return;
            }
            const endTime = state.running ? Date.now() : (state.finishedAt || Date.now());
            const seconds = Math.max(0, Math.floor((endTime - state.startedAt) / 1000));
            const minutes = String(Math.floor(seconds / 60)).padStart(2, "0");
            const remainder = String(seconds % 60).padStart(2, "0");
            elements.elapsed.textContent = minutes + ":" + remainder;
        }

        async function syncStatus() {
            try {
                const response = await fetch("/api/status", {headers: {"Accept": "application/json"}});
                if (!response.ok) return;
                const status = await response.json();
                elements.hostOs.textContent = status.os + " host";
                if (status.params && status.params.run_mode) setRunMode(status.params.run_mode);
                setRunning(status.running, false);
                if (status.params && (status.params.iterations || status.params.checkpoints)) {
                    state.totalIterations = Number(status.params.iterations || status.params.checkpoints);
                }
                state.startedAt = status.started_at ? status.started_at * 1000 : null;
                state.finishedAt = status.finished_at ? status.finished_at * 1000 : null;
                elements.download.classList.toggle("disabled", !status.layer_available);
                elements.download.setAttribute("aria-disabled", String(!status.layer_available));
                elements.layerStatus.textContent = status.layer_available
                    ? "Layer generated from this run and ready to import."
                    : "Available after the run completes or is stopped.";
                elements.groundTruthDownload.classList.toggle("disabled", !status.ground_truth_available);
                elements.groundTruthDownload.setAttribute("aria-disabled", String(!status.ground_truth_available));
                elements.validationDownload.classList.toggle("disabled", !status.validation_available);
                elements.validationDownload.setAttribute("aria-disabled", String(!status.validation_available));
                elements.bundleDownload.classList.toggle("disabled", !status.bundle_available);
                elements.bundleDownload.setAttribute("aria-disabled", String(!status.bundle_available));
                const benchmark = status.benchmark_metrics || {};
                elements.scenarioArtifactStatus.textContent = status.ground_truth_available && status.validation_available
                    ? "Evidence ready · precision " + Math.round(Number(benchmark.precision || 0) * 100) + "% · recall " + Math.round(Number(benchmark.recall || 0) * 100) + "%"
                    : "Available after the scenario suite completes or is stopped.";
                if (state.mode === "scenario" && status.validation_available && !state.debugData) {
                    loadDebugSummary(false);
                }
                if (!status.running && status.outcome === "complete") {
                    elements.runHeading.textContent = state.mode === "scenario" ? "Scenario suite complete" : "Simulation complete";
                    elements.runSubtitle.textContent = state.mode === "scenario"
                        ? "Review the checkpoint stream, ground truth, and detection validation report."
                        : "Review the event stream or download the generated Navigator layer.";
                } else if (!status.running && status.outcome === "stopped") {
                    elements.runHeading.textContent = state.mode === "scenario" ? "Scenario suite stopped" : "Simulation stopped";
                    elements.runSubtitle.textContent = "Partial artifacts contain the checkpoints completed before the stop request.";
                } else if (!status.running && status.outcome === "error") {
                    setRunning(false, true);
                    elements.runHeading.textContent = state.mode === "scenario" ? "Scenario suite failed" : "Simulation failed";
                    elements.runSubtitle.textContent = "Review the final event for details, adjust the run, and try again.";
                }
                updateMetrics();
                updateElapsed();
            } catch (_error) {
                elements.connection.textContent = "Local status unavailable";
            }
        }

        async function submitRun(event) {
            event.preventDefault();
            elements.error.textContent = "";
            state.totalIterations = state.mode === "scenario" ? selectedScenarioCount() : Number(document.getElementById("iterations").value);
            resetRunMetrics(true);
            if (state.mode === "scenario") resetDebugger();
            state.startedAt = Date.now();
            state.finishedAt = null;
            updateElapsed();
            setRunning(true, false);
            elements.download.classList.add("disabled");
            elements.download.setAttribute("aria-disabled", "true");
            elements.layerStatus.textContent = "Generating after the run completes…";
            elements.groundTruthDownload.classList.add("disabled");
            elements.validationDownload.classList.add("disabled");
            elements.bundleDownload.classList.add("disabled");
            elements.scenarioArtifactStatus.textContent = "Generating labeled evidence and validation checks…";

            try {
                const response = await fetch("/start", {
                    method: "POST",
                    body: new FormData(elements.form),
                    headers: {"Accept": "application/json"}
                });
                if (!response.ok) {
                    const message = await response.text();
                    throw new Error(message.indexOf("already running") !== -1 ? "A simulation is already running." : "The run settings were rejected.");
                }
                showToast(state.mode === "scenario" ? "Scenario suite started" : "Simulation started");
                await syncStatus();
            } catch (error) {
                setRunning(false, true);
                elements.error.textContent = error.message;
                elements.runHeading.textContent = state.mode === "scenario" ? "Unable to start scenario suite" : "Unable to start simulation";
            }
        }

        async function stopRun() {
            elements.stop.disabled = true;
            try {
                const body = new FormData();
                body.append("form_token", FORM_TOKEN);
                const response = await fetch("/stop", {
                    method: "POST",
                    body: body,
                    headers: {"Accept": "application/json"}
                });
                if (!response.ok) throw new Error();
                elements.statusText.textContent = "Stopping";
                showToast("Stop requested; waiting for the current command");
            } catch (_error) {
                elements.error.textContent = "Unable to stop the current run.";
                elements.stop.disabled = false;
            }
        }

        async function clearEvents() {
            try {
                const body = new FormData();
                body.append("form_token", FORM_TOKEN);
                const response = await fetch("/clear", {
                    method: "POST",
                    body: body,
                    headers: {"Accept": "application/json"}
                });
                if (!response.ok) throw new Error();
                resetRunMetrics(true);
                elements.runHeading.textContent = state.mode === "scenario" ? "Ready for a scenario suite" : "Ready for a simulation";
                elements.runSubtitle.textContent = state.mode === "scenario"
                    ? "Select a scenario and run malicious plus benign control traces."
                    : "Configure a behavior profile and start generating endpoint process telemetry.";
                state.startedAt = null;
                state.finishedAt = null;
                updateElapsed();
                showToast("Event history cleared");
            } catch (_error) {
                showToast("Stop the active run before clearing");
            }
        }

        async function copyLog() {
            if (!state.events.length) {
                showToast("No events to copy");
                return;
            }
            const text = state.events.map(function (event) {
                return "[" + event.time + "] " + event.message;
            }).join("\\n");
            try {
                await navigator.clipboard.writeText(text);
                showToast("Event log copied");
            } catch (_error) {
                showToast("Clipboard access unavailable");
            }
        }

        document.querySelectorAll(".preset").forEach(function (button) {
            button.addEventListener("click", function () { applyProfile(button.dataset.preset); });
        });
        document.querySelectorAll('input[type="range"]').forEach(function (input) {
            input.addEventListener("input", markCustomProfile);
        });
        [elements.dryRun, elements.network, elements.seed].forEach(function (input) {
            input.addEventListener("change", markCustomProfile);
        });
        elements.network.addEventListener("change", function () {
            if (elements.network.checked) elements.dryRun.checked = false;
            syncControlOutputs();
        });
        elements.dryRun.addEventListener("change", function () {
            if (elements.dryRun.checked) elements.network.checked = false;
            syncControlOutputs();
        });
        elements.runMode.addEventListener("change", function () {
            setRunMode(elements.runMode.value);
            resetRunMetrics(false);
        });
        [elements.scenario, elements.variant, elements.mutations, elements.mutationSeed].forEach(function (input) {
            input.addEventListener("change", function () {
                if (!state.running) state.totalIterations = selectedScenarioCount();
                updateRunDetails();
                updateMetrics();
            });
        });
        document.getElementById("seed-button").addEventListener("click", function () {
            elements.seed.value = Math.floor(Math.random() * 1000000);
            markCustomProfile();
        });
        document.querySelectorAll(".filter-button").forEach(function (button) {
            button.addEventListener("click", function () {
                state.filter = button.dataset.filter;
                document.querySelectorAll(".filter-button").forEach(function (item) {
                    item.classList.toggle("active", item === button);
                });
                renderEvents();
            });
        });
        elements.search.addEventListener("input", function () {
            state.search = elements.search.value.trim().toLowerCase();
            renderEvents();
        });
        elements.debugResultFilter.addEventListener("change", function () {
            renderDebugTraceList();
            if (state.selectedDebugTrace) loadDebugTrace(state.selectedDebugTrace);
        });
        elements.debugSearch.addEventListener("input", function () {
            renderDebugTraceList();
            if (state.selectedDebugTrace) loadDebugTrace(state.selectedDebugTrace);
        });
        elements.debugRefresh.addEventListener("click", function () {
            state.debugData = null;
            loadDebugSummary(true);
        });
        elements.campaignRun.addEventListener("click", runSafeCampaign);
        elements.v1DetectionRun.addEventListener("click", runV1Detection);
        elements.v1AssuranceRun.addEventListener("click", runV1Assurance);
        elements.v1LabRun.addEventListener("click", runV1Lab);
        elements.feedbackRun.addEventListener("click", runFeedbackAnalysis);
        elements.investigationRun.addEventListener("click", runInvestigation);
        elements.investigationTrace.addEventListener("change", function () {
            state.selectedInvestigationTrace = elements.investigationTrace.value;
            state.selectedInvestigationFinding = null;
            refreshInvestigation();
        });
        elements.investigationSeverity.addEventListener("change", function () {
            state.selectedInvestigationFinding = null;
            refreshInvestigation();
        });
        elements.form.addEventListener("submit", submitRun);
        elements.stop.addEventListener("click", stopRun);
        elements.clear.addEventListener("click", clearEvents);
        elements.copy.addEventListener("click", copyLog);
        elements.download.addEventListener("click", function (event) {
            if (elements.download.classList.contains("disabled")) event.preventDefault();
        });
        [elements.groundTruthDownload, elements.validationDownload, elements.bundleDownload].forEach(function (link) {
            link.addEventListener("click", function (event) {
                if (link.classList.contains("disabled")) event.preventDefault();
            });
        });

        const stream = new EventSource("/stream");
        stream.onopen = function () { elements.connection.textContent = "Live stream connected"; };
        stream.onerror = function () { elements.connection.textContent = "Reconnecting to local stream…"; };
        stream.onmessage = function (message) {
            try { ingestEvent(JSON.parse(message.data)); } catch (_error) { /* Ignore malformed local events. */ }
        };

        window.setInterval(updateElapsed, 1000);
        setRunMode("behavior");
        syncControlOutputs();
        setRunning(INITIAL_RUNNING, false);
        loadCampaignFoundation();
        syncStatus();
    </script>
</body>
</html>
"""


def _parse_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw_value = request.form.get(name, str(default))
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        abort(400, description=f"{name} must be an integer")
    if not minimum <= value <= maximum:
        abort(400, description=f"{name} must be between {minimum} and {maximum}")
    return value


def _parse_rate(name: str, default: float) -> float:
    raw_value = request.form.get(name, str(default))
    try:
        value = float(raw_value)
    except (TypeError, ValueError):
        abort(400, description=f"{name} must be a number")
    if not 0.0 <= value <= 1.0:
        abort(400, description=f"{name} must be between 0.0 and 1.0")
    return value


def _validate_form_token() -> None:
    submitted_token = request.form.get("form_token", "")
    if not hmac.compare_digest(submitted_token, form_token):
        abort(400, description="invalid form token")


def _validate_api_token() -> None:
    submitted_token = request.headers.get("X-AgentSim-Form-Token", "")
    if not hmac.compare_digest(submitted_token, form_token):
        abort(400, description="invalid form token")


def _json_or_redirect(payload: dict[str, Any], endpoint: str = "index") -> Response:
    if request.accept_mimetypes.best == "application/json":
        return jsonify(payload)
    return redirect(url_for(endpoint))


@app.after_request
def set_security_headers(response: Response) -> Response:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.route("/")
def index() -> str:
    with state_lock:
        running = is_running
    scenario_counts = {
        scenario_id: {
            "malicious": len(definition.malicious_steps),
            "benign": len(definition.benign_steps),
            "both": len(definition.malicious_steps) + len(definition.benign_steps),
        }
        for scenario_id, definition in SCENARIOS.items()
    }
    scenario_counts["all"] = {
        variant: sum(counts[variant] for counts in scenario_counts.values())
        for variant in ("malicious", "benign", "both")
    }
    return render_template_string(
        HTML_TEMPLATE,
        is_running=running,
        form_token=form_token,
        scenarios=[SCENARIOS[scenario_id] for scenario_id in sorted(SCENARIOS)],
        campaigns=[CAMPAIGNS[campaign_id] for campaign_id in sorted(CAMPAIGNS)],
        abilities=[ABILITIES[ability_id] for ability_id in sorted(ABILITIES)],
        scenario_counts=scenario_counts,
        scenario_total=len(SCENARIOS),
    )


@app.route("/api/status")
def api_status() -> Response:
    return jsonify(_status_snapshot())


@app.route("/api/v0.4/catalog")
@app.route("/api/v1/catalog")
def api_foundation_catalog() -> Response:
    history = RunStore(CAMPAIGN_DATABASE_PATH).history(25) if CAMPAIGN_DATABASE_PATH.exists() else []
    return jsonify(
        {
            "version": "1.5.0",
            "workflow": ["emulate", "observe", "detect", "defend", "retest"],
            "capabilities": {
                "offline_collectors": ["jsonl", "otel", "otel_genai", "sysmon", "auditd", "cloudtrail", "crowdstrike", "splunk", "elastic", "sentinel", "logscale", "panther", "graylog", "agent_runtime", "mcp_audit"],
                "live_read_only_connectors": list(CONNECTOR_NAMES),
                "agent_trace_contract": "1.1",
                "detection_formats": ["sigma", "kql", "splunk", "crowdstrike", "elastic", "panther", "graylog"],
                "agentic_fixtures": len(list_fixtures()),
                "external_adapters": list(adapter_names()),
                "external_execution_supported_by_core": False,
                "signed_builtin_content": True,
                "plugin_api_version": "1.0",
                "reference_agent_lab": True,
                "telemetry_assurance": True,
                "multi_agent_investigation": True,
                "graph_detection_primitives": ["graph_path", "graph_fanout"],
                "detection_pack_rules": len(load_detection_pack().rules),
                "detection_feedback_reconciliation": True,
                "detection_tuning_drift": True,
            },
            "abilities": [
                {
                    "ability_id": ability.ability_id,
                    "name": ability.name,
                    "risk": ability.risk,
                    "providers": list(ability.execution.supported_providers),
                    "production_allowed": ability.production_allowed,
                    "detection_objectives": list(ability.detection_objectives),
                    "defenses": list(ability.defenses),
                }
                for ability in ABILITIES.values()
            ],
            "campaigns": [
                {
                    "campaign_id": campaign.campaign_id,
                    "name": campaign.name,
                    "objective": campaign.objective,
                    "ability_count": len(campaign.steps),
                    "authorization_required": campaign.authorization_required,
                }
                for campaign in CAMPAIGNS.values()
            ],
            "history": history,
        }
    )


@app.route("/api/v0.4/campaign/simulate", methods=["POST"])
@app.route("/api/v1/campaign/simulate", methods=["POST"])
def api_simulate_campaign() -> Response:
    _validate_api_token()
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        abort(400, description="JSON request body is required")
    campaign_id = payload.get("campaign_id")
    if not isinstance(campaign_id, str) or campaign_id not in CAMPAIGNS:
        abort(400, description="unknown campaign")
    campaign = CAMPAIGNS[campaign_id]
    now = datetime.now(timezone.utc)
    manifest = AuthorizationManifest.from_mapping(
        {
            "manifest_id": f"dashboard-{secrets.token_hex(8)}",
            "authorized_by": "local-dashboard-operator",
            "scope": "One non-executing dashboard campaign against synthetic://dashboard",
            "issued_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": (now + timedelta(minutes=15)).isoformat().replace("+00:00", "Z"),
            "allowed_modes": ["simulate"],
            "allowed_targets": ["synthetic://dashboard"],
            "allowed_ability_ids": list(campaign.ability_ids),
            "allow_network": False,
            "resource_limits": {
                "max_actions": max(1, len(campaign.steps)),
                "max_duration_seconds": 60,
                "max_processes": 1,
                "max_cloud_spend_usd": 0,
            },
        }
    )
    try:
        result = CampaignRunner(
            ABILITIES,
            database_path=CAMPAIGN_DATABASE_PATH,
        ).run(
            campaign,
            mode="simulate",
            target=TargetProfile.from_uri("synthetic://dashboard"),
            manifest=manifest,
            output_directory=CAMPAIGN_OUTPUT_DIRECTORY,
        )
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        abort(400, description=str(exc))
    store = RunStore(CAMPAIGN_DATABASE_PATH)
    return jsonify(
        {
            "run_id": result.run_id,
            "campaign_id": result.campaign_id,
            "campaign_name": campaign.name,
            "mode": result.mode,
            "provider": result.provider,
            "target_uri": result.target_uri,
            "status": result.status,
            "summary": result.summary,
            "events": store.events_for_run(result.run_id),
            "history": store.history(25),
        }
    )


@app.route("/api/v1/detection/demo", methods=["POST"])
def api_detection_demo() -> Response:
    """Run a synthetic, non-executing detection validation for one reviewed ability."""

    _validate_api_token()
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        abort(400, description="JSON request body is required")
    ability_id = payload.get("ability_id", "endpoint.discovery.processes")
    if not isinstance(ability_id, str) or ability_id not in ABILITIES:
        abort(400, description="unknown ability")
    ability = ABILITIES[ability_id]
    candidate = generate_candidate(ability)
    process_names = candidate.process_names or ("synthetic-tool",)
    source = str(ability.expected_telemetry[0].get("source", "agent_runtime"))
    records = [
        {
            "timestamp": f"2026-01-01T00:00:0{index}Z",
            "source": source,
            "event_type": source,
            "host_id": "synthetic-dashboard-host",
            "user_id": "synthetic-dashboard-user",
            "process_name": process_names[(index - 1) % len(process_names)],
            "command_line": "<redacted synthetic command>",
            "parent_process_name": "agentsim-synthetic-parent",
            "parent_process_id": "100",
            "account_id": "synthetic-account",
            "principal_id": "synthetic-principal",
            "service": "synthetic-service",
            "operation": "synthetic-read",
            "source_ip": "192.0.2.10",
        }
        for index in (1, 2)
    ]
    events = normalize_records(records, synthetic=True)
    evaluation = evaluate_rule(candidate.rule, events)
    coverage = analyze_coverage(ability, events)
    findings = analyze_gaps(ABILITIES, (coverage,), {ability_id: evaluation})
    return jsonify(
        {
            "execution_mode": "synthetic_detection_demo",
            "process_started": False,
            "network_opened": False,
            "candidate": candidate.to_dict(),
            "evaluation": evaluation.to_dict(),
            "coverage": coverage.to_dict(),
            "findings": [finding.to_dict() for finding in findings],
            "runbook": generate_runbook(ability, findings),
        }
    )


@app.route("/api/v1/telemetry/assurance", methods=["POST"])
def api_telemetry_assurance() -> Response:
    """Assess the content-safe reference corpus and run answer-key-free pack rules."""

    _validate_api_token()
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        abort(400, description="JSON request body is required")
    if payload.get("corpus", "reference-agent") != "reference-agent":
        abort(400, description="unsupported assurance corpus")
    runs = run_reference_suite()
    events = tuple(event.to_normalized_event() for run in runs for event in run.events)
    assurance = assess_telemetry(events)
    sweep = sweep_detection_pack(load_detection_pack(), events)
    return jsonify(
        {
            "execution_mode": "synthetic_telemetry_assurance",
            "process_started": False,
            "network_opened": False,
            "trace_count": assurance.trace_count,
            "assurance": assurance.to_dict(),
            "sweep": sweep.to_dict(),
        }
    )


@app.route("/api/v1/telemetry/investigation", methods=["POST"])
def api_telemetry_investigation() -> Response:
    """Build a bounded multi-agent investigation graph from the reference corpus."""

    _validate_api_token()
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        abort(400, description="JSON request body is required")
    if payload.get("corpus", "reference-agent") != "reference-agent":
        abort(400, description="unsupported investigation corpus")
    runs = run_reference_suite()
    events = tuple(event.to_normalized_event() for run in runs for event in run.events)
    return jsonify(
        {
            "execution_mode": "synthetic_multi_agent_investigation",
            "process_started": False,
            "network_opened": False,
            "report": investigate_telemetry(events).to_dict(),
        }
    )


@app.route("/api/v1/defense/feedback-demo", methods=["POST"])
def api_detection_feedback_demo() -> Response:
    """Reconcile a fixed unsafe verdict and compare an offline tuning candidate."""

    _validate_api_token()
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        abort(400, description="JSON request body is required")
    if payload.get("corpus", "detection-feedback-integrity") != "detection-feedback-integrity":
        abort(400, description="unsupported feedback corpus")
    run = run_reference_fixture("detection-feedback-integrity")
    malicious = tuple(
        event
        for event in run.events
        if event.attributes.get("variant") == "malicious"
    )
    alert_event = malicious[0]
    feedback_event = malicious[1]
    alert = DetectionAlert(
        alert_id=str(alert_event.attributes["alert_id"]),
        rule_id="agentsim.feedback-identity-evidence-tampering",
        detected_at=alert_event.timestamp,
        severity="critical",
        trace_id=alert_event.trace_id,
        source_record_ids=(alert_event.event_id,),
        agent_id=alert_event.agent_id,
    )
    annotation = OperatorAnnotation(
        annotation_id=f"{run.run_id}:unsafe-verdict",
        target_type="alert",
        target_id=alert.alert_id,
        disposition="false_positive",
        reason_code="insufficient_evidence",
        author_id=feedback_event.agent_id,
        author_type="agent",
        created_at=feedback_event.timestamp,
        evidence_ids=(alert_event.event_id,),
        evidence_digest_match=False,
    )
    report = reconcile_detection_feedback(
        (alert,),
        tuple(event.to_normalized_event() for event in run.events),
        (annotation,),
    )
    drift = compare_detection_snapshots(
        DetectionSnapshot("reviewed-baseline", 38, 0, 38, 0, 3.0, 4, 4),
        DetectionSnapshot("unsafe-tuning-candidate", 31, 4, 34, 7, 6.0, 2, 4),
    )
    return jsonify(
        {
            "execution_mode": "synthetic_feedback_analysis",
            "process_started": False,
            "network_opened": False,
            "feedback": report.to_dict(),
            "drift": drift.to_dict(),
        }
    )


@app.route("/api/v1/lab/run", methods=["POST"])
def api_v1_lab_run() -> Response:
    _validate_api_token()
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        abort(400, description="JSON request body is required")
    fixture_id = payload.get("fixture_id", "all")
    if not isinstance(fixture_id, str):
        abort(400, description="fixture_id must be a string")
    try:
        results = run_lab_suite() if fixture_id == "all" else (run_fixture(fixture_id),)
    except ValueError as exc:
        abort(400, description=str(exc))
    return jsonify(
        {
            "passed": all(result.passed for result in results),
            "results": [result.to_dict() for result in results],
        }
    )


@app.route("/api/v1/lab/reference", methods=["POST"])
def api_v1_reference_lab_run() -> Response:
    _validate_api_token()
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        abort(400, description="JSON request body is required")
    fixture_id = payload.get("fixture_id", "all")
    if not isinstance(fixture_id, str):
        abort(400, description="fixture_id must be a string")
    try:
        results = (
            run_reference_suite()
            if fixture_id == "all"
            else (run_reference_fixture(fixture_id),)
        )
    except ValueError as exc:
        abort(400, description=str(exc))
    return jsonify(
        {
            "version": "1.5.0",
            "passed": all(result.passed for result in results),
            "results": [result.to_dict() for result in results],
        }
    )


def _debug_artifact_paths() -> tuple[Path, Path]:
    with state_lock:
        events_path = last_ground_truth_path
        report_path = last_validation_path
    if (
        events_path is None
        or report_path is None
        or not events_path.exists()
        or not report_path.exists()
    ):
        abort(404, description="no scenario detection artifacts are available")
    return events_path, report_path


def _load_debug_report(path: Path) -> dict[str, Any]:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        abort(500, description="scenario validation report is unreadable")
    if not isinstance(report, dict) or not isinstance(report.get("results"), list):
        abort(500, description="scenario validation report is invalid")
    return report


@app.route("/api/detection-debug")
def api_detection_debug() -> Response:
    _events_path, report_path = _debug_artifact_paths()
    report = _load_debug_report(report_path)
    traces = []
    for result in report["results"]:
        if not isinstance(result, dict):
            continue
        traces.append(
            {
                "trace_id": result.get("trace_id"),
                "scenario_id": result.get("scenario_id"),
                "scenario_name": result.get("scenario_name"),
                "variant": result.get("variant"),
                "mutation_id": result.get("mutation_id"),
                "expected_detected": result.get("expected_detected"),
                "detected": result.get("detected"),
                "passed": result.get("passed"),
                "detected_at_sequence": result.get("detected_at_sequence"),
                "trace_event_count": result.get("trace_event_count"),
                "signal_count": len(result.get("signal_event_ids", [])),
            }
        )
    return jsonify(
        {
            "run_id": report.get("run_id"),
            "summary": report.get("summary", {}),
            "metrics": report.get("metrics", {}),
            "mutation_summary": report.get("mutation_summary", {}),
            "traces": traces,
        }
    )


@app.route("/api/detection-debug/trace")
def api_detection_debug_trace() -> Response:
    trace_id = request.args.get("trace_id", "")
    if not trace_id:
        abort(400, description="trace_id is required")
    events_path, report_path = _debug_artifact_paths()
    report = _load_debug_report(report_path)
    result = next(
        (
            item
            for item in report["results"]
            if isinstance(item, dict) and item.get("trace_id") == trace_id
        ),
        None,
    )
    if result is None:
        abort(404, description="trace was not found in the current benchmark")
    try:
        trace_events = [
            event
            for event in load_ground_truth(events_path)
            if event.get("trace_id") == trace_id
        ]
    except (OSError, ValueError):
        abort(500, description="scenario ground truth is unreadable")
    definition = SCENARIOS.get(str(result.get("scenario_id", "")))
    detector = dict(definition.detector) if definition is not None else {}
    return jsonify(
        {
            "result": result,
            "detector": detector,
            "events": trace_events,
        }
    )


@app.route("/start", methods=["POST"])
def start_sim() -> Response:
    global is_running, sim_thread, last_layer_path
    global last_ground_truth_path, last_validation_path, last_bundle_path
    global last_benchmark_metrics
    global run_started_at, run_finished_at, current_params, last_outcome
    _validate_form_token()

    run_mode = request.form.get("run_mode", "behavior")
    if run_mode == "scenario":
        scenario_id = request.form.get("scenario", "all")
        variant = request.form.get("variant", "both")
        mutations = _parse_int("mutations", 0, 0, 100)
        mutation_seed_value = request.form.get("mutation_seed", "").strip()
        try:
            mutation_seed = int(mutation_seed_value) if mutation_seed_value else None
        except ValueError:
            abort(400, description="mutation_seed must be an integer")
        if scenario_id != "all" and scenario_id not in SCENARIOS:
            abort(400, description="unknown scenario")
        if variant not in {"malicious", "benign", "both"}:
            abort(400, description="variant must be malicious, benign, or both")
        checkpoints = estimate_event_count(
            scenario_id,
            variant=variant,
            mutation_count=mutations,
        )
        params = {
            "run_mode": "scenario",
            "scenario": scenario_id,
            "variant": variant,
            "speed": _parse_int("speed", 100, 0, 1000),
            "checkpoints": checkpoints,
            "mutations": mutations,
            "mutation_seed": mutation_seed,
        }
        worker = run_scenario_background
    elif run_mode == "behavior":
        seed_value = request.form.get("seed", "").strip()
        try:
            seed = int(seed_value) if seed_value else None
        except ValueError:
            abort(400, description="seed must be an integer")
        params = {
            "run_mode": "behavior",
            "iterations": _parse_int("iterations", 20, 1, 100),
            "speed": _parse_int("speed", 100, 0, 1000),
            "hallucination_rate": _parse_rate("hallucination_rate", 0.15),
            "context_loss_rate": _parse_rate("context_loss_rate", 0.05),
            "retry_rate": _parse_rate("retry_rate", 0.30),
            "evasion_rate": _parse_rate("evasion_rate", 0.10),
            "allow_network": request.form.get("allow_network") == "on",
            "dry_run": request.form.get("dry_run") == "on",
            "seed": seed,
        }
        worker = run_sim_background
    else:
        abort(400, description="run_mode must be behavior or scenario")

    with state_changed:
        if is_running:
            if request.accept_mimetypes.best == "application/json":
                return jsonify({"status": "already running"}), 409
            return redirect(url_for("index"))
        is_running = True
        last_outcome = "running"
        stop_event.clear()
        log_queue.clear()
        last_layer_path = None
        last_ground_truth_path = None
        last_validation_path = None
        last_bundle_path = None
        last_benchmark_metrics = {}
        run_started_at = time.time()
        run_finished_at = None
        current_params = dict(params)
        state_changed.notify_all()

    _append_event(
        "[*] Run requested with validated dashboard parameters.",
        kind="start",
        category="system",
        params=dict(params),
    )
    sim_thread = threading.Thread(
        target=worker,
        kwargs=params,
        daemon=True,
        name="agentsim-worker",
    )
    sim_thread.start()
    return _json_or_redirect({"status": "started"})


@app.route("/stop", methods=["POST"])
def stop_sim() -> Response:
    _validate_form_token()
    with state_lock:
        running = is_running
    if not running:
        if request.accept_mimetypes.best == "application/json":
            return jsonify({"status": "not running"}), 409
        return redirect(url_for("index"))
    stop_event.set()
    _append_event(
        "[!] STOP REQUESTED: Waiting for the current command to finish.",
        kind="stop_requested",
        category="anomaly",
    )
    return _json_or_redirect({"status": "stopping"})


@app.route("/clear", methods=["POST"])
def clear_events() -> Response:
    global last_outcome
    _validate_form_token()
    with state_changed:
        if is_running:
            if request.accept_mimetypes.best == "application/json":
                return jsonify({"status": "running"}), 409
            return redirect(url_for("index"))
        log_queue.clear()
        last_outcome = "ready"
        state_changed.notify_all()
    return _json_or_redirect({"status": "cleared"})


@app.route("/download-layer")
def download_layer() -> Response:
    with state_lock:
        layer_path = last_layer_path
    if layer_path is None or not layer_path.exists():
        abort(404, description="no Navigator layer is available")
    return send_file(
        layer_path,
        mimetype="application/json",
        as_attachment=True,
        download_name="agent_sim_layer.json",
        max_age=0,
    )


@app.route("/download-ground-truth")
def download_ground_truth() -> Response:
    with state_lock:
        artifact_path = last_ground_truth_path
    if artifact_path is None or not artifact_path.exists():
        abort(404, description="no scenario ground truth is available")
    return send_file(
        artifact_path,
        mimetype="application/x-ndjson",
        as_attachment=True,
        download_name="agent_sim_events.jsonl",
        max_age=0,
    )


@app.route("/download-validation")
def download_validation() -> Response:
    with state_lock:
        artifact_path = last_validation_path
    if artifact_path is None or not artifact_path.exists():
        abort(404, description="no scenario validation report is available")
    return send_file(
        artifact_path,
        mimetype="application/json",
        as_attachment=True,
        download_name="agent_sim_validation.json",
        max_age=0,
    )


@app.route("/download-bundle")
def download_bundle() -> Response:
    with state_lock:
        artifact_path = last_bundle_path
    if artifact_path is None or not artifact_path.exists():
        abort(404, description="no scenario evidence bundle is available")
    return send_file(
        artifact_path,
        mimetype="application/zip",
        as_attachment=True,
        download_name="agent_sim_evidence.zip",
        max_age=0,
    )


@app.route("/stream")
def stream() -> Response:
    try:
        cursor = int(request.headers.get("Last-Event-ID", "0"))
    except ValueError:
        cursor = 0

    def event_stream():
        nonlocal cursor
        while True:
            with state_changed:
                messages = [
                    event for event in log_queue if int(event["id"]) > cursor
                ]
                if not messages:
                    state_changed.wait(timeout=15)
                    messages = [
                        event for event in log_queue if int(event["id"]) > cursor
                    ]
            if messages:
                for event in messages:
                    cursor = int(event["id"])
                    yield (
                        f"id: {cursor}\n"
                        f"data: {json.dumps(event, separators=(',', ':'))}\n\n"
                    )
            else:
                yield ": keep-alive\n\n"

    response = Response(event_stream(), mimetype="text/event-stream")
    response.headers["Cache-Control"] = "no-cache"
    response.headers["X-Accel-Buffering"] = "no"
    return response


def main() -> None:
    raw_port = os.environ.get("AGENTSIM_WEB_PORT", "5000")
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise SystemExit("AGENTSIM_WEB_PORT must be an integer from 1 to 65535") from exc
    if not 1 <= port <= 65535:
        raise SystemExit("AGENTSIM_WEB_PORT must be an integer from 1 to 65535")
    print(f"[*] Starting Web UI on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
