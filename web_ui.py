"""Local Flask dashboard for AgentSim."""

from __future__ import annotations

import hmac
import json
import secrets
import threading
import time
from typing import Any

from flask import Flask, Response, abort, redirect, render_template_string, request, url_for

from core import AgentSim


app = Flask(__name__)
log_queue: list[str] = []
state_lock = threading.Lock()
is_running = False
sim_thread: threading.Thread | None = None
form_token = secrets.token_urlsafe(32)


def log_callback(message: str) -> None:
    with state_lock:
        log_queue.append(str(message))


def run_sim_background(**kwargs: Any) -> None:
    global is_running
    status_message = "[*] Simulation finished. You can start a new one."
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
            log_callback=log_callback,
        )
        simulator.run_simulation(kwargs["iterations"])
    except Exception as exc:  # Keep a failed worker from wedging the UI.
        status_message = f"[!] Simulation failed: {exc}"
    finally:
        with state_lock:
            is_running = False
        log_callback(status_message)


HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>AgentSim Dashboard</title>
    <style>
        body { background-color: #1e1e1e; color: #d4d4d4; font-family: Consolas, monospace; display: flex; flex-direction: column; min-height: 100vh; margin: 0; padding: 20px; box-sizing: border-box; }
        h1 { color: #569cd6; border-bottom: 1px solid #3c3c3c; padding-bottom: 10px; margin-top: 0; font-size: 1.5rem; }
        .container { display: flex; gap: 20px; flex-grow: 1; min-height: 0; }
        .controls { width: 320px; background: #252526; padding: 20px; border-radius: 5px; border: 1px solid #3c3c3c; overflow-y: auto; }
        .console-container { flex-grow: 1; display: flex; flex-direction: column; min-height: 360px; }
        #logs { white-space: pre-wrap; overflow-wrap: anywhere; flex-grow: 1; overflow-y: auto; padding: 10px; border: 1px solid #3c3c3c; background: #000; border-radius: 5px; }
        label { display: block; margin-top: 15px; color: #9cdcfe; }
        input[type="range"], input[type="number"] { width: 100%; margin-top: 5px; box-sizing: border-box; }
        .checkbox { color: #d4d4d4; }
        .checkbox input { margin-right: 8px; }
        .warning { color: #dcdcaa; font-size: 0.85rem; line-height: 1.4; }
        button { background-color: #4caf50; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; margin-top: 20px; width: 100%; font-size: 16px; }
        button:disabled { background-color: #555; cursor: not-allowed; }
        .val { color: #ce9178; float: right; }
        @media (max-width: 800px) { .container { flex-direction: column; } .controls { width: auto; } }
    </style>
</head>
<body>
    <h1>AgentSim Control Center</h1>
    <div class="container">
        <div class="controls">
            <form action="/start" method="post">
                <input type="hidden" name="form_token" value="{{ form_token }}">
                <label for="iter">Iterations: <span class="val" id="val-iter">30</span></label>
                <input type="range" id="iter" name="iterations" min="1" max="100" value="30" oninput="document.getElementById('val-iter').textContent = this.value">

                <label for="speed">Speed (ms): <span class="val" id="val-speed">100</span></label>
                <input type="range" id="speed" name="speed" min="0" max="1000" value="100" oninput="document.getElementById('val-speed').textContent = this.value">

                <label for="hall">Hallucination Rate: <span class="val" id="val-hall">0.15</span></label>
                <input type="range" id="hall" name="hallucination_rate" min="0" max="1" step="0.05" value="0.15" oninput="document.getElementById('val-hall').textContent = this.value">

                <label for="ctx">Context Loss Rate: <span class="val" id="val-ctx">0.05</span></label>
                <input type="range" id="ctx" name="context_loss_rate" min="0" max="1" step="0.05" value="0.05" oninput="document.getElementById('val-ctx').textContent = this.value">

                <label for="retry">Retry Rate: <span class="val" id="val-retry">0.30</span></label>
                <input type="range" id="retry" name="retry_rate" min="0" max="1" step="0.05" value="0.30" oninput="document.getElementById('val-retry').textContent = this.value">

                <label for="evasion">Evasion Rate: <span class="val" id="val-evasion">0.10</span></label>
                <input type="range" id="evasion" name="evasion_rate" min="0" max="1" step="0.05" value="0.10" oninput="document.getElementById('val-evasion').textContent = this.value">

                <label for="seed">Random seed (optional)</label>
                <input type="number" id="seed" name="seed" step="1">

                <label class="checkbox"><input type="checkbox" name="dry_run">Dry run (execute nothing)</label>
                <label class="checkbox"><input type="checkbox" name="allow_network">Allow cloud CLI network requests</label>
                <p class="warning">Local read-only commands execute by default. Cloud actions require explicit opt-in.</p>

                <button id="start-button" type="submit" {% if is_running %}disabled{% endif %}>{% if is_running %}Running...{% else %}Start Simulation{% endif %}</button>
            </form>
        </div>
        <div class="console-container">
            <div id="logs" role="log" aria-live="polite"></div>
        </div>
    </div>
    <script>
        const eventSource = new EventSource('/stream');
        eventSource.onmessage = function(event) {
            const logs = document.getElementById('logs');
            const message = JSON.parse(event.data);
            logs.textContent += message + '\n';
            logs.scrollTop = logs.scrollHeight;
            if (message.startsWith('[*] Simulation finished') || message.startsWith('[!] Simulation failed')) {
                const button = document.getElementById('start-button');
                button.disabled = false;
                button.textContent = 'Start Simulation';
            }
        };
    </script>
</body>
</html>
'''


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


@app.after_request
def set_security_headers(response: Response) -> Response:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.route("/")
def index() -> str:
    with state_lock:
        running = is_running
    return render_template_string(
        HTML_TEMPLATE,
        is_running=running,
        form_token=form_token,
    )


@app.route("/start", methods=["POST"])
def start_sim() -> Response:
    global is_running, sim_thread
    submitted_token = request.form.get("form_token", "")
    if not hmac.compare_digest(submitted_token, form_token):
        abort(400, description="invalid form token")

    seed_value = request.form.get("seed", "").strip()
    try:
        seed = int(seed_value) if seed_value else None
    except ValueError:
        abort(400, description="seed must be an integer")

    params = {
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

    with state_lock:
        if is_running:
            return redirect(url_for("index"))
        is_running = True
        log_queue.clear()
        log_queue.append(f"[*] Starting simulation with params: {params}")
        sim_thread = threading.Thread(
            target=run_sim_background,
            kwargs=params,
            daemon=True,
            name="agentsim-worker",
        )
        sim_thread.start()
    return redirect(url_for("index"))


@app.route("/stream")
def stream() -> Response:
    def event_stream():
        next_index = 0
        while True:
            with state_lock:
                messages = log_queue[next_index:]
                next_index += len(messages)
            if messages:
                for message in messages:
                    yield f"data: {json.dumps(message)}\n\n"
            else:
                time.sleep(0.1)

    response = Response(event_stream(), mimetype="text/event-stream")
    response.headers["Cache-Control"] = "no-cache"
    response.headers["X-Accel-Buffering"] = "no"
    return response


def main() -> None:
    print("[*] Starting Web UI on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)


if __name__ == "__main__":
    main()
