# AgentSim

AgentSim is an open-source defensive lab for testing detections of autonomous
and agentic AI behavior. It can create endpoint process telemetry with a
randomized command-selection loop, or emit structured ground truth for safe AI
agent attack scenarios. It does not use an LLM, exploitation code, real
credential access, persistence, or lateral movement.

The endpoint simulator uses a static catalog of read-only commands mapped to
MITRE ATT&CK® Enterprise techniques. The scenario lab records proposed agent
actions and policy decisions for prompt injection, tool poisoning, and decoy
secret access without invoking a tool or opening a network connection. Both are
available through the CLI and local Web dashboard.

> [!CAUTION]
> Endpoint behavior mode executes local operating-system commands by default.
> Run it only on systems you own or are explicitly authorized to test. Start
> with `--dry-run`. Agentic scenario mode is always simulation-only.

## What it simulates

### Endpoint behavior

AgentSim models behavioral patterns that can help exercise detections:

- rapid, varied host-discovery commands;
- incorrect commands caused by losing track of the host OS;
- baseline discovery repeated after simulated context loss;
- retries and shell pivots after command errors;
- nested shell execution; and
- transitions from host discovery to privilege/network discovery and optional
  cloud service discovery.

### Agentic attack scenarios

- indirect prompt injection that causes goal drift and a proposed sensitive
  tool call;
- an MCP tool definition that changes outside its trusted baseline and expands
  permissions; and
- synthetic decoy-secret access followed by blocked, loopback-only exfiltration.

Each malicious trace has a benign twin and deterministic detection check. Runs
write line-delimited JSON ground truth and a validation report. See
[`SCENARIOS.md`](SCENARIOS.md) for the event schema, safety boundary, mappings,
and integration guidance.

AgentSim is a deterministic or randomized state-machine lab, not an LLM or a
full adversary-emulation framework. Scenario framework mappings are references,
not claims of complete coverage or certification.

## Requirements

- Python 3.9 or newer
- No third-party dependencies for the CLI
- Flask 3.1 or newer for the Web UI

The target commands themselves vary by platform. Missing utilities are treated
as command failures, which is useful when testing retry behavior.

## Quick start

Clone or download the repository, then preview a deterministic run without
executing commands:

```bash
python core.py --dry-run --iterations 12 --seed 42
```

Run every agentic scenario with malicious and benign controls:

```bash
python core.py --scenario all --variant both --speed 0
```

This writes `agent_sim_events.jsonl` and `agent_sim_validation.json`. A
successful run exits with status 0 only when every malicious trace is detected
and every benign twin is rejected by the built-in correlation checks.

Run the local, read-only command set:

```bash
python core.py --iterations 20
```

The simulation writes `agent_sim_layer.json` in the current directory. Upload
that file to [ATT&CK Navigator](https://mitre.github.io/attack-navigator/enterprise/)
to inspect the selected techniques.

### Web UI

Create a virtual environment and install the Web dependency:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python web_ui.py
```

On Windows PowerShell, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

Open `http://127.0.0.1:5000`. The development server binds only to localhost.
Choose **Endpoint behavior** for presets, probability controls, seeded runs,
dry-run mode, and explicit cloud-network opt-in. Choose **Agentic attack
scenarios** to run one or all simulation-only traces with malicious and benign
controls. The dashboard streams structured checkpoints and provides the
Navigator layer or scenario ground truth and validation report for download.

You can also install the project and use console commands:

```bash
python -m pip install .
agentsim --dry-run
agentsim-web
```

## CLI options

| Option | Default | Description |
| --- | ---: | --- |
| `--list-scenarios` | off | List safe agentic scenario IDs and descriptions. |
| `--scenario` | none | Run one scenario ID or `all` instead of endpoint behavior. |
| `--variant` | `both` | Emit `malicious`, `benign`, or both scenario traces. |
| `--ground-truth-output` | `agent_sim_events.jsonl` | Scenario JSONL output path. |
| `--validation-output` | `agent_sim_validation.json` | Scenario validation report path. |
| `-i`, `--iterations` | `20` | Number of cycles; must be at least 1. |
| `--speed` | `100` | Delay between actions in milliseconds; may be 0. |
| `--hallucination-rate` | `0.15` | Chance of trying syntax from the wrong OS. |
| `--context-loss-rate` | `0.05` | Chance of re-running baseline discovery. |
| `--retry-rate` | `0.30` | Chance of retrying after an access error. |
| `--evasion-rate` | `0.10` | Chance of wrapping a command in nested shells. |
| `--dry-run` | off | Select and log commands without executing them. |
| `--allow-network` | off | Permit read-only cloud CLI requests. |
| `--seed` | random | Make command selection reproducible. |
| `--output` | `agent_sim_layer.json` | Navigator layer output path. |

All rate values must be between `0.0` and `1.0`.

Use `agentsim --list-scenarios` after installation to discover scenario IDs.
`--speed` controls the delay between scenario checkpoints as well as endpoint
actions.

## Simulation phases

1. **Host Discovery** — system information, current user, local accounts, and
   processes.
2. **Privilege and Network Discovery** — local groups, network connections, and
   network configuration.
3. **Cloud Service Discovery** — AWS, Azure, or Google Cloud CLI queries. Real
   execution is skipped unless `--allow-network` is supplied.

Runs with fewer than three iterations execute only the earliest phases. Longer
runs distribute cycles across all three phases in order.

## Scope and safety

- The trusted command catalog in [`tactics.py`](tactics.py) contains discovery
  commands only; it does not modify files, users, services, or network settings.
- Read-only does not mean impact-free. Discovery can expose sensitive system
  metadata to the local console and endpoint tooling, consume resources, or
  trigger security alerts.
- AgentSim captures command output in memory only to recognize errors. It does
  not print, persist, or transmit that output.
- Cloud commands are disabled by default. With `--allow-network`, installed
  cloud CLIs may make authenticated read-only API requests using the current
  user's configuration and credentials.
- AgentSim does not send telemetry to a SIEM or EDR. Your existing process
  monitoring must collect the child-process activity it creates.
- Nested-shell behavior is conspicuous simulation telemetry, not a claim that
  shell wrapping bypasses EDR controls.
- Scenario mode does not execute operating-system commands, tool calls, file
  reads, or network requests. It records synthetic proposed actions only.
- Scenario prompt content, tool arguments, tool results, and payloads are not
  stored. Synthetic fingerprints and classifications provide correlation keys.
- The exfiltration scenario uses a loopback URL in its event data, but
  `executed` remains false and no socket is opened.

For vulnerabilities in AgentSim itself, follow [`SECURITY.md`](SECURITY.md).

## Detection content

The [`detections/`](detections/) directory contains experimental endpoint
examples for Sigma-compatible tools, Microsoft Defender XDR, Splunk,
CrowdStrike Falcon LogScale, Graylog, and Panther. Scenario mode adds portable,
labeled agent-workflow events for testing correlations across input trust, goal
changes, tool definitions, tool requests, results, network intent, and policy
decisions. See [`DETECTIONS.md`](DETECTIONS.md) for both validation workflows.

## Development

Run the test suite without executing the command catalog:

```bash
python -m unittest discover -s tests -v
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the command safety policy and pull
request checklist. Community expectations are in
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Release history is in
[`CHANGELOG.md`](CHANGELOG.md).

## Project status

AgentSim is experimental defensive tooling. ATT&CK, MITRE ATLAS, OWASP
Agentic, and NIST mappings plus example detections should be reviewed as the
frameworks and telemetry schemas evolve.

## License and attribution

AgentSim is available under the [MIT License](LICENSE).

MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation.
AgentSim is not affiliated with, sponsored by, or endorsed by MITRE. See
[`NOTICE`](NOTICE) for the required ATT&CK attribution.
