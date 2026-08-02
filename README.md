# AgentSim

AgentSim is an open-source defensive lab for testing detections of autonomous
and agentic AI behavior. It can create endpoint process telemetry with a
randomized command-selection loop, or emit structured ground truth for safe AI
agent attack scenarios. It does not use an LLM, exploitation code, real
credential access, persistence, or lateral movement.

The endpoint simulator uses a static catalog of read-only commands mapped to
MITRE ATT&CK® Enterprise techniques. The scenario lab records proposed agent
actions and policy decisions across prompt injection, memory and RAG poisoning,
multi-agent trust, approvals, MCP authorization, policy evasion, resource
abuse, code execution intent, and decoy-secret access without invoking a tool
or opening a network connection. Both are available through the CLI and local
Web dashboard.

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

### Agentic detection benchmark

Thirteen built-in scenarios cover indirect prompt injection, cross-session
memory poisoning, RAG integrity poisoning, MCP tool and identity abuse,
confused-deputy/SSRF intent, inter-agent spoofing, cascading delegation,
deceptive approvals, rogue policy evasion, unexpected code execution intent,
recursive cost abuse, and decoy-secret exfiltration.

Each malicious trace has a benign twin and a label-independent reference
detector. Optional semantic-preserving mutations test detection resilience.
Runs produce JSONL ground truth, a scorecard, JUnit, SARIF,
OpenTelemetry-compatible logs, a coverage report, and a ZIP evidence bundle.
See
[`SCENARIOS.md`](SCENARIOS.md) for the event schema, safety boundary, mappings,
custom scenario packs, and integration guidance.

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
python core.py --scenario all --variant both --mutations 3 --mutation-seed 42 --speed 0
```

This writes the complete benchmark artifact set, including
`agent_sim_evidence.zip`. A successful run exits with status 0 only when every
malicious trace is detected and every benign twin is rejected, including
generated mutations.

Exercise MCP authorization controls with protocol-shaped JSON-RPC entirely in
memory:

```bash
python core.py --mcp-lab
```

The lab tests audience validation, per-client consent, token passthrough,
session binding, scopes, and tool allowlisting. It opens no transport and
executes no tool.

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
controls plus optional mutations. The dashboard streams structured
checkpoints, displays precision and recall, and provides either the Navigator
layer or a portable scenario evidence bundle for download.

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
| `--scenario-pack PATH` | none | Add a validated JSON pack or directory; repeatable. |
| `--variant` | `both` | Emit `malicious`, `benign`, or both scenario traces. |
| `--mutations` | `0` | Semantic-preserving mutations per trace, from 0 to 100. |
| `--mutation-seed` | random | Make scenario mutations reproducible. |
| `--ground-truth-output` | `agent_sim_events.jsonl` | Scenario JSONL output path. |
| `--validation-output` | `agent_sim_validation.json` | Scenario validation report path. |
| `--junit-output` | `agent_sim_junit.xml` | CI-compatible test results. |
| `--sarif-output` | `agent_sim_results.sarif` | Benchmark mismatches in SARIF 2.1. |
| `--otel-output` | `agent_sim_otel.jsonl` | OpenTelemetry-compatible log records. |
| `--coverage-output` | `agent_sim_coverage.json` | Framework, event, and detector-field coverage. |
| `--bundle-output` | `agent_sim_evidence.zip` | ZIP containing all benchmark artifacts. |
| `--mcp-lab` | off | Run the in-memory MCP boundary checks. |
| `--mcp-lab-output` | `agent_sim_mcp_lab.json` | MCP security report path. |
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
- Pack validation rejects non-synthetic resource URLs, action checkpoints that
  omit `executed: false`, token/payload recording, duplicate IDs, and detectors
  that consult labels or fire on their own benign controls.
- Scenario prompt content, tool arguments, tool results, and payloads are not
  stored. Synthetic fingerprints and classifications provide correlation keys.
- The exfiltration scenario uses a loopback URL in its event data, but
  `executed` remains false and no socket is opened.

For vulnerabilities in AgentSim itself, follow [`SECURITY.md`](SECURITY.md).

## Detection content

The [`detections/`](detections/) directory contains experimental endpoint and
agent-event examples for Sigma-compatible tools, Microsoft Defender XDR,
Splunk, CrowdStrike Falcon LogScale/Next-Gen SIEM, Graylog, Panther, and Elastic
Security. Scenario mode adds portable workflow events for testing trust,
memory, lineage, delegation, identity, approval, tools, network intent, budgets,
and policy decisions. See [`DETECTIONS.md`](DETECTIONS.md) for both validation
workflows.

## Development

Run the test suite without executing the command catalog:

```bash
python -m py_compile core.py mcp_lab.py scenarios.py tactics.py web_ui.py
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
