# AgentSim

Detection-first adversary emulation for endpoints, cloud, and agentic AI.

**EMULATE → OBSERVE → DETECT → DEFEND → RETEST**

AgentSim is an open-source purple-team framework that connects bounded attack
behavior to ground truth, telemetry expectations, detection validation,
defensive recommendations, cleanup verification, and repeatable evidence. It
is deliberately not a general exploitation toolkit or command-and-control
platform.

Version 0.4.0, **Adversary Emulation Foundation**, adds directed campaigns,
reviewed ability content, scoped authorization, execution providers, action
lifecycle schema v3, persistent run history, and a safe campaign workflow in
the dashboard. The existing synthetic agentic benchmark remains
simulation-only.

## What makes AgentSim different

A conventional attack framework often stops after an action runs. AgentSim
records and evaluates the complete defensive lifecycle:

```text
planned → authorized → prepared → attempted → simulated/executed
        → observed → detected/missed/pending
        → cleanup started → cleaned → verified
```

Every v0.4 ability defines expected telemetry, detection objectives, benign
controls, and defenses. Campaign runs produce an immutable authorization/run
manifest, lifecycle-v3 JSONL, a defensive report, SQLite history, and a ZIP
evidence bundle.

## Three separate content contracts

| Content | Purpose | Execution |
| --- | --- | --- |
| Scenario pack | Malicious/benign agentic traces and detector tests | Never |
| Ability pack | One reviewed adversary behavior | Gated by provider and policy |
| Campaign pack | Directed ability graph, objective, telemetry, and stop conditions | Gated by provider and policy |

Scenario validation still requires `attributes.executed: false` for proposed
sensitive actions and permits only synthetic or loopback resources. Ability
and campaign files cannot embed commands, scripts, payloads, or arbitrary shell
text. Abilities reference an independently checksummed, reviewed static command
catalog with `catalog://...` identifiers.

## Execution modes

| Mode | Provider | Boundary |
| --- | --- | --- |
| `simulate` | Simulation | Default; starts no process and opens no network connection |
| `emulate` | Local | Static reviewed argv on an explicit `localhost://` target |
| `lab` | Docker | Static reviewed argv inside an explicitly named `docker://` container |

The public core rejects elevation, production targets, unallowlisted targets,
expired authorization, arbitrary command input, and state-changing abilities
without cleanup. Network access requires approval from the ability, run flag,
and authorization manifest.

External Atomic Red Team, Stratus Red Team, CALDERA, and Attack Flow adapters
are planned for later releases; AgentSim will integrate with those projects
instead of duplicating their exploitation or C2 functionality.

## Included coverage

### Directed endpoint and cloud abilities

Eight built-in abilities migrate the original read-only discovery catalog:

- system, user, account, process, and group discovery;
- network connection and network configuration discovery; and
- authenticated read-only cloud service discovery.

Two built-in campaigns provide an endpoint discovery baseline and a
simulation-first cloud visibility baseline. See [`ABILITIES.md`](ABILITIES.md)
and [`CAMPAIGNS.md`](CAMPAIGNS.md).

### Agentic detection benchmark

Nineteen built-in scenarios cover prompt injection, memory and RAG poisoning,
MCP tool and identity abuse, confused-deputy/SSRF intent, inter-agent spoofing,
cascading delegation, deceptive and replayed approvals, rogue policy evasion,
unexpected code-execution intent, recursive cost abuse, decoy-secret intent,
model fallback downgrade, planner/executor policy gaps, tenant confusion,
emergent tool chains, and agent registry poisoning.

Every malicious trace has a benign twin and a label-independent reference
detector. Optional mutations test resilience. Scenario runs preserve JSONL,
JUnit, SARIF, OpenTelemetry-compatible logs, coverage, scorecards, and ZIP
evidence bundles. See [`SCENARIOS.md`](SCENARIOS.md).

## Requirements

- Python 3.9 or newer
- Flask 3.1 or newer for the local Web UI
- Docker only when explicitly using `--mode lab`

The CLI foundation has no vendor credentials or direct SIEM dependency.
Detection outcomes can be supplied as an offline JSON mapping.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install .
```

On Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

## Quick start

Inspect the reviewed content:

```bash
agentsim --version
agentsim ability list
agentsim campaign list
```

Plan the endpoint campaign against the included simulation-only authorization:

```bash
agentsim campaign plan endpoint-discovery-baseline \
  --mode simulate \
  --target synthetic://ci \
  --authorization examples/authorization.simulate.json
```

Run it without starting a process:

```bash
agentsim campaign run endpoint-discovery-baseline \
  --mode simulate \
  --target synthetic://ci \
  --authorization examples/authorization.simulate.json
```

The run creates:

```text
agent_sim_campaign_runs/<run-id>/
├── run-manifest.json
├── action-lifecycle.jsonl
├── campaign-report.json
└── evidence.zip
```

Inspect persistent history:

```bash
agentsim campaign history
```

Run one ability through the same authorization and lifecycle pipeline:

```bash
agentsim ability run endpoint.discovery.processes \
  --mode simulate \
  --target synthetic://ci \
  --authorization examples/authorization.simulate.json
```

### Local emulation

Local execution is never the default. Create a short-lived authorization
manifest that names the exact `localhost://` target, allowed ability IDs,
resource limits, and `emulate` mode. Then run:

```bash
agentsim campaign run endpoint-discovery-baseline \
  --mode emulate \
  --target localhost://detection-lab \
  --authorization /path/to/short-lived-local-authorization.json
```

Commands are resolved from the reviewed catalog into argv arrays and executed
without user-controlled shell interpolation. Output content is not persisted;
only its byte count and SHA-256 digest are recorded.

### Docker lab

The Docker provider requires an existing, disposable Linux container named in
both the target URI and authorization allowlist:

```bash
agentsim campaign run endpoint-discovery-baseline \
  --mode lab \
  --target docker://agentsim-lab \
  --authorization /path/to/short-lived-lab-authorization.json
```

AgentSim does not create, pull, or select a container implicitly.

## Synthetic scenario and MCP labs

The v0.3 flags remain compatible:

```bash
agentsim --list-scenarios
agentsim --scenario all --variant both --mutations 1 --mutation-seed 42 --speed 0
agentsim --mcp-lab
```

Legacy randomized endpoint behavior is now a safe preview by default:

```bash
agentsim --iterations 12 --seed 42
```

Explicit legacy local execution requires `--execute-local`. New automation
should prefer abilities and campaigns because they also require scoped
authorization and produce lifecycle-v3 evidence.

## Web UI

```bash
agentsim-web
```

Open `http://127.0.0.1:5000`. The development server binds only to localhost.
The dashboard includes:

- safe endpoint behavior preview and explicit local opt-in;
- the synthetic agentic scenario benchmark;
- the human Detection Debugger;
- an **Authorized campaign foundation** card that runs simulation-only
  campaigns through lifecycle v3; and
- SQLite-backed campaign history.

The campaign card intentionally exposes only `simulate`. Local and Docker
execution require the CLI and an operator-created authorization manifest.

## Authorization manifests

An authorization manifest records who approved a run, its purpose, issuance
and expiration, modes, exact targets, ability IDs, network decision, and
resource limits. The machine-readable contract is
[`schemas/authorization-manifest.schema.json`](schemas/authorization-manifest.schema.json).

Target URI examples:

- `synthetic://ci`
- `localhost://detection-lab`
- `docker://agentsim-lab`
- `ip://192.0.2.10`, authorized through an explicit `cidr://192.0.2.0/24`
- `cloud://aws/security-sandbox`

Built-in abilities set `production_allowed: false`; a production cloud target
therefore fails closed even if it appears in a manifest.

## Detection content

The [`detections/`](detections/) directory contains experimental Sigma,
Microsoft KQL, Splunk SPL, CrowdStrike LogScale CQL, Graylog, Panther, and
Elastic EQL examples. Agent-runtime rules never query ground-truth labels.
See [`DETECTIONS.md`](DETECTIONS.md).

## Safety guarantees

- Simulation is the default for campaigns and legacy endpoint behavior.
- Scenario packs remain non-executing and synthetic-only.
- Campaigns reference abilities; they cannot contain executable text.
- Ability packs, campaign packs, and reviewed command catalogs require
  canonical SHA-256 integrity metadata.
- Local execution requires an explicit localhost target and short-lived
  authorization.
- Target allowlists accept exact named URIs or explicit CIDRs; wildcard target
  scope is not accepted.
- Docker execution requires an explicitly named existing container.
- Network use requires ability, manifest, and run approval.
- Production execution is disabled for every built-in ability.
- State-changing abilities require cleanup metadata; cleanup always runs in a
  `finally` path and is recorded.
- Kill-switch and resource-limit checks apply before actions and processes;
  cancellation preserves a separate bounded cleanup reserve.
- Raw command output, tokens, prompts, and secrets are not written to evidence.
- SQLite stores the immutable manifest hash and append-only action/event rows.

Read-only does not mean impact-free. Local discovery can expose system metadata
to local process telemetry or trigger alerts. Run it only on systems you own or
are explicitly authorized to test.

See [`SECURITY.md`](SECURITY.md) and [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Development

```bash
python -m py_compile core.py mcp_lab.py scenarios.py tactics.py web_ui.py
python -m compileall -q agentsim
python -m unittest discover -s tests -v
agentsim campaign run endpoint-discovery-baseline \
  --mode simulate \
  --target synthetic://ci \
  --authorization examples/authorization.simulate.json
```

Tests must mock local or Docker process execution. See
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Project status

AgentSim 0.4.0 is an alpha foundation. Direct telemetry collectors, temporal
and graph detector ASTs, candidate rule generation, isolated agentic fixtures,
and external attack-provider adapters remain planned work.

## License and attribution

AgentSim is available under the [MIT License](LICENSE).

MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation.
AgentSim is not affiliated with, sponsored by, or endorsed by MITRE. See
[`NOTICE`](NOTICE).
