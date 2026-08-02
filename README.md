# AgentSim

Detection-first adversary emulation for endpoints, cloud, and agentic AI.

**EMULATE → OBSERVE → DETECT → DEFEND → RETEST**

AgentSim is an open-source purple-team framework that connects bounded attack
behavior to ground truth, telemetry coverage, detection validation, defensive
guidance, cleanup verification, and repeatable evidence. It is deliberately not
a general exploitation toolkit or command-and-control platform.

Version 1.5.0 adds structured detection-feedback reconciliation, alert-to-trace
evidence binding, operator-verdict integrity checks, and explicit tuning-drift
gates over malicious and benign baselines. Five new malicious/benign scenarios,
a disposable feedback-integrity fixture, three reusable detections, and a new
dashboard workspace make feedback-loop and automated-remediation failures
directly testable without recording prompt or tool content. The release
preserves the v1 simulation-first and non-exploitation boundaries.

## Core workflow

Every campaign action records a complete lifecycle:

```text
planned → authorized → prepared → attempted → simulated/executed
        → observed → prevented/detected/missed/pending
        → cleanup started → cleaned → verified
```

AgentSim then correlates exported telemetry, evaluates vendor-neutral rules,
checks field availability, creates human-review candidate detections, explains
defensive gaps, and emits regression-ready evidence.

## v1.5 capabilities

- Eight reviewed endpoint/cloud abilities and two directed campaigns.
- Strict scenario, ability, and campaign content boundaries.
- Simulation, localhost, and named Docker execution providers.
- Expiring authorization, exact target/CIDR scope, production lockout, resource
  limits, kill switch, redaction, and mandatory cleanup paths.
- Offline JSON/JSONL collectors for OTel, Sysmon, auditd, CloudTrail,
  CrowdStrike, Splunk, Elastic, Sentinel, LogScale, Panther, Graylog, and
  agent-runtime exports, including OpenTelemetry GenAI and MCP audit profiles.
- Dry-run-first, exact-target live query connectors for Splunk, Elastic,
  CrowdStrike LogScale, Microsoft Sentinel, Panther, and Graylog. Execution
  requires both `--execute` and `--allow-network`; credentials remain in named
  environment variables.
- Detection AST supporting field predicates, boolean logic, ordered sequences,
  time windows, thresholds, distinct counts, parent/child relationships,
  causal graphs, bounded multi-link graph paths and fan-out, negative
  conditions, and host/user/resource grouping.
- A telemetry-assurance doctor that scores timestamp integrity, stable event
  identity, agent correlation coverage, causal links, and content-redaction
  boundaries. Results are `healthy`, `degraded`, or `unusable` with bounded
  findings and remediation.
- A strict, reusable detection-pack contract and fifteen-rule built-in agent
  security pack. Pack sweeps use normalized evidence only—never scenario
  labels—and classify each rule as `detected`, `not_detected`, or
  `visibility_gap`.
- A bounded multi-agent investigation report that reconstructs parent,
  caused-by, delegation, memory, and data-lineage edges; checks delegation
  endpoints, principal continuity, goal fingerprints, memory provenance, and
  retention; and produces evidence-backed operator paths and remediation.
- Strict feedback bundles for alerts and enumerated operator annotations;
  alert-to-trace/evidence reconciliation; detection of unresolved evidence,
  digest mismatch, agent-authored final verdicts, contradictory dispositions,
  and high-risk trace dismissal; and a content-safe feedback report.
- Detection-drift reports that compare precision, recall, false-positive rate,
  benign rejection, alert reconciliation, and checkpoint latency against
  explicit thresholds. Candidates remain offline and are never deployed.
- Candidate renderers for Sigma, Microsoft KQL, Splunk SPL, CrowdStrike
  LogScale, Elastic EQL, Panther Python, and Graylog.
- Telemetry coverage, defensive gap analysis, investigation runbooks,
  malicious/benign regression, and readiness scorecards.
- Thirty-eight declarative agentic scenarios plus twenty-two disposable control
  fixtures and an instrumented reference-agent runtime. Coverage includes
  cross-turn and cross-agent goal hijacking, provenance/tool-result poisoning,
  delegation identity drift, shared-memory retention escape, multi-agent trust
  cascades, alert-verdict poisoning, reconciliation confusion, annotation trust
  abuse, recall collapse, feedback-loop suppression, configuration and
  supply-chain tampering, replay, delayed exfiltration, scope challenge abuse,
  and deceptive summaries.
- Version-pinned, non-executing plans for Atomic Red Team, Stratus Red Team,
  and MITRE CALDERA. The public core does not execute these plans.
- Attack Flow STIX 2.1 import/export.
- RSA-signed built-in ability, campaign, and reviewed-command content.
- SQLite run, action, lifecycle, detection, and artifact records.
- Stable plugin API 1.0 for collectors, detection renderers, telemetry
  connectors, and separately installed external executors.

## Content and execution boundaries

| Content | Purpose | Execution |
| --- | --- | --- |
| Scenario pack | Malicious/benign agentic traces and detector tests | Never |
| Ability pack | One reviewed adversary behavior | Policy-gated |
| Campaign pack | Directed ability graph and defensive objective | Policy-gated |

| Mode | Provider | Boundary |
| --- | --- | --- |
| `simulate` | Simulation | Default; no process and no network |
| `emulate` | Local | Static reviewed argv on an explicit `localhost://` target |
| `lab` | Docker | Static reviewed argv in an explicitly named existing container |
| external plan | Plugin handoff | Version-pinned plan only; never executed by the public core |

Ability and campaign packs cannot embed commands, scripts, payloads, downloads,
or arbitrary shell text. Abilities reference an independently signed reviewed
catalog with `catalog://...` identifiers. Scenario actions remain synthetic,
redacted, and explicitly non-executing.

## Requirements and install

- Python 3.9 or newer
- Flask 3.1 or newer for the local Web UI
- Docker only for an explicitly authorized `lab` campaign
- External tools only when a separately installed executor plugin is reviewed
  and authorized

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install .
```

Windows PowerShell activation:

```powershell
.venv\Scripts\Activate.ps1
```

## Campaign quick start

```bash
agentsim --version
agentsim ability list
agentsim campaign list

agentsim campaign plan endpoint-discovery-baseline \
  --mode simulate \
  --target synthetic://ci \
  --authorization examples/authorization.simulate.json

agentsim campaign run endpoint-discovery-baseline \
  --mode simulate \
  --target synthetic://ci \
  --authorization examples/authorization.simulate.json

agentsim campaign history
```

A v1 campaign run creates:

```text
agent_sim_campaign_runs/<run-id>/
├── run-manifest.json
├── action-lifecycle.jsonl
├── campaign-report.json
├── defense-scorecard.json
├── defense-runbooks.json
├── detection-candidates.json
├── attack-flow.json
└── evidence.zip
```

Simulation completes the execution/cleanup lifecycle but leaves telemetry and
detection status explicitly unevaluated until exported sensor data or an
offline detection-result map is supplied.

### Local and Docker modes

Local execution is never the default. Create a short-lived authorization that
names the exact target and abilities, then explicitly select `emulate`:

```bash
agentsim ability run endpoint.discovery.processes \
  --mode emulate \
  --target localhost://detection-lab \
  --authorization /path/to/local-authorization.json
```

Docker mode requires an existing disposable container. AgentSim never pulls or
selects an image implicitly:

```bash
agentsim campaign run endpoint-discovery-baseline \
  --mode lab \
  --target docker://agentsim-lab \
  --authorization /path/to/lab-authorization.json
```

## Offline detection workflow

Inspect a vendor export without sending it anywhere:

```bash
agentsim telemetry inspect exported-events.jsonl --collector crowdstrike
```

Check whether the export is trustworthy enough to interpret:

```bash
agentsim telemetry doctor exported-events.jsonl \
  --collector agent_runtime \
  --output telemetry-assurance.json
```

The default exit code fails only for `unusable` evidence. Use
`--fail-on degraded` as a stricter CI gate, or `--fail-on never` when collecting
an advisory report.

Reconstruct multi-agent paths and evaluate delegation, identity, goal, and
memory invariants:

```bash
agentsim telemetry investigate agent-events.jsonl \
  --collector agent_runtime \
  --output investigation.json \
  --fail-on elevated
```

The report remains content-safe and is capped at 5,000 events. See
[MULTI_AGENT_INVESTIGATION.md](MULTI_AGENT_INVESTIGATION.md).

Generate a transparent candidate bundle:

```bash
agentsim detection generate endpoint.discovery.processes \
  --output-dir candidate-process-discovery
```

Evaluate a vendor-neutral rule:

```bash
agentsim detection evaluate rule.json exported-events.jsonl \
  --collector crowdstrike
```

Sweep the built-in agent-security pack without consulting a scenario answer
key:

```bash
agentsim detection sweep agent-events.jsonl \
  --collector agent_runtime \
  --output detection-sweep.json
```

Pass `--pack reviewed-pack.json` for a custom pack and
`--fail-on-visibility-gap` when missing fields should fail CI. A
`not_detected` result means the rule had the declared fields and sources but did
not match; a `visibility_gap` means the evidence cannot support that conclusion.

Analyze expected sources and required fields, then generate a runbook:

```bash
agentsim defense analyze endpoint.discovery.processes exported-events.jsonl \
  --collector crowdstrike
```

Use malicious and benign exports as a CI gate:

```bash
agentsim defense regress rule.json \
  --malicious malicious.jsonl \
  --benign benign.jsonl \
  --collector jsonl
```

Reconcile structured alert feedback to trace evidence, then reject detection
tuning that regresses either baseline:

```bash
agentsim defense reconcile feedback.json agent-events.jsonl \
  --collector agent_runtime \
  --output feedback-report.json \
  --fail-on elevated

agentsim defense drift baseline.json candidate.json \
  --output detection-drift.json
```

See [DETECTION_FEEDBACK.md](DETECTION_FEEDBACK.md) for the strict schemas,
conflict semantics, drift metrics, and change-control workflow.

Exit code `0` means the requested detection/regression condition passed; `1`
means it did not. Generated rules always retain candidate/human-review status.
See [DETECTION_ENGINE.md](DETECTION_ENGINE.md) and [DETECTIONS.md](DETECTIONS.md).

## Live read-only detection validation

Build a secret-free query plan first. The plan records the exact dataset,
target, time window, limit, endpoint, and query hash but never the credential:

```bash
agentsim telemetry query elastic \
  --base-url https://elastic.example.test \
  --dataset logs-endpoint.events.process-default \
  --target host-123 \
  --since 2026-08-02T00:00:00Z \
  --until 2026-08-02T00:15:00Z
```

After reviewing the plan, explicitly execute it and evaluate one or more
abilities:

```bash
export AGENTSIM_ELASTIC_API_KEY='replace-with-a-read-only-api-key'
agentsim telemetry query elastic \
  --base-url https://elastic.example.test \
  --dataset logs-endpoint.events.process-default \
  --target host-123 \
  --since 2026-08-02T00:00:00Z \
  --until 2026-08-02T00:15:00Z \
  --ability endpoint.discovery.processes \
  --execute --allow-network \
  --output live-validation.json
```

The result classifies each ability as `detected`, `missed`, or
`visibility_gap` and persists a redacted audit record in SQLite. Query windows
are limited to 24 hours, results to 10,000 records, responses to 32 MiB, and
wildcard datasets/targets are rejected. See
[LIVE_CONNECTORS.md](LIVE_CONNECTORS.md).

## Agentic security lab

The existing declarative benchmark remains available:

```bash
agentsim --list-scenarios
agentsim --scenario all --variant both --mutations 1 --mutation-seed 42 --speed 0
agentsim --mcp-lab
```

The v1.5 control fixtures are smaller disposable policy exercises:

```bash
agentsim lab list
agentsim lab run all --output agentic-lab-results.json
agentsim lab run approval-deception
```

These fixtures run in memory. They do not open a socket, start a process, load
a tool/plugin, read a file or credential, or record a prompt/token/payload.

Run the instrumented reference agent directly, or in its hardened container:

```bash
agentsim lab reference all --output reference-lab-results.json
docker compose -f labs/reference-agent/compose.yaml up --build
```

The reference runtime emits requested → policy decision → completed/blocked
causal traces, explicit MCP audience and per-client-consent checkpoints, and a
longer three-agent delegation/goal/memory graph. The feedback fixture adds
alert, verdict, reconciliation, tuning, coverage, and policy checkpoints. It
only applies fixed changes
to an in-memory dictionary for the benign twin. See [SCENARIOS.md](SCENARIOS.md) and
[`labs/reference-agent/README.md`](labs/reference-agent/README.md).

## External provider plans and Attack Flow

The public core only emits reviewed plans:

```bash
agentsim external list

agentsim external plan atomic-red-team \
  --provider-version 2.2.0 \
  --target localhost://atomic-lab \
  --technique-id T1057 \
  --test-guid 11111111-1111-4111-8111-111111111111 \
  --output atomic-plan.json

agentsim external plan stratus-red-team \
  --provider-version 2.17.0 \
  --target cloud://aws/security-sandbox \
  --technique-id aws.discovery.ec2-describe-instances
```

No plan contains credentials, and `execution_supported_by_core` is always
false. Execution requires a separately installed plugin, explicit operator
authorization, a version match, and an isolated target.

```bash
agentsim attack-flow export endpoint-discovery-baseline --output flow.json
agentsim attack-flow import flow.json --output campaign-draft.json
```

Imports are review drafts and must be converted into a signed campaign pack
before execution. See [EXTERNAL_PROVIDERS.md](EXTERNAL_PROVIDERS.md).

## Web workspace

```bash
agentsim-web
```

Open `http://127.0.0.1:5000`. The server binds only to loopback. If that port
is already in use, choose another loopback port with
`AGENTSIM_WEB_PORT=5055 python web_ui.py`. The dashboard
includes safe endpoint preview, the scenario benchmark, human Detection
Debugger, authorized simulation-only campaigns, SQLite history, a synthetic
detection/coverage workspace, a telemetry-assurance and detection-pack view,
and a multi-agent investigation workbench with trace filters, causal
checkpoints, failed invariants, highlighted evidence paths, and remediation.
The feedback workspace shows reconciliation coverage, verdict conflicts, and
offline tuning drift. All twenty-two control fixtures and the instrumented
reference-agent run are available.
Local, Docker, and external execution are intentionally unavailable in the UI.

## Plugin SDK

```bash
agentsim plugin list
```

Plugin metadata is listed without importing third-party code. Explicit loading
enforces API version `1.0`. Entry-point groups are `agentsim.collectors`,
`agentsim.detection_renderers`, `agentsim.telemetry_connectors`, and
`agentsim.external_executors`. See [PLUGIN_SDK.md](PLUGIN_SDK.md).

## Safety guarantees

- Simulation is the default.
- Targets must be exact named URIs or explicit CIDRs; wildcard scope is denied.
- Built-in abilities are locked out of production.
- Network use requires ability, run, and authorization consent.
- Elevation is rejected by the public core.
- State changes require idempotent cleanup metadata and a cleanup attempt.
- Kill-switch cancellation preserves a bounded cleanup reserve.
- Raw command output, prompts, tokens, secrets, credentials, and payloads are
  excluded from evidence.
- Offline collectors limit file size and record count and never query vendors.
- Live connectors are read-only, dry-run by default, exact-target, bounded,
  TLS-validating, redirect-denying, and require a second network opt-in.
- Third-party entry points are not imported during plugin discovery.
- Built-in executable content has both a canonical digest and trusted RSA
  signature.
- External adapter plans are non-executing, version-pinned, hashed, and require
  cleanup phases.

Read-only behavior can still expose local metadata to sensors or trigger
alerts. Use AgentSim only on systems and accounts you own or are explicitly
authorized to test. See [SECURITY.md](SECURITY.md).

## Roadmap

The roadmap is ordered by defensive value, not a release-date commitment.
Interfaces remain subject to review until they are documented as stable.

| Release horizon | Status | Defensive focus |
| --- | --- | --- |
| v1.5 | Current | Structured feedback ingestion, alert-to-trace reconciliation, operator-verdict integrity, offline tuning drift, five feedback-loop scenarios, and an interactive feedback workspace. |
| v1.6 | Next | Portable OTel/ECS/OCSF field mappings, signed community detection-pack review, pack provenance, and cross-runtime fixture conformance. |
| v1.7 | Planned | Detection lifecycle history, explainable baseline comparisons, signed feedback exports, and organization-defined reviewer quorum policies. |
| v2.0 | Direction | Stable content-registry and evidence contracts, reproducible cross-runtime conformance suites, and organization-scale regression orchestration with no implicit production execution. |

Across these releases, AgentSim will remain a detection-validation framework.
Generic exploitation, payload delivery, credential theft, persistence,
command-and-control, automated production rule deployment, raw prompt capture,
and autonomous target selection are explicit non-goals. Roadmap proposals are
welcome through issues and pull requests when they include an observable
defensive outcome, a benign control, and a safe test boundary.

## Development and documentation

```bash
python -m py_compile core.py mcp_lab.py scenarios.py tactics.py web_ui.py
python -m unittest discover -s tests -v
python -m build
```

- [Architecture](ARCHITECTURE.md)
- [Abilities](ABILITIES.md)
- [Campaigns](CAMPAIGNS.md)
- [Detection engine](DETECTION_ENGINE.md)
- [Detection content](DETECTIONS.md)
- [Agent telemetry contract](AGENT_TELEMETRY.md)
- [Telemetry assurance and detection packs](TELEMETRY_ASSURANCE.md)
- [Multi-agent investigation](MULTI_AGENT_INVESTIGATION.md)
- [Detection feedback and drift](DETECTION_FEEDBACK.md)
- [Live telemetry connectors](LIVE_CONNECTORS.md)
- [Agentic scenarios](SCENARIOS.md)
- [External providers](EXTERNAL_PROVIDERS.md)
- [Plugin SDK](PLUGIN_SDK.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)
- [Changelog](CHANGELOG.md)

## License and attribution

AgentSim is available under the [MIT License](LICENSE).

MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation.
AgentSim is not affiliated with, sponsored by, or endorsed by MITRE. See
[NOTICE](NOTICE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
