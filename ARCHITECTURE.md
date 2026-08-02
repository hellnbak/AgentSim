# AgentSim v1.3 architecture

AgentSim separates content, execution, authorization, telemetry, detection,
and defensive evaluation so synthetic traces cannot silently become executable
behavior and external integrations cannot bypass the public-core boundary.

```mermaid
flowchart TD
    Campaign["Campaign / Attack Flow"] --> Policy["Authorization and safety policy"]
    Policy --> Sim["Simulation provider"]
    Policy --> Local["Local provider"]
    Policy --> Docker["Docker lab provider"]
    Policy --> Plan["External plan adapters"]
    Plan --> Plugin["Explicit executor plugin outside public core"]
    Sim --> Timeline["Lifecycle-v3 ground truth"]
    Local --> Timeline
    Docker --> Timeline
    Plugin --> Timeline
    Timeline --> Store["SQLite run, action, event, detection, artifact history"]
    Export["Offline vendor exports"] --> Collect["Bounded collectors and redaction"]
    Live["Explicit read-only SIEM query"] --> Collect
    Runtime["Agent / OTel GenAI / MCP audit"] --> Contract["Content-safe agent trace contract"]
    Contract --> Collect
    Collect --> Normalize["Normalized event model"]
    Normalize --> Assure["Telemetry assurance and causal integrity"]
    Assure --> Correlate["Ground-truth correlation"]
    Assure --> Sweep["Answer-key-free detection-pack sweep"]
    Timeline --> Correlate
    Correlate --> Detect["Detection AST and coverage analysis"]
    Sweep --> Detect
    Detect --> Candidate["Human-review candidate renderers"]
    Detect --> Defense["Gaps, runbooks, scorecards, regression"]
    Candidate --> Bundle["Portable evidence bundle"]
    Defense --> Bundle
```

## Package layout

```text
agentsim/
├── cli.py                 stable v1 CLI and legacy dispatch
├── api.py                 stable Python API
├── plugins.py             entry-point metadata and API 1.0 contracts
├── models/                ability, campaign, target, result, event, agent telemetry
├── content/               strict loaders, integrity, RSA trust, signed content
├── orchestration/         directed planning and lifecycle runner
├── execution/             simulate, local, and Docker provider interfaces
├── external/              non-executing Atomic, Stratus, CALDERA plans
├── safety/                authorization, target scope, policy, limits, cleanup
├── telemetry/             contracts, collectors, assurance, live connectors, correlation
├── detection/             AST, packs, evaluator, coverage, generator, renderers
├── defense/               recommendations, gaps, runbooks, regression, scorecard
├── lab/                   in-memory controls and instrumented reference agent
├── reporting/             bundles and Attack Flow STIX interchange
└── web/                   packaged loopback Web entry point
```

The root `core.py`, `scenarios.py`, `tactics.py`, `mcp_lab.py`, and `web_ui.py`
remain compatibility surfaces. New automation should use `agentsim.cli` or
`agentsim.api`.

## Trust boundaries

### Scenario packs

Scenario packs are non-executing fixtures. Validators require action events to
set `attributes.executed: false`, restrict resources to synthetic/loopback
identifiers, reject prompt/token/payload recording, and prevent detectors from
reading ground-truth labels.

### Ability and campaign packs

Abilities reference reviewed `catalog://` argv; campaign steps reference
abilities. Unknown executable fields fail closed. Canonical SHA-256 digests
protect content arrays, and built-in content adds an RSA PKCS#1 v1.5 SHA-256
signature verified against `agentsim/content/trusted_keys.json`.

The signing private key is not distributed. Third-party packs may use checksum
integrity without claiming AgentSim trust; deployments can maintain their own
review/signing pipeline rather than modifying the built-in trust key.

### External adapters and plugins

External adapters return a hashed `ExternalPlan`; they do not run a command or
make an HTTP request. Plans require exact semantic versions, typed identifiers,
explicit targets, and cleanup phases. CALDERA plans exclude credentials.

Plugin discovery reads entry-point metadata without importing code. Loading is
an explicit act and enforces plugin API `1.0`. An external executor is outside
the public core and must independently enforce authorization, version, target,
resource, cleanup, and evidence contracts.

### Live telemetry connectors

Live connectors are a narrow read-only exception to the public core's general
non-networking default. Building a plan never contacts a vendor. Execution
requires `--execute` plus `--allow-network`; exact datasets and targets are
mandatory; time, record, response, timeout, redirect, and TLS constraints are
enforced. Only a credential environment-variable name is serialized. The
credential value and request authorization header are never placed in the
plan, audit record, normalized events, or output artifact.

The connector boundary retrieves telemetry only. It cannot create, update,
deploy, or delete vendor detections, dashboards, indexes, users, or policies.

## Authorization and execution

Before preparation, the safety policy checks manifest expiration, mode, exact
target/CIDR, ability scope, provider compatibility, target type, production
lockout, elevation, network triple-consent, and cleanup metadata. Denied actions
still produce `planned`, `denied`, and `prevented` evidence.

`ExecutionProvider` exposes `prepare`, `execute`, and `cleanup`:

- Simulation validates lifecycle without starting a process.
- Local resolves static argv for an explicit localhost target.
- Docker uses static argv with `docker exec` against a named existing container.

Cleanup is called from a `finally` path. Kill-switch cancellation stops new
actions while keeping a separately bounded cleanup reserve.

## Telemetry and detection

Offline collectors read local JSON/JSONL exports, enforce a 256 MiB and 250,000
record limit, normalize known vendor fields, inventory available fields, and
discard fields whose names indicate prompts, credentials, secrets, tokens,
payloads, or authorization data.

The agent trace contract adds stable correlation and authorization fields for
agent runtimes, OpenTelemetry GenAI spans, and MCP audit records. Raw prompts,
messages, tool arguments/results, and model responses are excluded by design.
Live connector responses pass through the same normalized/redacted event model.

Telemetry assurance runs before interpretation. It checks source timestamps,
stable record IDs, native agent identities, causal edge resolution, cross-trace
links, temporal inversions, and the content-redaction boundary. It never reads
or emits prompt/tool content. A degraded or unusable report is evidence about
observability quality, not evidence that an attack occurred.

The detection AST is data, not executable code. Evaluation is deterministic and
bounded. Regex values are length-limited; evidence is capped and contains only
record identity, time, source, type, and synthetic status. Grouping prevents
cross-host or cross-principal sequence matches.

Candidate generation uses reviewed ability metadata and static command names.
It does not inspect raw command output or deploy a rule. Rendered content is
marked experimental/candidate and includes known limitations.

Detection packs are strict JSON data. The loader rejects answer-key fields,
duplicate rule IDs, undeclared rule fields, unknown pack fields, oversized
packs, and executable expressions. A sweep reports `detected`,
`not_detected`, or `visibility_gap`; it does not claim malicious/benign ground
truth and does not deploy vendor content.

## Persistence and evidence

SQLite stores immutable manifest JSON/hash, action results, append-only
lifecycle events, detection evaluations, artifact metadata, and redacted live
query audits. Only final run status/summary fields and explicit post-run
detection counters are updated.

The v1 evidence ZIP contains the manifest, lifecycle JSONL, campaign report,
scorecard, runbooks, candidate detections, and Attack Flow export. Process
output is reduced to return codes, byte count, and SHA-256 digest before any
evidence is persisted.

The public schemas are in [schemas](schemas/), including normalized events,
detection rules, external plans, agent trace events, live query plans,
reference-lab results, telemetry-assurance reports, detection packs and sweep
reports, signed packs, authorization, and lifecycle v3.
