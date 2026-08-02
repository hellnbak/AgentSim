# Detection validation engine

AgentSim v1.4 validates defensive assumptions against exported telemetry or an
explicitly authorized, read-only live query. Offline operation remains the
default and requires no vendor credential.

## Data flow

```text
vendor export OR bounded live query → normalized/redacted events
             → assurance and causal-integrity checks
             → multi-agent graph and invariant investigation
             → lifecycle correlation → field/source coverage
             → detection AST → evidence → gaps/runbook/regression
             → candidate vendor renderers (human review required)
```

## Offline collectors

`jsonl`, `otel`, `sysmon`, `auditd`, `cloudtrail`, `crowdstrike`, `splunk`,
`elastic`, `sentinel`, `logscale`, `panther`, `graylog`, `agent_runtime`,
`otel_genai`, and `mcp_audit` collectors accept a JSON array, a JSON object,
newline-delimited JSON, or common wrapper arrays such as `records`, `events`,
`results`, and `Records`.

Collectors never contact a vendor. A file is rejected above 256 MiB or 250,000
records. Prompt, token, authorization, credential, password, payload, and secret
fields are excluded before normalization.

```bash
agentsim telemetry inspect export.jsonl --collector sysmon
```

The normalized record contract is
[`schemas/normalized-event.schema.json`](schemas/normalized-event.schema.json).
Agent-specific input is projected through the stricter
[`schemas/agent-trace-event.schema.json`](schemas/agent-trace-event.schema.json)
contract described in [AGENT_TELEMETRY.md](AGENT_TELEMETRY.md).

## Telemetry assurance

Run assurance before treating an unmatched rule as meaningful:

```bash
agentsim telemetry doctor agent-events.jsonl \
  --collector agent_runtime \
  --output telemetry-assurance.json
```

The doctor checks invalid or substituted timestamps, missing/duplicate event
IDs, incomplete or generated agent correlation identity, unresolved causal
parents, cross-trace links, causal time inversion, unknown redaction provenance,
and accidental content-field exposure. Reports follow
[`schemas/telemetry-assurance-report.schema.json`](schemas/telemetry-assurance-report.schema.json)
and return `healthy`, `degraded`, or `unusable` plus a 0–100 score and bounded
remediation findings. `--fail-on degraded` is the strict CI mode.

## Multi-agent investigation

When agent, delegation, goal, or memory fields are present, reconstruct the
causal graph before rule interpretation:

```bash
agentsim telemetry investigate agent-events.jsonl \
  --collector agent_runtime \
  --output investigation.json \
  --fail-on elevated
```

The analyzer evaluates delegation endpoint/identity, principal continuity,
goal fingerprint/integrity, and memory provenance/retention/lineage
invariants. High and critical findings include bounded causal paths and
operator remediation. See
[`MULTI_AGENT_INVESTIGATION.md`](MULTI_AGENT_INVESTIGATION.md).

## Live query connectors

Splunk, Elastic, CrowdStrike LogScale, Microsoft Sentinel, Panther, and Graylog
connectors first create a non-executing query plan. Live access is double
opt-in, read-only, exact-target, time/record/response bounded, and credentialed
only from an explicitly named environment variable. Redirects are denied and
remote origins require HTTPS.

When abilities are selected, candidate AST rules and their telemetry
requirements are evaluated together. Outcomes are:

- `detected`: the candidate rule matched;
- `missed`: the rule did not match even though required telemetry was fully
  present; or
- `visibility_gap`: the rule did not match and required sources or fields were
  absent.

See [LIVE_CONNECTORS.md](LIVE_CONNECTORS.md) for vendor dataset formats,
credential names, audit behavior, and CLI examples.

## Detection AST

Rules are JSON objects described by
[`schemas/detection-rule.schema.json`](schemas/detection-rule.schema.json).
Supported expression nodes are:

- `match`: `eq`, `ne`, `in`, `contains`, `exists`, `startswith`, `endswith`,
  or bounded `matches` predicates;
- `all`, `any`, and `not`;
- `sequence` with `max_span_seconds`;
- `threshold` with a time window and optional distinct field;
- `parent_child` using normalized process IDs; and
- `causal_graph` using record IDs and a configurable link field;
- `graph_path` for ordered expressions connected through one or more causal
  link fields within a bounded depth; and
- `graph_fanout` for a root reaching a required number of distinct descendant
  entities.

`group_by` evaluates a full expression independently for each host, user,
agent, principal, session, or resource key. This prevents a sequence from
combining unrelated entities.

Example:

```json
{
  "schema_version": "1.0",
  "rule_id": "example.discovery-burst",
  "name": "Discovery process burst",
  "severity": "medium",
  "group_by": ["host_id", "user_id"],
  "expression": {
    "type": "threshold",
    "count": 2,
    "window_seconds": 300,
    "child": {
      "type": "match",
      "predicates": [
        {"field": "source", "operator": "eq", "value": "process_creation"},
        {"field": "process_name", "operator": "in", "value": ["ps", "top"]}
      ]
    }
  }
}
```

```bash
agentsim detection evaluate rule.json events.jsonl --collector jsonl
```

Evidence is bounded to 100 record references and excludes raw fields.

## Detection packs and sweeps

A detection pack adds explicit `required_fields` and `expected_sources` to
each AST rule. The built-in `agentsim.agent-security-core` pack contains twelve
content-safe investigative rules for untrusted/tainted high-risk tool requests,
policy outcomes, MCP requests, authorization audience and consent failures,
memory writes, attribution gaps, a goal-to-memory-to-tool path, and invalid
memory provenance fanning out across agent identities.

```bash
agentsim detection sweep agent-events.jsonl --collector agent_runtime
agentsim detection sweep agent-events.jsonl \
  --collector agent_runtime \
  --pack reviewed-pack.json \
  --fail-on-visibility-gap
```

The loader rejects scenario answer keys such as `expected_detection` and
`ground_truth`, duplicate rule IDs, unknown pack fields, and rules whose
declared requirements omit fields used by their AST. Sweep outcomes mean:

- `detected`: the AST matched bounded normalized evidence;
- `not_detected`: the declared evidence was available but the AST did not
  match; or
- `visibility_gap`: the AST did not match and one or more declared sources or
  fields were absent.

Sweep reports explicitly record `ground_truth_used: false`. The public schemas
are [`detection-pack.schema.json`](schemas/detection-pack.schema.json) and
[`detection-sweep-report.schema.json`](schemas/detection-sweep-report.schema.json).

## Coverage and defensive analysis

Every ability declares expected sources and required fields. Coverage reports
distinguish a missing source from missing fields. Gap findings include the
ability, severity, evidence, and reviewed remediation. Runbooks add triage,
benign controls, detection objectives, and a repeatable regression command.

```bash
agentsim defense analyze endpoint.discovery.processes events.jsonl \
  --collector crowdstrike
```

## Candidate generation

Candidate rules are derived from ability telemetry contracts and the reviewed
static command catalog. Bundles include Sigma, KQL, SPL, LogScale, EQL, Panther,
Graylog, and a vendor-neutral JSON record.

```bash
agentsim detection generate endpoint.discovery.processes --output-dir candidate
```

Candidate status is never automatically promoted. Before deployment, validate:

1. the malicious baseline;
2. malicious mutations;
3. the benign twin;
4. benign mutations;
5. field availability for each platform;
6. vendor syntax; and
7. environment-specific thresholds and allowlists.

## Regression and CI

```bash
agentsim defense regress rule.json \
  --malicious malicious.jsonl \
  --benign benign.jsonl
```

A regression passes only when the malicious fixture matches and the benign
fixture remains quiet. The command returns exit code `0` on pass and `1` on a
detection or suppression failure.
