# Detection validation engine

AgentSim v1 validates defensive assumptions against exported telemetry without
requiring vendor credentials or live query access.

## Data flow

```text
vendor export → bounded collector → normalized/redacted events
             → lifecycle correlation → field/source coverage
             → detection AST → evidence → gaps/runbook/regression
             → candidate vendor renderers (human review required)
```

## Offline collectors

`jsonl`, `otel`, `sysmon`, `auditd`, `cloudtrail`, `crowdstrike`, `splunk`, and
`agent_runtime` collectors accept a JSON array, a JSON object, newline-delimited
JSON, or common wrapper arrays such as `records`, `events`, `results`, and
`Records`.

Collectors never contact a vendor. A file is rejected above 256 MiB or 250,000
records. Prompt, token, authorization, credential, password, payload, and secret
fields are excluded before normalization.

```bash
agentsim telemetry inspect export.jsonl --collector sysmon
```

The normalized record contract is
[`schemas/normalized-event.schema.json`](schemas/normalized-event.schema.json).

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
- `causal_graph` using record IDs and a configurable link field.

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
