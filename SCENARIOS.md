# Agentic Scenario Lab

AgentSim's scenario lab produces safe, labeled traces for validating detections
at AI-agent trust boundaries. It records what an agent observed, proposed, and
was allowed or blocked from doing. It never invokes an AI model or tool.

## Quick start

List scenarios:

```bash
python core.py --list-scenarios
```

Run all malicious traces and their benign twins:

```bash
python core.py \
  --scenario all \
  --variant both \
  --speed 0 \
  --ground-truth-output agent_sim_events.jsonl \
  --validation-output agent_sim_validation.json
```

The command returns 0 when every built-in check has the expected result, 1 when
a check fails, and 130 when interrupted. An interrupted run still exports its
completed checkpoints and a report marked `stopped: true`.

## Included scenarios

| ID | Malicious behavior | Benign twin | Detection correlation |
| --- | --- | --- | --- |
| `indirect-prompt-injection` | Untrusted retrieved content causes goal drift and a proposed high-risk file tool request. | Trusted documentation keeps the authorized goal and proposes a public synthetic read. | Untrusted input precedes a high-risk tool request in the same trace. |
| `mcp-tool-poisoning` | An unsigned synthetic MCP definition expands from read to network-write before proposed invocation. | A signed definition matches the trusted read-only baseline. | Permission expansion plus an invalid signature precedes a tool request. |
| `decoy-secret-exfiltration` | A synthetic decoy-secret result is transformed and followed by blocked egress intent. | Public synthetic data is followed by an approved simulated health check. | A decoy-secret result precedes a blocked network request. |

The built-in detectors deliberately do not read `expected_detection`. That
field is a ground-truth label for external evaluation; the checks correlate the
observable security fields instead.

## Safety boundary

Scenario mode is simulation-only by construction:

- all resources use the `synthetic://` namespace;
- prompt bodies, reasoning, tool arguments, tool results, and payloads are not
  recorded;
- sensitive and network events explicitly include `executed: false`;
- the network examples contain loopback URLs only, and no socket is opened;
- fingerprints are fixed fixture identifiers, not hashes of local data; and
- the engine imports no agent SDK, MCP client, HTTP client, or subprocess API.

This boundary is different from endpoint behavior mode, which runs the
documented read-only command catalog unless `--dry-run` is selected.

## Ground-truth JSONL schema

`agent_sim_events.jsonl` contains one JSON object per checkpoint. Schema version
`1.0` uses these stable top-level fields:

| Field | Purpose |
| --- | --- |
| `schema_version` | Event schema version. |
| `timestamp` | UTC ISO 8601 time. |
| `event_id`, `parent_event_id` | Ordered event lineage within a trace. |
| `run_id`, `trace_id`, `sequence` | Suite, trace, and checkpoint correlation. |
| `producer`, `execution_mode` | Always `AgentSim` and `simulation_only`. |
| `scenario_id`, `scenario_name`, `scenario_variant`, `scenario_risk` | Scenario context and malicious/benign control identity. |
| `expected_detection` | Ground-truth label; true only for malicious traces. |
| `stage`, `event_type`, `message` | Workflow checkpoint and safe description. |
| `input_trust` | `trusted`, `untrusted`, or `not_applicable`. |
| `tool_name`, `tool_action`, `tool_risk` | Proposed tool context; values may be null. |
| `policy_decision`, `outcome` | Pending, allow, block, observe, proposed, simulated, or observed state. |
| `attributes` | Event-specific, non-secret correlation fields. |
| `mappings` | Descriptive MITRE ATLAS, OWASP Agentic, and NIST references. |

Example, formatted for readability:

```json
{
  "schema_version": "1.0",
  "execution_mode": "simulation_only",
  "scenario_id": "indirect-prompt-injection",
  "scenario_variant": "malicious",
  "expected_detection": true,
  "stage": "pre_tool",
  "event_type": "agent.tool.requested",
  "input_trust": "untrusted",
  "tool_name": "filesystem.read_file",
  "tool_risk": "high",
  "policy_decision": "pending",
  "attributes": {
    "arguments_redacted": true,
    "data_classification": "decoy_secret"
  }
}
```

Event types are namespaced around runtime checkpoints:
`agent.input.*`, `agent.goal.*`, `agent.tool.*`, `agent.network.*`, and
`agent.policy.*`. Preserve `run_id`, `trace_id`, `sequence`, trust,
classification, and policy fields when normalizing into a SIEM. Raw prompt and
tool content is neither required nor recommended for these correlations.

## Validation report

`agent_sim_validation.json` contains one result for each scenario/variant trace:

- `expected_detected` is true for a malicious trace and false for its benign
  twin;
- `detected` is the built-in correlation result;
- `passed` means the result matched that expectation; and
- `signal_event_ids` identifies the events used by the check.

Running `--variant both` is the recommended regression mode because it measures
both true-positive behavior and the matching benign control. A malicious-only
run cannot demonstrate false-positive rejection.

## SIEM and agent-runtime integration

For a product integration, ingest JSONL as a custom dataset and correlate on
`trace_id` in ascending `sequence` order. Start with three analytics:

1. untrusted input followed by goal drift or a high-risk tool request;
2. tool-definition hash, signature, or capability change followed by use; and
3. sensitive tool output followed by transform or network intent.

Treat policy blocks as high-value detections, not harmless noise: they show the
attack reached a control boundary. Also retain allowed outcomes so detections
can distinguish prevention from exposure. Before recording production agent
telemetry, review privacy and retention requirements; tool arguments and
results can contain sensitive data.

## Framework references

Scenario mappings are descriptive cross-references based on the current public
frameworks. They are not control attestations and may need revision as catalogs
change:

- [MITRE ATLAS](https://atlas.mitre.org/) for AI-system adversary tactics and
  agent-specific techniques;
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  for goal hijack, tool misuse, identity/privilege abuse, and agentic supply
  chain risks;
- [NIST AI 100-2 E2025](https://csrc.nist.gov/pubs/ai/100/2/e2025/final) for
  adversarial machine-learning terminology and attack taxonomy;
- [OpenTelemetry generative AI semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/)
  for interoperability guidance; and
- [Model Context Protocol security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
  for MCP authorization and tool-security considerations.

Review mappings and field normalization before using AgentSim evidence in an
audit, benchmark, or production detection claim.
