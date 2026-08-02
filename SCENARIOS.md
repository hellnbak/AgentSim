# Agentic Scenario Lab

AgentSim produces safe, labeled traces for validating detections at AI-agent
trust boundaries. It records what an agent observed, proposed, delegated, and
was allowed or blocked from doing. It never invokes an AI model or tool.

In v1, scenario packs remain a separate non-executing content contract.
Gated endpoint or lab behavior belongs in ability packs and directed campaign
packs documented in [`ABILITIES.md`](ABILITIES.md) and
[`CAMPAIGNS.md`](CAMPAIGNS.md). A scenario pack cannot opt into lifecycle-v3
execution.

## Quick start

```bash
python core.py --list-scenarios
python core.py --scenario all --variant both --mutations 3 --mutation-seed 42 --speed 0
python core.py --mcp-lab
```

The benchmark exits 0 when every trace has the expected detector result, 1 on a
mismatch, and 130 when interrupted. Interrupted runs still export completed
checkpoints and a report marked `stopped: true`.

## Included scenarios

Every malicious workflow has a closely matched benign twin. Reference
detectors inspect observable event fields and never query `scenario_variant`,
`expected_detection`, or another answer-key field.

| ID | Detection objective |
| --- | --- |
| `indirect-prompt-injection` | Untrusted input followed by a high-risk tool request. |
| `memory-context-poisoning` | Untrusted content persisted in one session and acted on in another. |
| `rag-integrity-poisoning` | Retrieval integrity failure followed by goal drift and risky action. |
| `mcp-tool-poisoning` | Unsigned MCP permission expansion followed by proposed use. |
| `mcp-identity-abuse` | Wrong token audience and session-principal mismatch preceding a risky MCP action. |
| `mcp-confused-deputy-ssrf` | Missing per-client consent followed by synthetic internal-resource access intent. |
| `inter-agent-spoofing` | Unsigned peer message followed by over-scoped delegation. |
| `cascading-agent-failure` | Tainted result propagated through multiple delegated agents. |
| `human-approval-deception` | Approval summary does not match the high-risk proposed action. |
| `rogue-policy-evasion` | Denied intent retried through another tool plus monitoring-disable intent. |
| `unexpected-code-execution` | Untrusted content followed by interpreter/tool execution intent. |
| `resource-cost-abuse` | Tool budget exceeded followed by deep, high-fan-out delegation. |
| `decoy-secret-exfiltration` | Decoy-secret lineage followed by transformed, blocked loopback egress intent. |
| `model-fallback-downgrade` | Fallback model changes the safety profile without a valid policy binding. |
| `planner-executor-policy-gap` | A stale executor policy allows equivalent intent blocked by the planner. |
| `approval-replay` | An expired approval is reused for a different high-risk action fingerprint. |
| `cross-tenant-context-confusion` | Principal and resource tenants diverge after an invalid context switch. |
| `tool-chain-capability-escalation` | Modest tools compose into a high-risk restricted-data egress capability. |
| `agent-registry-poisoning` | Unsigned registry capability expansion precedes a risky agent delegation. |

The catalog is declarative JSON under `agentsim_scenarios/packs/`; adding a
scenario does not require editing the engine.

## Safety boundary

Scenario mode is simulation-only by construction:

- action checkpoints must include `attributes.executed: false`;
- resources must use `synthetic://` or an explicit loopback URL;
- prompt bodies, reasoning, arguments, results, tokens, and payloads are not
  recorded;
- fixed fingerprints identify fixtures and are not hashes of local data;
- pack loading rejects label-dependent detectors and detectors that fire on
  their own benign control; and
- the engine imports no agent SDK, HTTP client, or subprocess API.

The MCP lab in `mcp_lab.py` serializes protocol-shaped JSON-RPC in memory. It
tests token audience, passthrough rejection, client consent, session binding,
scopes, and tool allowlisting without starting a server, opening a socket,
loading a plugin, or executing a tool.

This boundary differs from endpoint behavior mode, which runs the documented
read-only command catalog unless `--dry-run` is selected.

## v1 disposable control fixtures

`agentsim lab run all` adds ten smaller in-memory controls alongside the
declarative benchmark: indirect prompt injection, memory poisoning, RAG
poisoning, MCP permission expansion, MCP identity/audience failure, confused
deputy, delegation spoofing, approval deception, decoy-secret access, and
budget/recursion abuse. Each fixture exercises a malicious request and benign
twin against a deterministic synthetic policy. No fixture opens a socket,
starts a process, loads a plugin, executes a tool, or uses a credential.

## Event schema v2

`agent_sim_events.jsonl` contains one JSON object per checkpoint. The complete
machine-readable contract is [`schemas/agent-event.schema.json`](schemas/agent-event.schema.json).
The loader remains compatible with v1 JSONL.

Important correlation fields include:

| Fields | Purpose |
| --- | --- |
| `run_id`, `trace_id`, `sequence`, `event_id` | Suite, trace, order, and checkpoint identity. |
| `parent_event_id`, `caused_by_event_ids` | Sequential and explicit causal graph edges. |
| `session_id`, `conversation_id` | Cross-session and conversational boundaries. |
| `agent_id`, `agent_instance_id`, `principal_id` | Logical agent, runtime instance, and authenticated principal. |
| `delegation_id`, `approval_id` | Delegation and human-approval correlation. |
| `data_lineage_id`, `taint_labels` | Data provenance and trust propagation. |
| `policy_id`, `policy_version`, `policy_decision` | Versioned control result. |
| `event_type`, `stage`, `outcome` | Runtime checkpoint and disposition. |
| `input_trust`, `tool_name`, `tool_risk` | Trust and proposed tool context. |
| `scenario_variant`, `expected_detection` | Ground-truth answer key; evaluation datasets only. |
| `attributes` | Event-specific, non-secret security facts. |

Event types cover input, goal, memory, retrieval, tools, networks, delegation,
approvals, authorization, budgets, configuration, policy, and observation.
Production detections should ingest security facts but must not query the
answer-key fields.

## Mutations and scorecard

`--mutations N` adds `N` semantic-preserving variants to every selected
malicious and benign trace. Mutations can alias synthetic tool names, vary safe
descriptions, add delay metadata, and insert benign noise. `--mutation-seed`
makes the generated corpus reproducible. The scorecard reports:

- true/false positives and negatives;
- precision, recall, accuracy, and benign rejection rate;
- mean and maximum checkpoints to detection;
- baseline and mutation pass/fail counts;
- per-scenario results; and
- detector field and framework coverage.

Use `--variant both` for regression testing. A malicious-only run cannot
measure false-positive rejection.

## Benchmark artifacts

Scenario CLI runs create these files by default:

| Artifact | Use |
| --- | --- |
| `agent_sim_events.jsonl` | Canonical labeled ground-truth events. |
| `agent_sim_validation.json` | Detailed results and scorecard. |
| `agent_sim_junit.xml` | CI test reporting. |
| `agent_sim_results.sarif` | Code-scanning-compatible mismatch reporting. |
| `agent_sim_otel.jsonl` | OpenTelemetry-compatible log records for collector testing. |
| `agent_sim_coverage.json` | Framework mappings, event types, agents, risks, and detector fields. |
| `agent_sim_evidence.zip` | Portable bundle containing all artifacts above. |

The OpenTelemetry export contains fixed synthetic descriptions, never raw
prompts, tool arguments, or results. Review privacy and retention before
adapting the pattern to production telemetry.

## Human detection debugger

After a dashboard scenario run, the **Detection debugger** reads only the local
ground-truth and validation artifacts for that run. It provides:

- pass/mismatch and malicious/benign/mutation filters;
- expected versus observed alert behavior;
- the ordered detector conditions as evaluated;
- the trace sequence where detection completed; and
- a timeline with contributing `signal_event_ids` highlighted.

The viewer is an evaluation surface and intentionally has access to ground
truth. Production analytics must still run without `expected_detection` or
`scenario_variant`. The local API endpoints `/api/detection-debug` and
`/api/detection-debug/trace` return 404 until a scenario artifact set exists.

## Custom scenario packs

Pass a JSON file or directory with repeatable `--scenario-pack PATH`. Built-in
packs remain enabled. The machine-readable pack contract is
[`schemas/scenario-pack.schema.json`](schemas/scenario-pack.schema.json).

Minimal structure:

```json
{
  "pack_schema_version": "1.0",
  "pack_id": "example.agent-security",
  "scenarios": [
    {
      "scenario_id": "example-risk",
      "name": "Example risk",
      "description": "Synthetic trust-boundary example.",
      "risk": "high",
      "mappings": {
        "owasp_agentic": ["ASI02 Tool Misuse"],
        "mitre_atlas": ["AI Agent Tool Invocation"]
      },
      "detector": {
        "type": "ordered_sequence",
        "conditions": [
          {"event_type": "agent.input.observed", "equals": {"input_trust": "untrusted"}},
          {"event_type": "agent.tool.requested", "equals": {"tool_risk": "high"}}
        ]
      },
      "malicious_steps": [],
      "benign_steps": []
    }
  ]
}
```

Populate both step arrays; the abbreviated empty arrays above only illustrate
the document shape. Conditions support `equals`, `not_equals`, `contains`,
`gte`, and `exists` against dotted field paths. All conditions must occur in
order within one trace. Pack IDs and scenario IDs must be unique across loaded
packs.

Validate a pack by listing it, then run its controls:

```bash
python core.py --scenario-pack ./my-pack.json --list-scenarios
python core.py --scenario-pack ./my-pack.json --scenario example-risk --variant both --speed 0
```

## SIEM and runtime integration

Ingest JSONL into a test-only dataset, preserve `trace_id`, `sequence`, lineage,
agent, session, and policy fields, and keep the answer key in a separate table.
Join SIEM alerts to ground truth by `trace_id` only after the analytic runs.
Vendor examples for CrowdStrike, Graylog, Microsoft KQL, Splunk, Panther,
Elastic EQL, and Sigma are documented in [`DETECTIONS.md`](DETECTIONS.md).

Treat blocked requests as high-value observations: they show an attack reached
a control boundary. Keep allowed/simulated outcomes too, so prevention can be
distinguished from possible exposure.

## Framework references

Mappings are descriptive cross-references, not certifications or complete
coverage claims:

- [MITRE ATLAS](https://atlas.mitre.org/);
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/);
- [NIST AI 100-2 E2025](https://csrc.nist.gov/pubs/ai/100/2/e2025/final);
- [OpenTelemetry generative AI semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/); and
- [Model Context Protocol security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices).

Review mapping names and field normalization before using AgentSim evidence in
an audit, benchmark, or production detection claim.
