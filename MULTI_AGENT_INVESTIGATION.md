# Multi-agent investigation

AgentSim 1.5 reconstructs content-safe causal graphs from normalized agent
telemetry. The investigation report is intended to answer four operator
questions:

1. Which agent, principal, goal, and memory records participated?
2. How did evidence move through delegation and causal links?
3. Which identity, goal, memory, or retention invariant failed?
4. What evidence and remediation should a human review next?

The feature does not inspect prompts, messages, tool arguments, tool results,
tokens, or payloads. It uses record identifiers and bounded security metadata.

## Command line

```bash
agentsim telemetry investigate agent-events.jsonl \
  --collector agent_runtime \
  --output investigation.json \
  --fail-on elevated
```

`--fail-on` accepts `never`, `review`, `elevated`, or `critical`. The default
fails only when the report status is `critical`. At most 5,000 normalized
events are accepted in one investigation.

## Report model

The report contains:

- nodes for content-safe event checkpoints;
- `parent`, `caused_by`, `delegation`, `data_lineage`, and `memory_lineage`
  edges;
- per-trace agent, delegation, finding, and maximum-depth summaries;
- invariant findings with evidence and remediation;
- bounded root-to-finding paths for high and critical findings; and
- a 0–100 triage score plus `clean`, `review`, `elevated`, or `critical`
  status.

The score helps prioritize a supplied corpus. It is not a compliance result or
claim that every runtime event was collected.

The JSON schema is
[`schemas/multi-agent-investigation-report.schema.json`](schemas/multi-agent-investigation-report.schema.json).

## Invariants

| Invariant | Finding examples |
| --- | --- |
| Delegation identity | Cross-agent causal edge without a delegation ID; failed receiver binding; changing sender or receiver under one delegation ID. |
| Principal continuity | More than one principal appears in a delegation without an explicitly approved principal transition. |
| Goal integrity | A goal-integrity checkpoint fails or its fingerprint changes without approval. |
| Memory provenance | A memory read or write reports invalid provenance. |
| Memory retention | A memory operation violates retention/scope policy or a shared write lacks a lineage ID. |

Agent trace contract 1.1 adds optional canonical fields for delegation
endpoints, identity binding, goal identity/fingerprint/integrity, and memory
scope/provenance/retention. Adapters also accept their documented dotted alias
forms.

## Graph-aware detection primitives

The detection AST adds two declarative, non-executable expressions:

- `graph_path` matches ordered expressions connected through configured causal
  fields within a bounded depth;
- `graph_fanout` requires one root to reach a configured count of distinct
  descendant entities.

Both default to `parent_event_id` and `caused_by_event_ids`, enforce a maximum
depth of 50, and remain scoped by the rule's `group_by` fields. The built-in
pack uses them to detect a goal → shared-memory → high-risk-tool path and
invalid memory provenance fanning out across agent identities.

## Web workbench

Run `agentsim-web`, open `http://127.0.0.1:5000`, and select **Build
investigation**. The workbench provides:

- trace selection labeled by fixture, variant, agent count, and finding count;
- trace-specific graph metrics;
- severity filtering;
- indented causal checkpoints with agent identity, edge types, outcomes, and
  risk flags;
- click-to-highlight finding evidence; and
- operator remediation plus a reconstructed causal path.

The bundled view uses the mixed malicious/benign reference corpus. A critical
overall status is expected when the malicious trace is present; select the
benign twin to verify the invariant-clean control.

## Python API

```python
from agentsim.api import collect_telemetry, telemetry_investigation

events = collect_telemetry("agent-events.jsonl", collector="agent_runtime")
report = telemetry_investigation(events)
```

The returned object is JSON-serializable and follows the public report schema.

## Design references

- [OWASP Multi-Agentic System Threat Modeling Guide](https://genai.owasp.org/resource/multi-agentic-system-threat-modeling-guide-v1-0/)
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OpenTelemetry semantic conventions for events](https://opentelemetry.io/docs/specs/semconv/general/events/)
- [MITRE ATLAS](https://atlas.mitre.org/)

Mappings are descriptive aids. They do not imply certification or complete
coverage of a framework.
