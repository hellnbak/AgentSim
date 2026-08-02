# Agent and MCP telemetry contract

AgentSim 1.3 defines a content-safe event contract for correlating agent,
model, tool, policy, and MCP activity without retaining prompts, reasoning,
messages, tool arguments/results, model responses, payloads, credentials, or
unsafe token values.

## Profiles

The offline collector and Python API accept three agent-oriented profiles:

| Profile | Intended input |
| --- | --- |
| `agent_runtime` | Native agent lifecycle/audit events. |
| `otel_genai` | OpenTelemetry GenAI spans or log records. |
| `mcp_audit` | MCP client/server authorization and tool audit events. |

```bash
agentsim telemetry inspect agent-spans.jsonl --collector otel_genai
agentsim telemetry inspect mcp-audit.jsonl --collector mcp_audit
agentsim telemetry doctor mcp-audit.jsonl --collector mcp_audit
```

Python callers can project a single record before normalizing it:

```python
from agentsim.api import normalize_agent_telemetry

event = normalize_agent_telemetry(record, collector="otel_genai")
```

The complete machine-readable shape is
[`schemas/agent-trace-event.schema.json`](schemas/agent-trace-event.schema.json).

## Correlation fields

| Field family | Examples | Detection use |
| --- | --- | --- |
| Trace context | `trace_id`, `session_id`, `conversation_id`, `turn_id` | Cross-turn and cross-session sequence boundaries. |
| Identity | `agent_id`, `agent_instance_id`, `principal_id` | Prevent unrelated agents or principals from being correlated. |
| Tool activity | `tool_call_id`, `tool_name`, `tool_risk` | Connect a request, authorization decision, and outcome. |
| Causality | `parent_event_id`, `caused_by_event_ids`, `delegation_id` | Reconstruct delegation and multi-agent graphs. |
| Data state | `data_lineage_id`, `memory_id`, `input_trust`, `taint_labels` | Track provenance and trust propagation. |
| Policy/approval | `policy_id`, `policy_version`, `policy_decision`, `approval_id`, `approval_fingerprint` | Detect stale policy, replay, or summary/action mismatch. |
| MCP authorization | `mcp_client_id`, `mcp_server_id`, `auth_audience`, `auth_resource`, `auth_scopes`, `auth_audience_valid`, `consent_valid` | Detect audience, resource, scope, and per-client-consent failures. |
| Result | `outcome`, `synthetic`, `content_recorded` | Separate proposed, blocked, simulated, and completed checkpoints. |

`event_type` begins with `agent.`, `gen_ai.`, or `mcp.`. Adapters map common
OpenTelemetry GenAI and MCP field names into the canonical columns and retain
bounded, non-content security attributes such as token counts, error type,
delegation depth, and remaining budget.

Adapters preserve `caused_by_event_ids` in addition to `parent_event_id`.
Normalization metadata records whether the source timestamp and record ID were
present and valid and which core identities had to be generated. These are
quality facts only; raw missing values are not retained.

## Privacy and security boundary

`content_recorded` is always `false`; attempts to construct an event with it
enabled fail validation. Attribute names containing content-bearing or secret
terms are recursively removed, nested structures are depth/size bounded, and
long scalar values are truncated. The normalized record inventories safe
field names so coverage can be evaluated without preserving their sensitive
values.

This is a defensive telemetry minimum, not a universal observability standard.
Deployments should map their runtime vocabulary, retention policy, and access
controls before production ingestion. OpenTelemetry GenAI semantic conventions
are evolving, so pin and test the field mapping used by each runtime release.

## Recommended event sequence

An instrumented tool lifecycle should emit distinct checkpoints:

```text
agent.tool.requested
  → agent.policy.decision
  → agent.tool.completed | agent.tool.blocked
```

MCP-mediated requests should also emit `mcp.authorization.checked` with client,
server, audience/resource, bounded scopes, audience validity, and per-client
consent. The v1.3 reference corpus emits malicious/benign authorization twins
so absence of those fields is no longer a detection-pack visibility gap.

Memory writes, retrieval, delegation, approval, configuration, and MCP
authorization should likewise emit the observable decision separately from the
requested action. Blocked events remain valuable: they prove hostile or unsafe
intent reached a control boundary without implying compromise.

Run [`telemetry doctor`](TELEMETRY_ASSURANCE.md) on every new runtime mapping.
A deterministic fallback keeps malformed exports parseable, but the assurance
report marks substituted timestamps and generated identities so they cannot be
mistaken for native correlation evidence.
