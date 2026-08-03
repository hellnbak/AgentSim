# Agent and MCP telemetry contract

AgentSim 1.7 uses agent trace contract 1.1 for correlating agent,
model, tool, policy, and MCP activity without retaining prompts, reasoning,
messages, tool arguments/results, model responses, payloads, credentials, or
unsafe token values.

## Profiles

The offline collector and Python API accept three agent-oriented source
profiles plus two portable security-schema collectors:

| Profile | Intended input |
| --- | --- |
| `agent_runtime` | Native agent lifecycle/audit events. |
| `otel_genai` | OpenTelemetry GenAI spans or log records. |
| `mcp_audit` | MCP client/server authorization and tool audit events. |
| `ecs` | Elastic Common Schema JSON/JSONL, including AgentSim portable mappings. |
| `ocsf` | OCSF JSON/JSONL, including API Activity with trace and AI-operation fields. |

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

For live runtime flights, strict bundles, OTLP/HTTP JSON, OpenAI Agents SDK
processor integration, pseudonymous twins, and baseline/candidate gates, see
[`FLIGHT_RECORDER.md`](FLIGHT_RECORDER.md).

## Portable mappings

The canonical contract can be exported to pinned OpenTelemetry Semantic
Conventions 1.43.0, ECS 9.4.0, or OCSF 1.8.0. AgentSim distinguishes native
standard fields from project-specific security extensions:

| Profile | Native examples | Extension namespace |
| --- | --- | --- |
| `otel` | trace/span IDs, GenAI operation, agent, conversation, tool, model, and data-source IDs | `attributes.agentsim` |
| `ecs` | `@timestamp`, `event.id`, `event.action`, `event.dataset`, `trace.id`, `session.id`, `user.id` | `agentsim` |
| `ocsf` | API Activity, actor, trace/span, message context, AI model, source, and status | `unmapped.agentsim` |

Policy, approval, delegation, goal, memory, and MCP authorization facts remain
explicit extensions when a standard has no equivalent. Content values are
never exported. Each result inventories native and extension fields and
reports native coverage.

```bash
agentsim telemetry mappings
agentsim telemetry map agent-events.jsonl \
  --from-profile canonical --to-profile otel \
  --output otel-events.json
agentsim lab conformance multi-agent-delegation-cascade --fail-on-error
```

Conformance restores each mapped event and compares the canonical security
invariants and safe attributes. A passing AgentSim round trip does not claim
general certification for the target standard. Mapping details, version
references, review boundaries, APIs, and schemas are in
[`PORTABILITY_AND_TRUST.md`](PORTABILITY_AND_TRUST.md).

The complete machine-readable shape is
[`schemas/agent-trace-event.schema.json`](schemas/agent-trace-event.schema.json).

## Correlation fields

| Field family | Examples | Detection use |
| --- | --- | --- |
| Trace context | `trace_id`, `session_id`, `conversation_id`, `turn_id` | Cross-turn and cross-session sequence boundaries. |
| Identity | `agent_id`, `agent_instance_id`, `principal_id` | Prevent unrelated agents or principals from being correlated. |
| Tool activity | `tool_call_id`, `tool_name`, `tool_risk` | Connect a request, authorization decision, and outcome. |
| Causality | `parent_event_id`, `caused_by_event_ids`, `delegation_id` | Reconstruct delegation and multi-agent graphs. |
| Delegation identity | `delegated_from_agent_id`, `delegated_to_agent_id`, `identity_binding_valid` | Verify sender/receiver continuity at cross-agent boundaries. |
| Goal integrity | `goal_id`, `goal_fingerprint`, `goal_integrity_valid`, `goal_change_approved` | Detect unapproved goal changes across turns and agents. |
| Data state | `data_lineage_id`, `memory_id`, `memory_scope`, `memory_provenance_valid`, `memory_retention_valid`, `input_trust`, `taint_labels` | Track provenance, retention, and trust propagation. |
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
consent. The v1.4 reference corpus emits malicious/benign authorization twins
so absence of those fields is no longer a detection-pack visibility gap.

Multi-agent runtimes should preserve a chain such as:

```text
agent.goal.integrity
  → agent.delegation.requested
  → agent.delegation.accepted
  → agent.memory.written | agent.memory.read
  → agent.tool.requested
  → agent.policy.decision
```

Every cross-agent edge should carry a delegation ID, bound sender/receiver,
originating principal, goal identity/fingerprint, and applicable memory
lineage. The v1.4 reference fixture emits a three-agent malicious/benign twin
for this sequence.

Detection and remediation agents should preserve feedback as separate
checkpoints:

```text
agent.detection.alerted
  → agent.feedback.submitted
  → agent.alert.reconciled
  → agent.detection.tuned
  → agent.monitoring.coverage
  → agent.policy.decision
```

Record only stable alert/evidence identifiers, enumerated author/disposition
facts, identity and evidence-digest validity, tuning scope, and coverage
metrics. Do not place analyst narrative, alert payloads, prompts, arguments, or
results in these attributes. The v1.5 feedback fixture emits malicious/benign
twins for this sequence.

Memory writes, retrieval, delegation, approval, configuration, and MCP
authorization should likewise emit the observable decision separately from the
requested action. Blocked events remain valuable: they prove hostile or unsafe
intent reached a control boundary without implying compromise.

Run [`telemetry doctor`](TELEMETRY_ASSURANCE.md) on every new runtime mapping,
then use [`telemetry investigate`](MULTI_AGENT_INVESTIGATION.md) when agent,
delegation, goal, or memory fields are present.
Run [`defense reconcile`](DETECTION_FEEDBACK.md) before using alert feedback for
tuning, then compare the candidate with a reviewed malicious/benign baseline.
A deterministic fallback keeps malformed exports parseable, but the assurance
report marks substituted timestamps and generated identities so they cannot be
mistaken for native correlation evidence.
