# AgentSim Detection Engineering Guide

These experimental detections target behavioral telemetry produced by
AgentSim. They are starting points, not production-ready controls. Field names,
process ancestry, event latency, and command-line visibility vary across data
sources.

MITRE ATT&CK® mappings describe the discovery behavior being simulated. A
mapping does not guarantee complete coverage of an ATT&CK technique.

AgentSim v1 campaign runs add lifecycle-v3 ground truth with ability,
campaign, authorization, provider, target, cleanup, and detection-outcome
fields. The v1 engine adds bounded offline collectors, normalized telemetry,
temporal/graph evaluation, source/field coverage, malicious/benign regression,
gap analysis, runbooks, and candidate renderers. Existing scenario and vendor
analytics below remain fully supported. See
[`DETECTION_ENGINE.md`](DETECTION_ENGINE.md) for the vendor-neutral rule format
and CLI workflow.

## Reusable v1.4 detection pack

The packaged `agentsim.agent-security-core` pack provides twelve answer-key-free
AST rules for agent/tool/MCP and multi-agent graph telemetry. It is intended for exploratory
validation before vendor-specific tuning:

```bash
agentsim telemetry doctor agent-events.jsonl --collector agent_runtime
agentsim telemetry investigate agent-events.jsonl --collector agent_runtime --fail-on never
agentsim detection sweep agent-events.jsonl --collector agent_runtime
```

Each rule declares required fields and acceptable sources. An unmatched rule
is reported as `not_detected` only when those requirements are present;
otherwise it is a `visibility_gap`. The pack neither reads
`scenario_variant`/`expected_detection` nor replaces the vendor examples and
malicious/benign scoring below. See
[`TELEMETRY_ASSURANCE.md`](TELEMETRY_ASSURANCE.md) for pack authoring and report
semantics and [`MULTI_AGENT_INVESTIGATION.md`](MULTI_AGENT_INVESTIGATION.md)
for graph evidence and invariant interpretation.

## Data requirements

Collect process-creation events with, where available:

- event time and host/device identifier;
- process name, full command line, and process ID; and
- parent process name, command line, and process ID.

AgentSim does not forward events. Confirm that your EDR, audit policy, Sysmon,
or equivalent sensor records child processes created by Python and the shell.

### Agent-runtime data

Scenario mode supplies a separate, vendor-neutral JSONL dataset for agent
workflow detections. Preserve these fields when mapping it into a SIEM:

- `timestamp`, `run_id`, `trace_id`, `sequence`, and `event_type`;
- `session_id`, `conversation_id`, `agent_id`, `agent_instance_id`, and
  `principal_id`;
- `parent_event_id`, `caused_by_event_ids`, `delegation_id`, `approval_id`,
  `data_lineage_id`, and `taint_labels`;
- `input_trust`, `tool_name`, `tool_risk`, and `policy_decision`;
- `scenario_variant` and `expected_detection` in a ground-truth-only table; and
- relevant `attributes`, especially permission expansion, signature validity,
  data classification, destination scope, and execution state.

Do not let production analytics query `expected_detection`; it is the answer
key. Use it only after evaluation to score the analytic. The built-in AgentSim
validators follow this rule. See [`SCENARIOS.md`](SCENARIOS.md) for the full
schema and privacy boundary.

## Endpoint platform coverage

| Platform | Native content | Expected schema |
| --- | --- | --- |
| Sigma-compatible tools | Cross-OS command hallucination rule | Sigma process-creation fields |
| Microsoft Defender XDR | Rapid cross-shell pivot hunt | `DeviceProcessEvents` |
| Splunk | High-velocity discovery burst | CIM-style Endpoint.Processes aliases |
| CrowdStrike Falcon LogScale / Next-Gen SIEM | High-velocity discovery burst | Falcon `ProcessRollup2` events |
| Graylog | High-velocity discovery burst filter | Graylog Information Model process fields |
| Panther | Thresholded Python detection | CrowdStrike Falcon Data Replicator process logs |

## Agent-event platform coverage

These examples target normalized AgentSim schema-v2 workflow events. They are
correlation starting points and require the documented ingestion mapping.

| Platform | Native content | File |
| --- | --- | --- |
| Microsoft Sentinel / Defender XDR | KQL trust-lineage join | [`detections/kql/agentic_attack_correlations.kql`](detections/kql/agentic_attack_correlations.kql) |
| Splunk | SPL eventstats correlation | [`detections/splunk/agentic_attack_correlations.spl`](detections/splunk/agentic_attack_correlations.spl) |
| CrowdStrike Falcon LogScale / Next-Gen SIEM | CQL grouped checkpoint correlation | [`detections/crowdstrike/agentic_attack_correlations.cql`](detections/crowdstrike/agentic_attack_correlations.cql) |
| Graylog | Candidate filter for Filter & Aggregation | [`detections/graylog/agentic_attack_correlations.query`](detections/graylog/agentic_attack_correlations.query) |
| Panther | Custom-log unique-value threshold rule | [`detections/panther/agentic_attack_lineage.py`](detections/panther/agentic_attack_lineage.py) and [metadata](detections/panther/agentic_attack_lineage.yml) |
| Elastic Security | EQL sequence | [`detections/elastic/agentic_attack_lineage.eql`](detections/elastic/agentic_attack_lineage.eql) |
| Sigma-compatible pipelines | High-risk action selector | [`detections/sigma/agentic_high_risk_action.yml`](detections/sigma/agentic_high_risk_action.yml) |

The common analytic looks for untrusted input, memory, or retrieval context
followed by a high-risk tool, network, or delegation action in the same trace
and, where available, the same data lineage. Configure event ordering using
`sequence`; grouped count alone is insufficient when ingestion can arrive out
of order. The Panther streaming example uses `unique()` and a threshold to
collect both checkpoint kinds, so its runbook explicitly requires ordering
verification. The Graylog file is only the search filter: configure grouping
and ordered-condition checks in a Filter & Aggregation event definition.

Use a dedicated test index/repository/stream. Replace the visible table,
index, repository, stream, and log-type placeholders before running any query.
Do not map `expected_detection` or `scenario_variant` into the searchable view
used by the analytic.

### Control-plane invariant detections

A second rule family covers direct, high-confidence runtime invariant failures:

| Platform | File |
| --- | --- |
| Microsoft KQL | [`detections/kql/agentic_control_plane_abuse.kql`](detections/kql/agentic_control_plane_abuse.kql) |
| Splunk | [`detections/splunk/agentic_control_plane_abuse.spl`](detections/splunk/agentic_control_plane_abuse.spl) |
| CrowdStrike Falcon LogScale / Next-Gen SIEM | [`detections/crowdstrike/agentic_control_plane_abuse.cql`](detections/crowdstrike/agentic_control_plane_abuse.cql) |
| Graylog | [`detections/graylog/agentic_control_plane_abuse.query`](detections/graylog/agentic_control_plane_abuse.query) |
| Panther | [`detections/panther/agentic_control_plane_abuse.py`](detections/panther/agentic_control_plane_abuse.py) and [metadata](detections/panther/agentic_control_plane_abuse.yml) |
| Elastic Security | [`detections/elastic/agentic_control_plane_abuse.eql`](detections/elastic/agentic_control_plane_abuse.eql) |
| Sigma-compatible pipelines | [`detections/sigma/agentic_control_plane_abuse.yml`](detections/sigma/agentic_control_plane_abuse.yml) |

These rules select invalid model-to-policy binding, planner/executor policy
version disagreement, action-fingerprint approval replay, tenant-principal
confusion, high-risk composed tool capability, and unsigned agent-registry
expansion. They use explicit boolean or enumerated security fields rather than
scenario IDs or message text. In production, generate these fields at the
authorization and orchestration boundaries; inferring them later from prompts
is less reliable.

Use the dashboard Detection Debugger during tuning. It shows the exact ordered
reference conditions and highlights `signal_event_ids` in the trace timeline.
That viewer is allowed to read the ground-truth label because it is a debugging
surface; the vendor queries above are tested to exclude answer-key fields.

These examples intentionally use each platform's native field names. Normalize
or remap your source fields before evaluating a rule; changing only the query
syntax is not enough to make detections portable.

## Included examples

### Cross-OS command hallucination (Sigma)

File: [`detections/sigma/llm_hallucination.yml`](detections/sigma/llm_hallucination.yml)

Detects a Windows command shell carrying common Unix discovery syntax, or a
POSIX shell carrying common Windows discovery syntax. This aligns with
AgentSim's hallucination-rate behavior.

Expected false positives include WSL, compatibility layers, shell tutorials,
build systems, and administrators intentionally testing cross-platform scripts.
Tune on parent process, user, host role, and known automation.

### Rapid cross-shell pivot (Microsoft Defender XDR KQL)

File: [`detections/kql/agent_pivot.kql`](detections/kql/agent_pivot.kql)

Finds a single initiating process that launches both CMD and PowerShell within
a ten-second window. This can identify the Windows retry/pivot behavior.

Software deployment, CI workers, configuration management, and administrative
wrappers commonly use both shells. Replace the example lookback and tune the
initiating-process filters for your environment.

### High-velocity discovery burst (Splunk SPL)

File: [`detections/splunk/velocity_recon.spl`](detections/splunk/velocity_recon.spl)

Counts distinct discovery command families launched by one parent process in a
five-second bucket. The example assumes CIM-style Endpoint.Processes fields and
contains an explicit index placeholder.

Tune the time bucket and distinct-command threshold for sensor batching and
normal automation. A five-second search bucket is not the same as an exact
sliding five-second window.

### High-velocity discovery burst (CrowdStrike Falcon LogScale CQL)

File: [`detections/crowdstrike/agent_discovery_burst.cql`](detections/crowdstrike/agent_discovery_burst.cql)

Filters Falcon `ProcessRollup2` events to discovery commands whose immediate
parent is a Python process, then finds four or more distinct commands in a
five-second bucket. It uses Falcon-native `aid`, `ComputerName`,
`ParentProcessId`, `ParentBaseFileName`, and `CommandLine` fields.

Run it first as an Advanced Event Search over a short time range. Tune known
Python automation, notebooks, software inventory, and diagnostic tooling. The
query uses fixed buckets rather than an exact sliding window, and CrowdStrike's
distinct count may be estimated at high cardinality. The syntax follows the
[official CQL query language](https://library.humio.com/data-analysis/syntax.html)
and [`ProcessRollup2` command-line examples](https://library.humio.com/examples/examples-regex-filter-commandline.html).

### High-velocity discovery burst (Graylog)

File: [`detections/graylog/agent_discovery_burst.query`](detections/graylog/agent_discovery_burst.query)

This Graylog search filter targets normalized process-start events with a
Python parent and an AgentSim discovery command. It expects the current Graylog
Information Model fields `gim_event_type`, `process_parent_name`, and
`process_command_line`; map vendor fields into those names before use.

For an alert, create a **Filter & Aggregation** event definition with this
query, group by the endpoint identifier and `process_parent_id`, use a short
window appropriate for ingestion latency, and begin with a raw message-count
threshold of six. Graylog can aggregate matches, but this portable query cannot
derive AgentSim's distinct command families by itself, so review the backlog
messages and tune the count for your source. See Graylog's
[process field schema](https://go2docs.graylog.org/illuminate-current/schema/field_schema_entities/process.html),
[search syntax](https://go2docs.graylog.org/current/making_sense_of_your_log_data/search_syntax_reference.htm),
and [event-definition workflow](https://go2docs.graylog.org/current/interacting_with_your_log_data/event_definitions.html).

### High-velocity discovery burst (Panther)

Files:

- [`detections/panther/agent_discovery_burst.py`](detections/panther/agent_discovery_burst.py)
- [`detections/panther/agent_discovery_burst.yml`](detections/panther/agent_discovery_burst.yml)

The Panther rule targets `Crowdstrike.CrowdstrikeProcessRollup2` logs. The
Python rule accepts individual discovery process events, groups them by Falcon
endpoint and parent process, and returns a normalized discovery family through
`unique()`. Its disabled-by-default YAML metadata alerts when four distinct
families occur in the five-minute deduplication period.

The five-minute threshold is intentionally broader than the LogScale and
Splunk hunts because Panther streaming rules evaluate one event at a time and
apply alert thresholds across a deduplication period. Shorten or lengthen that
period for your ingestion characteristics, run the included positive and
negative tests with Panther Analysis Tool, and enable the rule only after
tuning authorized Python automation. The files follow Panther's current
[Python detection format](https://docs.panther.com/detections/rules/python)
and [unique-value threshold behavior](https://docs.panther.com/detections/rules).

## Additional hunting ideas

### Agent trust-boundary correlations

For indirect prompt injection, memory poisoning, and RAG poisoning, join an
untrusted origin to a later high-risk action on `trace_id`, with increasing
`sequence` and matching `data_lineage_id` where available. Goal drift is a
useful intermediate signal but should not be required when the runtime cannot
expose it safely.

For MCP tool poisoning, baseline tool definition hashes, signatures, and
capability sets. Alert when an unsigned permission expansion is followed by use
of that same `tool_name`. Include version and server identity in a production
baseline even though AgentSim uses one synthetic server.

For decoy-secret access, correlate sensitive `agent.tool.result` classification
with a later transform or `agent.network.requested` checkpoint. Keep the policy
decision and execution state so a prevented attempt is distinguishable from an
allowed request.

Benign twins are essential tuning data. Trusted content, verified read-only
tools, and public results intentionally resemble the malicious workflow without
crossing the same trust boundary.

For multi-agent attacks, validate message signature/peer identity before
joining `delegation_id` across agents. Alert on taint propagation, scope
expansion, depth/fan-out growth, or policy decisions that differ between the
delegator and executor.

For approval deception, bind `approval_id` to an immutable action fingerprint
and compare the displayed summary to the proposed tool, scope, destination, and
risk. A generic “approval granted” event is not enough.

For MCP, detect wrong token audience, token passthrough, missing per-client
consent, session-principal changes, and access to internal destinations. Keep
authentication, authorization, and tool-call checkpoints distinct so a
confused deputy is not mistaken for a valid user action.

### Nested shell execution

Look for Python spawning a shell that immediately launches a second shell with
discovery syntax. Parent/child/grandchild correlation is more robust than a
single command-line match. AgentSim's `--evasion-rate` produces this pattern,
but the behavior is not proof of successful EDR evasion.

### Multi-cloud probing

When `--allow-network` is enabled, one Python parent may rapidly launch more
than one of `aws`, `az`, and `gcloud`. Correlate process events with cloud audit
logs and require two or more distinct CLI families to reduce noise.

### Context-loss bursts

Repeated `whoami` executions followed by several different discovery commands
from the same Python parent can indicate AgentSim's context-loss behavior. This
pattern is also common in health checks and scripted diagnostics, so baseline
the parent executable and service account.

## Validation workflow

### Endpoint behavior rules

1. Run `python core.py --dry-run --seed 42` to review the planned commands.
2. Use an authorized test endpoint with the required process telemetry enabled.
3. Run a short local simulation without `--allow-network`.
4. Confirm raw events contain the required ancestry and command-line fields.
5. Run the query, record misses, then tune field mappings and thresholds.
6. Test known administrative automation before enabling any alert.

Do not use `--allow-network` solely to test local process detections; dry-run
shows cloud selections, and local cloud CLI process creation should be performed
only with explicit authorization.

### Agentic scenario rules

1. Run `python core.py --scenario all --variant both --mutations 3 --mutation-seed 42 --speed 0`.
2. Ingest `agent_sim_events.jsonl` into a test-only dataset.
3. Run the analytic without exposing `expected_detection` to its query.
4. Join alert results to the ground-truth label by `trace_id`.
5. Require each malicious trace to alert and each benign twin to remain quiet.
6. Compare with `agent_sim_validation.json`, import `agent_sim_junit.xml` in CI,
   and retain `agent_sim_evidence.zip` with the detection change.

The built-in report validates the reference correlations, not a vendor query.
Your SIEM result must be scored separately after ingestion.

## ATT&CK references

The current command catalog uses ATT&CK Enterprise v19.1 mappings. Relevant
official technique pages include:

- [System Information Discovery (T1082)](https://attack.mitre.org/techniques/T1082/)
- [System Owner/User Discovery (T1033)](https://attack.mitre.org/techniques/T1033/)
- [Local Account Discovery (T1087.001)](https://attack.mitre.org/techniques/T1087/001/)
- [Process Discovery (T1057)](https://attack.mitre.org/techniques/T1057/)
- [Local Groups Discovery (T1069.001)](https://attack.mitre.org/techniques/T1069/001/)
- [System Network Connections Discovery (T1049)](https://attack.mitre.org/techniques/T1049/)
- [System Network Configuration Discovery (T1016)](https://attack.mitre.org/techniques/T1016/)
- [Cloud Service Discovery (T1526)](https://attack.mitre.org/techniques/T1526/)
