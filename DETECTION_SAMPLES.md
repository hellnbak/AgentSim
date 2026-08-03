# Detection and alert sample library

AgentSim includes a deterministic sample library for testing parsers, field
mappings, alert pipelines, detection-as-code workflows, and analyst runbooks.
The library is deliberately synthetic and content-safe. It never deploys a
rule, contacts a SIEM, or records prompts, messages, arguments, results,
responses, credentials, secrets, tokens, or payload values.

## Coverage

Six representative agent-security detection families are included:

| Sample | Severity | Scenario twin |
| --- | --- | --- |
| Untrusted input reached a high-risk tool | High | `indirect-prompt-injection` |
| Authorization audience validation failed | Critical | `mcp-identity-abuse` |
| Memory provenance validation failed | High | `memory-context-poisoning` |
| Goal integrity validation failed | Critical | `cross-agent-goal-fingerprint-drift` |
| Delegation identity binding failed | Critical | `delegation-identity-drift` |
| High-risk tool received an allow decision | High | `planner-executor-policy-gap` |

Each family produces a detection example for:

- AgentSim's generic declarative AST;
- Sigma;
- Microsoft Sentinel KQL;
- Splunk SPL;
- CrowdStrike Falcon LogScale / Next-Gen SIEM CQL;
- Elastic EQL;
- Panther Python with disabled YAML metadata; and
- Graylog search/event-definition syntax.

The library therefore contains 48 rule/format combinations and 54 files
because each Panther sample has separate Python and YAML files. It also
contains six alert records for each live connector—Splunk, Elastic,
CrowdStrike, Microsoft Sentinel, Panther, and Graylog—plus six generic alerts,
for 42 alert records total.

The syntax choices follow the vendors' current public documentation for
[Splunk `stats` and search pipelines](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.2/search-commands/stats),
[Elastic EQL](https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html),
[Microsoft Sentinel KQL](https://learn.microsoft.com/en-us/kusto/query/tutorials/common-tasks-microsoft-sentinel?view=microsoft-sentinel),
[CrowdStrike LogScale query grammar](https://library.humio.com/lql-grammar.pdf),
[Panther Python detections](https://docs.panther.com/detections/rules/python),
and the [Graylog search/event workflow](https://go2docs.graylog.org/current/interacting_with_your_log_data/event_definitions.html).
Every native sample still requires environment-specific field mapping, index
or table selection, tuning, a malicious/benign replay, and human review.

## Export and inspect

Inspect the catalog without writing files:

```bash
agentsim detection samples
```

Export the complete library:

```bash
agentsim detection sample-export detection-samples
```

Export only selected formats and alert profiles:

```bash
agentsim detection sample-export detection-samples \
  --format sigma --format splunk \
  --alert-profile generic --alert-profile splunk
```

The destination must be absent or empty. AgentSim will not overwrite an
existing sample directory. A full export contains:

```text
detection-samples/
├── detections/
│   ├── generic/
│   ├── sigma/
│   ├── kql/
│   ├── splunk/
│   ├── crowdstrike/
│   ├── elastic/
│   ├── panther/
│   └── graylog/
├── alerts/
│   ├── generic.jsonl
│   ├── splunk.jsonl
│   ├── elastic.jsonl
│   ├── crowdstrike.jsonl
│   ├── sentinel.jsonl
│   ├── panther.jsonl
│   └── graylog.jsonl
├── telemetry/
│   ├── malicious.jsonl
│   └── benign.jsonl
├── README.md
└── manifest.json
```

The checked-in [`examples/detection-samples`](examples/detection-samples/)
directory is generated from the packaged catalog. `manifest.json` inventories
every file with its byte size and SHA-256 so examples can be compared across
releases.

## Validate a sample

The generic detection files use AgentSim's non-executing AST and can be run
against the supplied telemetry:

```bash
agentsim detection evaluate \
  detection-samples/detections/generic/goal-integrity-failure.json \
  detection-samples/telemetry/malicious.jsonl \
  --collector agent_runtime
```

Repeat the evaluation with `telemetry/benign.jsonl`; the corresponding rule
must not match. Unit tests enforce this positive/negative behavior for all six
families.

Generic alert rows conform to AgentSim's strict `DetectionAlert` contract and
can be placed into a `detection-feedback` bundle. Vendor rows are illustrative,
collector-normalizable JSONL rather than claims about a universal vendor
export schema. They retain vendor-recognizable timestamp, source, alert/rule,
severity, status, trace, agent, scenario, and source-event fields. Adapt the
envelope to the exact product version and source integration in use.

## Python API

```python
from agentsim.api import (
    detection_alert_samples,
    detection_samples,
    export_detection_samples,
)

catalog = detection_samples()
sentinel_alerts = detection_alert_samples("sentinel")
export_detection_samples("detection-samples", formats=("sigma", "kql"))
```

Lower-level helpers in `agentsim.detection` expose the parsed definitions,
generic pack, malicious/benign telemetry, renderers, and alert generators.

## Safety and deployment boundary

- Every alert and telemetry record is synthetic and trace-linked.
- Detection logic never reads scenario labels or expected-detection fields.
- Exported native detections are disabled or visibly marked tuning/review
  required where the format supports metadata.
- Samples contain placeholders rather than production indexes, repositories,
  streams, tables, or destinations.
- No API in the library creates, updates, enables, suppresses, or deletes a
  vendor rule or alert.
- Alert samples must not be mistaken for real incidents or sent to production
  response automation without a separate, explicit test boundary.

Machine-readable contracts are provided in:

- `schemas/detection-sample-catalog.schema.json`
- `schemas/detection-alert-sample.schema.json`
- `schemas/detection-sample-export.schema.json`
