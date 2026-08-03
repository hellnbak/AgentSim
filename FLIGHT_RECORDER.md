# Agent security flight recorder and Detection CI

AgentSim 1.6 records the defensive structure of an agent run without retaining
prompts, messages, reasoning, tool arguments, tool results, model responses,
credentials, secrets, or payload values. A recording can be inspected,
converted into a pseudonymous synthetic twin, and compared with a candidate
recording as a detection merge gate.

The public contracts are:

- [`schemas/flight-recorder-bundle.schema.json`](schemas/flight-recorder-bundle.schema.json)
- [`schemas/detection-ci-report.schema.json`](schemas/detection-ci-report.schema.json)
- [`schemas/agent-trace-event.schema.json`](schemas/agent-trace-event.schema.json)

## Record an exported flight

Agent-runtime or OpenTelemetry GenAI JSON/JSONL:

```bash
agentsim telemetry record agent-events.jsonl \
  --format agent_runtime \
  --runtime my-agent-runtime \
  --classification malicious \
  --output baseline-flight.json \
  --twin-output baseline-twin.jsonl

agentsim telemetry record otel-spans.jsonl \
  --format otel_genai \
  --runtime my-otel-runtime \
  --classification unknown \
  --output candidate-flight.json
```

An OTLP/HTTP JSON trace-export object can be projected directly:

```bash
agentsim telemetry record otlp-export.json \
  --format otlp \
  --runtime otel-collector \
  --classification malicious \
  --output baseline-flight.json
```

OTLP protobuf is not accepted by the public receiver. Convert it to OTLP JSON
in a trusted collector or use an agent-runtime JSON export.

## OpenAI Agents SDK processor

The SDK integration is optional and duck typed, so AgentSim does not require
the SDK at installation time:

```python
from agentsim.telemetry import (
    AgentSimTraceProcessor,
    FlightRecorder,
    attach_to_openai_agents,
)

recorder = FlightRecorder(
    source_runtime="openai-agents",
    classification="unknown",
)
processor = AgentSimTraceProcessor(
    recorder,
    output_path="agent-flight.json",
)
attach_to_openai_agents(processor)
```

The processor implements trace and span lifecycle callbacks, returns quickly,
and catches recording failures so observability cannot break the agent loop.
It reads selected structural properties and intentionally never calls a span's
general export method because an SDK export may include function input/output
or model content. See the current
[OpenAI Agents SDK tracing documentation](https://openai.github.io/openai-agents-python/ref/tracing/).

## Loopback OTLP/HTTP JSON receiver

The receiver is disabled until loopback access is explicitly allowed:

```bash
agentsim telemetry serve-otlp \
  --host 127.0.0.1 \
  --port 4318 \
  --runtime local-otel \
  --classification unknown \
  --output agent-flight.json \
  --allow-loopback
```

It accepts JSON only at `POST /v1/traces`, exposes `GET /health` and
`GET /snapshot`, rejects non-loopback binding, caps request size and span
count, and never opens an outbound connection.

## Synthetic twins

A twin preserves event types, topology, ordering, policy facts, field
availability, and safe numerical metadata. Trace, session, conversation,
agent, principal, event, tool-call, delegation, memory, goal, and lineage IDs
are deterministically pseudonymized within the recording. Every twin event is
marked:

```json
{
  "synthetic": true,
  "content_recorded": false,
  "attributes": {
    "synthetic_twin": true,
    "executed": false
  }
}
```

Twins do not replay tools, model calls, network requests, or state changes.

## Detection CI

Compare a reviewed baseline flight with telemetry produced by an agent change:

```bash
agentsim detection ci baseline-flight.json candidate-flight.json \
  --classification malicious \
  --output detection-ci.json \
  --markdown-output detection-ci.md \
  --junit-output detection-ci.xml \
  --sarif-output detection-ci.sarif \
  --fail-on block
```

The gate runs telemetry assurance, multi-agent invariant analysis, and every
answer-key-free rule in the selected detection pack over both recordings. It
classifies per-rule transitions and reports:

- a lost malicious detection;
- a new benign detection;
- a new visibility gap;
- an assurance-score regression;
- a more severe agent-invariant state; or
- excessive loss of lifecycle checkpoints.

`malicious` and `benign` are explicit expected classifications, not inferred
from detector output. Use `unknown` to turn changed detection behavior into a
human-review result instead of guessing ground truth.

Default CLI exit behavior fails only on `block`. Use `--fail-on review` to make
review findings fail CI or `--fail-on never` for advisory reporting.

## Web workspace

Run `agentsim-web` and open `http://127.0.0.1:5000`. The Flight Recorder card
can load a fixed safe demo or a local strict bundle, render a bounded structural
timeline, show assurance and investigation metrics, and download its synthetic
twin. The Detection CI pane accepts baseline and candidate bundles and exports
JSON, Markdown, and SARIF. Uploaded files are validated in memory and are not
written to server storage.

## Security invariants

- `content_values_recorded` and `content_recorded` must remain `false`.
- Every imported bundle must pass strict-field, counter, size, timestamp, and
  SHA-256 digest validation.
- Attribute keys associated with content or secrets are recursively removed.
- SDK callbacks must not raise into an application runtime.
- Receiver binding remains loopback-only and requires explicit opt-in.
- Detection CI is offline and cannot deploy or modify a vendor rule.
- Synthetic twins cannot execute any recorded behavior.

Treat any bypass of these invariants as a security issue.
