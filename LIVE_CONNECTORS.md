# Live read-only telemetry connectors

AgentSim 1.2 can validate candidate detections against a narrowly scoped live
telemetry query. This is not a SIEM administration surface: connectors cannot
create, update, deploy, or delete detections, dashboards, indexes, users, or
policies.

## Safety model

Building a query is offline. Sending it requires both `--execute` and
`--allow-network`. Every request requires:

- an exact vendor dataset/index/repository/table/stream and exact target;
- an ISO-8601 interval no longer than 24 hours;
- a result limit from 1 to 10,000;
- HTTPS, except explicit `127.0.0.1`, `localhost`, or `::1` test origins;
- a credential from a named uppercase environment variable;
- TLS certificate validation, no redirects, a bounded timeout, and a 32 MiB
  response ceiling; and
- normalization and sensitive-field removal before detection evaluation.

Plans serialize the credential environment-variable name and query SHA-256,
never the credential value, request header, or raw response. The CLI persists
the same redacted audit facts in SQLite.

## Supported connectors

| Connector | `--dataset` format | Default target field | Default credential variable |
| --- | --- | --- | --- |
| `splunk` | Exact index, for example `main` | `host` | `AGENTSIM_SPLUNK_TOKEN` |
| `elastic` | Exact index/data stream | `host.id` | `AGENTSIM_ELASTIC_API_KEY` |
| `crowdstrike` | Exact LogScale repository | `aid` | `AGENTSIM_CROWDSTRIKE_TOKEN` |
| `sentinel` | `WORKSPACE_ID:TABLE` | `Computer` | `AGENTSIM_SENTINEL_TOKEN` |
| `panther` | Exact Data Lake table | `p_any_hostname` | `AGENTSIM_PANTHER_API_KEY` |
| `graylog` | Exact stream ID | `source` | `AGENTSIM_GRAYLOG_TOKEN` |

Use `--target-field` when your schema stores the exact target identity in a
different field. Field names are validated and are not arbitrary expressions.
Use `--credential-env AGENTSIM_MY_READ_ONLY_TOKEN` to override the default
variable name.

## Plan, review, execute

```bash
agentsim telemetry query sentinel \
  --base-url https://api.loganalytics.io \
  --dataset 00000000-0000-4000-8000-000000000000:SecurityEvent \
  --target test-host-01 \
  --since 2026-08-02T00:00:00Z \
  --until 2026-08-02T00:10:00Z \
  --output sentinel-plan.json
```

Review the origin, endpoint, dataset, target, time bounds, record limit,
credential variable, and query hash. Then use a vendor identity restricted to
read/query permissions:

```bash
export AGENTSIM_SENTINEL_TOKEN='replace-with-a-short-lived-read-token'
agentsim telemetry query sentinel \
  --base-url https://api.loganalytics.io \
  --dataset 00000000-0000-4000-8000-000000000000:SecurityEvent \
  --target test-host-01 \
  --since 2026-08-02T00:00:00Z \
  --until 2026-08-02T00:10:00Z \
  --ability endpoint.discovery.processes \
  --execute --allow-network \
  --output sentinel-validation.json
```

Multiple `--ability` values are allowed. `--run-id` loads the abilities from an
existing campaign, links results into its SQLite detection history, and updates
only its post-run detection counters. `--include-events` adds redacted
normalized events to the output and should be used only where local evidence
retention is appropriate.

```bash
agentsim telemetry query-history --database agent_sim_runs.db
```

## Result interpretation

| Status | Meaning |
| --- | --- |
| `detected` | The generated human-review candidate matched the returned events. |
| `missed` | It did not match, although all expected sources and required fields were present. |
| `visibility_gap` | It did not match and required telemetry sources or fields were absent. |

A candidate match does not prove the production vendor rule is deployed or
syntactically correct. It validates AgentSim's vendor-neutral AST against the
normalized query result. Review and test the vendor-native rendering before
deployment.

## Python and testing

```python
from agentsim.api import build_live_query, execute_live_query
from agentsim.telemetry.connectors import QuerySpec

plan = build_live_query(QuerySpec(
    connector="elastic",
    base_url="https://elastic.example.test",
    dataset="logs-endpoint.events.process-default",
    target="host-123",
    since="2026-08-02T00:00:00Z",
    until="2026-08-02T00:05:00Z",
))

# Still disabled unless the caller explicitly supplies allow_network=True.
result = execute_live_query(plan, allow_network=True)
```

Connector tests must inject a fake `QueryTransport`; automated tests must not
contact a vendor. Custom installed connectors can use the plugin API 1.0 group
`agentsim.telemetry_connectors`.
