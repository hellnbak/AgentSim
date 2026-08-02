# Campaign packs

Campaigns replace random action selection with a directed defensive test. The
machine-readable schema is
[`schemas/campaign-pack.schema.json`](schemas/campaign-pack.schema.json).

A campaign declares its initial target profile, objective, dependency-ordered
ability steps, required telemetry, stop conditions, and authorization
requirement. It cannot contain commands or payloads.

## Built-in campaigns

### `endpoint-discovery-baseline`

Runs seven reviewed endpoint discovery abilities through host, identity,
process, group, socket, and network-configuration stages. It expects process
creation, ancestry, and user context telemetry.

### `cloud-discovery-baseline`

Runs one authenticated read-only cloud discovery ability. In 0.4 it is
simulation-only and does not contact a cloud service. Executable cloud
discovery is reserved for a future isolated or external provider.

## Workflow

```bash
agentsim campaign list

agentsim campaign plan endpoint-discovery-baseline \
  --mode simulate \
  --target synthetic://ci \
  --authorization examples/authorization.simulate.json

agentsim campaign run endpoint-discovery-baseline \
  --mode simulate \
  --target synthetic://ci \
  --authorization examples/authorization.simulate.json

agentsim campaign history
```

`plan` shows the resolved provider, authorization decision, command and cleanup
references, telemetry expectations, and defenses for every step. It does not
prepare or invoke a provider.

## Detection-result input

Use `--detection-results PATH` with a JSON object that maps ability IDs to
booleans:

```json
{
  "endpoint.discovery.processes": true,
  "endpoint.discovery.local-accounts": false
}
```

`true` produces a `detected` lifecycle transition, `false` produces `missed`,
and omitted abilities remain `detection_pending`. This is intentionally an
offline interface in 0.4. Direct read-only SIEM connectors are planned for a
later release.

## Stop and cleanup behavior

An action with `on_failure: stop` ends further campaign execution after its
cleanup attempt. `continue` permits the next already-declared step. The global
kill switch and resource limits are checked before every action and process.
Cleanup is still attempted when provider preparation or execution fails.
Cancellation records an explicit `cancelled` lifecycle state, stops remaining
steps, and retains a bounded cleanup-process reserve so cleanup can still run.
