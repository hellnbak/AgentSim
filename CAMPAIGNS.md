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

Runs one authenticated read-only cloud discovery ability. The built-in ability
is simulation-only and does not contact a cloud service. Higher-risk cloud
emulation can be represented by a version-pinned Stratus plan and executed only
through a separately reviewed plugin in a named sandbox.

## Directed control-validation preview

Four v1.6 campaigns add explicit dependency graphs while remaining
simulation-only:

- `endpoint-agent-execution-chain` links interpreter ancestry, credential
  decoy access, synthetic archive staging, and monitoring-tamper intent.
- `endpoint-persistence-control-validation` joins identity and interpreter
  context before autostart and monitoring policy proposals.
- `cloud-identity-to-impact` branches from cloud role discovery into decoy
  secret access and privilege intent, joins at public-access intent, and ends
  at an audit-logging control.
- `hybrid-agent-control-chain` correlates endpoint interpreter behavior,
  instance-metadata intent, cloud identity discovery, decoy access, and blocked
  cloud impact across trace identity.

These campaigns are checksum-protected review previews, not release-signed
executable content. Every preview ability is restricted to the simulation
provider, network denied, production locked, and state-change free.

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
and omitted abilities remain `detection_pending`. Vendor exports can also be
validated separately with `agentsim telemetry`, `agentsim detection`, and
`agentsim defense`; the public core intentionally has no live SIEM credential
connector.

## v1 portable outputs

Every run bundles the immutable manifest, lifecycle JSONL, campaign report,
defense scorecard, runbook/recommendation record, human-review detection
candidates, and Attack Flow STIX export. SQLite records artifact paths and
hashes alongside run/action/event history.

## Stop and cleanup behavior

An action with `on_failure: stop` ends further campaign execution after its
cleanup attempt. `continue` permits the next already-declared step. The global
kill switch and resource limits are checked before every action and process.
Cleanup is still attempted when provider preparation or execution fails.
Cancellation records an explicit `cancelled` lifecycle state, stops remaining
steps, and retains a bounded cleanup-process reserve so cleanup can still run.
