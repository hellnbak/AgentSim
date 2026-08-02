# External providers and Attack Flow

AgentSim integrates with established adversary-emulation systems through
version-pinned plans rather than reimplementing their execution capability.

## Public-core boundary

`agentsim external plan` validates identifiers, exact semantic versions,
targets, lifecycle phases, and cleanup requirements. It returns a SHA-256 hashed
JSON plan conforming to
[`schemas/external-plan.schema.json`](schemas/external-plan.schema.json).

The public core never executes the plan. It does not start the external binary,
make a CALDERA request, load credentials, install prerequisites, or select a
target. `execution_supported_by_core` is always `false`.

## Atomic Red Team

Atomic plans require an ATT&CK technique ID, stable test GUID, exact provider
version, and target. The plan records prerequisite check, test, and cleanup
phases. GUID selection is preferred because test names/numbers may change.

```bash
agentsim external plan atomic-red-team \
  --provider-version 2.2.0 \
  --target localhost://atomic-lab \
  --technique-id T1057 \
  --test-guid 11111111-1111-4111-8111-111111111111 \
  --output atomic-plan.json
```

Reference: [Atomic Red Team documentation](https://www.atomicredteam.io/docs/atomic-red-team).

## Stratus Red Team

Stratus plans require a named cloud/Kubernetes sandbox and record warmup,
detonation, revert, and cleanup. AgentSim rejects an ordinary localhost target.

```bash
agentsim external plan stratus-red-team \
  --provider-version 2.17.0 \
  --target cloud://aws/security-sandbox \
  --technique-id aws.discovery.ec2-describe-instances \
  --output stratus-plan.json
```

Reference: [Stratus Red Team command lifecycle](https://stratus-red-team.cloud/user-guide/getting-started/).

## MITRE CALDERA

CALDERA plans describe create, observe, and stop/cleanup requests against an
explicit server URL. URLs containing credentials, query data, or fragments are
rejected. The plan never contains an API token.

```bash
agentsim external plan mitre-caldera \
  --provider-version 5.1.0 \
  --target lab-agent://purple-01 \
  --adversary-id reviewed-profile \
  --server-url https://caldera.lab.example \
  --output caldera-plan.json
```

Reference: [MITRE CALDERA repository](https://github.com/mitre/caldera).

## Executor plugins

A separately installed `agentsim.external_executors` plugin may consume a plan.
Before execution it must verify:

- AgentSim plugin API `1.0`;
- exact external-tool version;
- plan hash and reviewed identifier;
- unexpired authorization and exact target scope;
- isolated lab/sandbox status;
- resource and network policy;
- cleanup/rollback readiness; and
- redacted lifecycle evidence returned to AgentSim.

Installing a plugin is a trust decision. Metadata discovery does not import it;
explicit loading does.

## Attack Flow STIX 2.1

AgentSim exports campaigns as Attack Flow `emulation-plan` bundles with one
`attack-flow` object and linked `attack-action` objects. The format uses the
official Attack Flow STIX extension ID.

```bash
agentsim attack-flow export endpoint-discovery-baseline --output flow.json
agentsim attack-flow import flow.json --output campaign-draft.json
```

Import maps an AgentSim ability external reference first, then a reviewed
ATT&CK technique. Unmapped actions are warnings and are skipped. Cycles fail
closed. Imported output is a review draft, not a signed executable campaign.

Reference: [Attack Flow language specification](https://center-for-threat-informed-defense.github.io/attack-flow/language/).
