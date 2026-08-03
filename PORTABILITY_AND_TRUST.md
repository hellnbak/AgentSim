# Telemetry portability and content trust

AgentSim 1.7 adds version-pinned mappings for content-safe agent events,
cross-runtime conformance, signed community-pack review, pack provenance, and a
non-executing lab-artifact reference contract. These interfaces make defensive
evidence easier to move and review; they do not add a payload runner, vendor
deployment path, or production execution capability.

## Portable telemetry profiles

The canonical AgentSim trace contract can be mapped to:

| Profile | Pinned version | Native examples | AgentSim extension |
| --- | --- | --- | --- |
| OpenTelemetry | Semantic Conventions 1.43.0 | trace/span identity, `gen_ai.agent.id`, conversation, tool, model, and data-source IDs | `attributes.agentsim` |
| Elastic Common Schema | ECS 9.4.0 | `@timestamp`, `event.*`, `trace.id`, `session.id`, `user.id` | `agentsim` |
| Open Cybersecurity Schema Framework | OCSF 1.8.0 API Activity with `trace` and `ai_operation` profiles | activity, actor, trace/span, message context, model, source, and status | `unmapped.agentsim` |

The pins follow the official [OpenTelemetry semantic conventions](https://opentelemetry.io/docs/specs/semconv/),
[ECS field reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html),
and [OCSF schema releases](https://github.com/ocsf/ocsf-schema/releases).
AgentSim does not claim that its records are a complete certification target
for any standard. Native fields are used only where the published standard has
a defensible equivalent. Agent policy, approval, delegation, goal, memory,
MCP authorization, and other project-specific fields remain in a visibly
separate extension namespace.

Content values are never mapped. Prompts, messages, reasoning, tool arguments
and results, responses, credentials, secrets, and payload values remain outside
the contract. Each mapped result reports its native and extension fields and a
native-coverage percentage so field loss cannot be hidden.

```bash
agentsim telemetry mappings

agentsim telemetry map agent-events.jsonl \
  --from-profile canonical \
  --to-profile ecs \
  --output ecs-events.json

agentsim telemetry map ecs-records.json \
  --from-profile ecs \
  --to-profile canonical \
  --output canonical-events.json
```

Input is limited to 10,000 records per invocation and each portable record is
limited to 2 MiB. The offline `ecs` and `ocsf` collectors accept mapped or
vendor-shaped JSON/JSONL without contacting a service.

## Cross-runtime conformance

Conformance runs a fixed instrumented reference-agent fixture, maps every
event to each selected profile, restores the canonical event, and compares
correlation and security invariants. It checks identity, causality,
delegation, goal, memory, tool, policy, trust, outcome, and bounded safe
attributes; it does not compare or retain content.

```bash
agentsim lab conformance multi-agent-delegation-cascade \
  --output conformance.json \
  --fail-on-error

# Run a subset when debugging a runtime mapping.
agentsim lab conformance multi-agent-delegation-cascade \
  --profile otel --profile ocsf
```

The report is capped at 2,000 events and includes profile versions, invariant
check counts, native coverage, bounded failures, and explicit non-execution and
non-network safety facts. Passing means the AgentSim round trip preserved its
declared invariants; it is not a general standard-compliance certification.

## Community pack review and provenance

Community ability, campaign, and detection packs are treated as untrusted
data. Review does not import a Python module or resolve a command. Approval
requires all of these gates:

1. The canonical content SHA-256 matches.
2. An RSA PKCS#1 v1.5 SHA-256 signature verifies under a built-in or explicitly
   supplied public trust key.
3. Provenance pins an HTTPS repository, 40–64 character hexadecimal revision,
   repository-relative source path, author identifiers, SPDX-style license,
   timestamped review status, reviewer, and policy.
4. The strict pack loader accepts the declarative structure.
5. No inline command, executable, script, payload, download, URL, elevation,
   or production-enabled behavior crosses the safety boundary.

Active providers, network capability, or state changes produce a `review`
verdict even when cryptographic and structural checks pass. A missing or
untrusted signature, invalid provenance, unsafe structure, or prohibited
content produces `blocked`.

```bash
agentsim content review examples/community-ability-pack.signed.json \
  --trust-store examples/community-trust-store.json \
  --output community-review.json \
  --fail-on review
```

The included key is an example public key only; its private key is not shipped.
An external trust store may add keys but cannot replace a built-in key ID. A
trust decision should be made by the organization that controls the runtime,
not inferred from a repository name or checksum alone.

To sign declarative content after an independent review:

```bash
python scripts/sign_content.py community-pack.json abilities \
  --private-key /secure/offline/key.json \
  --key-id organization-review-2026 \
  --output community-pack.signed.json
```

Never commit the private key. Provenance is included in the signed payload, so
changing the repository revision, source path, authorship, license, or review
record invalidates the signature even when the content array is unchanged.
AgentSim validates and cryptographically binds this metadata without contacting
the source repository. The signer or reviewer must verify the pinned revision
and path out of band before issuing an `approved` provenance record. The bundled
pack and key are illustrative test identities, not publisher identity claims.

## Reviewed lab-artifact references

The lab-artifact contract answers a narrow need: a scenario can name a
reviewed local artifact for defensive correlation without embedding, loading,
or executing its content. A reference requires:

- a repository-relative path under an explicit lab root;
- exact SHA-256 and size, media type, artifact type, and platform list;
- approved provenance;
- `lab_only: true`, `production_allowed: false`, and network denied;
- `execution_allowed: false`, an ephemeral-container requirement, cleanup,
  runtime, and memory limits; and
- a SHA-256 checksum over the reference metadata itself.

Review rejects absolute paths, traversal, symlinks, path escape, missing files,
oversized artifacts, and digest or size substitutions. It streams only the
SHA-256 calculation and returns metadata; artifact bytes are never returned.
Executable or script types remain inspection-only and receive a human-review
verdict. The public core has no artifact execution function.

```bash
agentsim lab artifact-review \
  labs/reference-agent/artifacts/synthetic-marker.reference.json \
  --lab-root labs/reference-agent/artifacts \
  --output artifact-review.json
```

Scenario packs may carry a `lab-artifact://...` identifier for correlation,
but cannot carry a path, byte string, URL, download, shell fragment, or
execution instruction.

## Python, Web, and schemas

Stable Python helpers are available from `agentsim.api`:

- `portable_mapping_catalog()`
- `map_agent_telemetry(...)`
- `cross_runtime_conformance(...)`
- `community_pack_review(...)`
- `lab_artifact_review(...)`

The loopback Web workspace exposes the same review surfaces with safe demo
data. Uploaded community JSON is evaluated in request memory and not retained.
The bundled artifact demo returns its digest and controls, not its content.

Machine-readable contracts:

- `schemas/portable-mapping.schema.json`
- `schemas/runtime-conformance-report.schema.json`
- `schemas/content-provenance.schema.json`
- `schemas/community-pack-review.schema.json`
- `schemas/lab-artifact-reference.schema.json`
- `schemas/lab-artifact-review.schema.json`

These contracts are defensive interchange and review surfaces. They do not
authorize execution, establish publisher identity outside the configured trust
store, or replace environment-specific privacy and retention review.
