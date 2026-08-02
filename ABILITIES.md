# Ability packs

Ability packs define reviewed, gated adversary behaviors. The machine-readable
schema is [`schemas/ability-pack.schema.json`](schemas/ability-pack.schema.json).

## Required metadata

Every ability includes:

- a stable ID, name, description, risk, platforms, and framework mappings;
- supported providers and a safe default provider;
- elevation, network, timeout, and state-change declarations;
- a static `catalog://` command reference and optional cleanup reference;
- allowed target types and `production_allowed`;
- expected telemetry sources and required fields;
- detection objectives and benign controls; and
- defensive recommendations.

Ability and execution objects reject unknown fields, so embedded `command`,
`commands`, `script`, `shell`, and `payload` keys fail closed. This prevents a
third-party content file from bypassing command review.

## Built-in abilities

| Ability | ATT&CK | Network | Providers |
| --- | --- | --- | --- |
| `endpoint.discovery.system-information` | T1082 | Denied | simulate, local, Docker |
| `endpoint.discovery.current-user` | T1033 | Denied | simulate, local, Docker |
| `endpoint.discovery.local-accounts` | T1087.001 | Denied | simulate, local, Docker |
| `endpoint.discovery.processes` | T1057 | Denied | simulate, local, Docker |
| `endpoint.discovery.local-groups` | T1069.001 | Denied | simulate, local, Docker |
| `endpoint.discovery.network-connections` | T1049 | Denied | simulate, local, Docker |
| `endpoint.discovery.network-configuration` | T1016 | Denied | simulate, local, Docker |
| `cloud.discovery.services` | T1526 | Required | simulate |

All built-in abilities are `production_allowed: false`.

## Integrity

Every ability pack must include a SHA-256 digest of the canonical abilities
array. Built-in packs and the reviewed command catalog also include an RSA
PKCS#1 v1.5 SHA-256 signature tied to the content kind, ID, key, and digest.
The reviewed command catalog remains an independent executable trust boundary.
Its machine-readable contract is
[`schemas/command-catalog.schema.json`](schemas/command-catalog.schema.json).
To calculate a digest for custom content, serialize the content object with
sorted keys and compact separators, then hash the UTF-8 bytes. AgentSim rejects
missing, malformed, or mismatched integrity metadata and rejects an unknown or
invalid signature when one is present.

## Adding an ability

1. Add or review static argv in `agentsim/content/catalogs/`.
2. Add the ability definition under `agentsim/content/packs/`.
3. Declare expected telemetry, a benign control, and actionable defenses.
4. Set `production_allowed: false` unless a future reviewed policy explicitly
   supports production.
5. For state changes, add an idempotent cleanup catalog reference.
6. Have a maintainer update the checksum and release signature after review.
7. Test simulation, policy denial, cleanup, and mocked provider execution.

Custom packs can be loaded with repeatable `--ability-pack PATH` options.
