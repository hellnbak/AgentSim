# Contributing to AgentSim

Thank you for helping improve AgentSim. Contributions must preserve its focus
on detection-first, bounded adversary emulation rather than general
exploitation or command-and-control capability.

By submitting a contribution, you agree that it may be distributed under the
project's [MIT License](LICENSE).

## Development setup

AgentSim supports Python 3.9 and newer. Create an isolated environment and
install the Web UI dependency:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Run the automated checks:

```bash
python -m py_compile core.py mcp_lab.py scenarios.py tactics.py web_ui.py
python -m compileall -q agentsim
python -m unittest discover -s tests -v
python -m build
python core.py --iterations 6 --speed 0 --seed 42
python core.py --scenario all --variant both --mutations 1 --mutation-seed 42 --speed 0
python core.py --mcp-lab
python -m agentsim.cli campaign run endpoint-discovery-baseline --mode simulate --target synthetic://ci --authorization examples/authorization.simulate.json
python -m agentsim.cli lab reference all
python -m agentsim.cli telemetry investigate agent_sim_events.jsonl --collector agent_runtime --fail-on never
python -m unittest tests.test_v15 -v
python -m unittest tests.test_v16 -v
python -m unittest tests.test_v17 -v
python -m agentsim.cli telemetry mappings
python -m agentsim.cli lab conformance multi-agent-delegation-cascade --fail-on-error
python -m agentsim.cli content review examples/community-ability-pack.signed.json --trust-store examples/community-trust-store.json --fail-on review
python -m agentsim.cli lab artifact-review labs/reference-agent/artifacts/synthetic-marker.reference.json
python -m agentsim.cli telemetry query elastic --base-url https://elastic.example.test --dataset logs-test --target host-test --since 2026-08-02T00:00:00Z --until 2026-08-02T00:05:00Z
```

Tests must not execute commands from the catalog. Mock process execution or use
dry-run mode.

## Ability and command safety policy

Executable content belongs in the reviewed static argv catalogs under
`agentsim/content/catalogs/`. Ability and campaign files may reference those
commands but may not embed shell text, scripts, payloads, downloads, or
user-controlled interpolation. Every catalog command must:

- be static and strictly read-only;
- avoid exploitation, credential access, persistence, lateral movement, data
  collection, destructive behavior, or security-control changes;
- avoid user-controlled interpolation, shell downloads, and remote scripts;
- have a short, bounded runtime under normal conditions;
- avoid prompting for credentials or elevation;
- work on the platform where it is listed, or fail safely when an optional tool
  is absent; and
- be mapped to the most specific applicable MITRE ATT&CK® technique using an
  official ATT&CK source.

Commands that contact a service must use an ability with
`network_access: required`. The run and authorization manifest must also permit
network access. Explain what data the command reads and which credentials it
may use in the pull request.

Every new ability must define supported providers, target types,
`production_allowed`, timeout, state-change and cleanup behavior, expected
telemetry, detection objectives, benign controls, and defenses. Built-in
content should remain `production_allowed: false`.

Ability packs, campaign packs, and command catalogs require canonical SHA-256
integrity metadata. Built-in content also requires the AgentSim release
signature. Contributors should update content and tests; a maintainer updates
the digest and signature with `scripts/sign_content.py` after review. Never
commit a private key or disable integrity verification to make a change load.

State-changing abilities require an idempotent cleanup catalog reference and
tests for success, failure, cancellation, and cleanup. Higher-risk behaviors
belong in disposable labs or external adapters rather than the public core.

Do not add payload bytes, URLs, downloads, or artifact paths to ability or
campaign packs. The v1.7 lab-artifact reference is an inspection-only metadata
contract: it verifies provenance, lab-root path scope, SHA-256, type, size,
platform, resource limits, and cleanup requirements but cannot execute or
return the artifact. A proposed execution integration must remain a separately
reviewed executor contract over that immutable reference and independently add
an exact disposable target, lab-only authorization, preflight controls, and
cleanup evidence. The public core must reject unpinned artifacts and retain no
payload content.

Campaign packs may only reference abilities. Dependencies must point to an
earlier declared step, and stop behavior must be explicit. See
[`ABILITIES.md`](ABILITIES.md) and [`CAMPAIGNS.md`](CAMPAIGNS.md).

## Agentic scenario safety policy

Add scenario content as a declarative JSON pack under
`agentsim_scenarios/packs/`; change `scenarios.py` only when the engine or
schema needs to evolve. Scenario fixtures may describe proposed file, tool,
credential, or network activity, but they must not implement it. Every new
malicious trace must:

- use synthetic resources and redact prompt, argument, result, and payload data;
- set execution metadata explicitly, including `executed: false` for proposed
  sensitive or network actions;
- include a benign twin that differs in the security-relevant context;
- include deterministic validation that matches the malicious trace and rejects
  its benign twin; and
- document framework mappings as descriptive references, not claims of complete
  coverage or certification.

Pack loading enforces additional invariants: action event types require
`attributes.executed: false`, resources must be synthetic or loopback-only,
tokens and payloads may not be recorded, IDs must be unique, and detector
conditions may not inspect label fields. Use the ordered detector operators
documented in [`SCENARIOS.md`](SCENARIOS.md). Update both JSON schemas when a
public pack or event field changes.

New scenarios should exercise meaningful combinations of session, agent,
principal, delegation, approval, policy version, causal, and data-lineage fields
rather than relying only on descriptions. Run at least one mutation per trace
to verify that the detector is not overfit to exact fixture wording.

Tests for scenario changes must write artifacts only to a temporary directory
and must not patch around the simulation-only boundary.

## Detection contributions

Place rules under the relevant `detections/` subdirectory and document them in
`DETECTIONS.md`. Include:

- the expected data source and required fields;
- ATT&CK mappings;
- known false positives and tuning guidance; and
- a sample or test showing that the rule matches AgentSim telemetry.

Agent-event analytics must not query `expected_detection`, `scenario_variant`,
`scenario_id`, or descriptive message text. Prefer ordered correlations on
security fields and include a benign event test.

Detection examples must use obvious placeholders for environment-specific
indexes and tables.

Changes to the generated sample library belong in
`agentsim/detection/sample_content/catalog.json` or its renderer, not directly
in checked-in generated files. Regenerate `examples/detection-samples`, verify
its manifest matches a fresh export, and add a malicious match plus a closely
matched benign rejection. Alert examples must stay synthetic, trace-linked,
collector-normalizable, and free of prompts, messages, arguments, results,
responses, credentials, secrets, tokens, and payload values. Vendor samples
must remain disabled or visibly marked tuning/human-review required.

Reusable detection packs belong under `agentsim/detection/pack_content/` or in
a separately reviewed JSON file. Each packed rule must declare all
`required_fields` used by its expression/grouping and the acceptable source
profiles. Packs may not contain `expected_detection`, `expected_detected`,
`ground_truth`, or `scenario_variant`. Include tests for `detected`,
`not_detected`, and `visibility_gap` behavior and run telemetry assurance over
the fixture before interpreting the result.

Changes to normalization must add assurance tests for timestamp provenance,
stable IDs, causal links, generated identity metadata, and content redaction.
Do not make a malformed timestamp silently look native or preserve the raw
invalid value in a report.

Detection-AST contributions must include malicious and benign normalized-event
fixtures, group/time-boundary tests, required-field coverage, and renderer
limitations. Generated rules must remain candidates until a human reviewer
promotes them outside AgentSim.

Graph-oriented AST contributions must additionally test multiple parents,
non-adjacent descendants, distinct-entity fan-out, maximum depth, missing
record IDs, and grouping isolation. Investigation invariants require a failing
trace, a closely matched clean twin, evidence/remediation assertions, and a
content-boundary test. Web changes must use text-safe DOM construction and be
verified in the local browser at desktop and narrow viewport widths.

Flight-recorder changes must test SDK-callback failure isolation, content-key
redaction, bounded OTLP JSON, loopback receiver denial, bundle digest tamper,
and non-executing pseudonymous twins. Detection CI changes must include stable,
malicious-regression, benign-regression, visibility-gap, JSON, Markdown, JUnit,
SARIF, CLI, API, and Web tests. See
[`FLIGHT_RECORDER.md`](FLIGHT_RECORDER.md).

Portable mapping changes must name the exact OTel, ECS, or OCSF version and
cite the official field definition. Do not call AgentSim policy, delegation,
goal, memory, or MCP fields standard-native when no equivalent exists. Add
map/import round-trip tests, content-redaction tests, collector coverage, and
cross-runtime conformance. Update the mapping catalog and
[`PORTABILITY_AND_TRUST.md`](PORTABILITY_AND_TRUST.md).

Community content must include strict provenance and a signature from a key the
reviewing organization explicitly trusts. Contributors may update the example
public key and signed fixture, but must never commit a private key. Add tests
for missing trust, checksum substitution, provenance substitution, prohibited
executable fields, and each review verdict. Artifact-reference changes must
test traversal, symlinks, path escape, size/digest substitution, content
non-return, and execution denial.

Feedback contract changes must keep alerts and annotations structured and
content-safe. Do not add a free-form analyst note, prompt, argument, result,
response, or payload field. Add tests for alert/evidence trace disagreement,
unresolved references, invalid evidence digests, agent-authored dispositions,
contradictory verdicts, and malicious/benign drift. Drift changes must test both
stable and regressed candidates and must never add a vendor deployment path.

## Collectors, live connectors, external adapters, and plugins

Offline collectors must read exported data only, enforce bounded input,
normalize to the public event schema, and remove sensitive values.

Live SIEM connectors must remain read-only and dry-run first. They must use an
exact dataset and target, bounded time/record/response limits, TLS validation,
redirect denial, an environment-sourced credential, a mockable transport, and
double network opt-in. Tests must use fake transports and verify credentials do
not enter plans, normalized events, output artifacts, or SQLite audits. Vendor
mutation/deployment APIs and broad searches are out of scope.

External adapters may emit version-pinned plans but may not execute a tool or
send a network request. Execution belongs in an explicitly installed
`agentsim.external_executors` plugin. Custom query backends may use
`agentsim.telemetry_connectors`. New plugin contracts must preserve API 1.0 or
introduce a clearly versioned new contract. See
[`PLUGIN_SDK.md`](PLUGIN_SDK.md) and
[`EXTERNAL_PROVIDERS.md`](EXTERNAL_PROVIDERS.md).

## Pull requests

Keep changes focused and include:

1. A concise description of the behavioral artifact or defect.
2. Safety and compatibility implications.
3. Tests for code changes.
4. Documentation updates for interface, command, or mapping changes.
5. Authorization, target-scope, resource-limit, and cleanup implications.
6. Confirmation that the checks above pass on a supported Python version.

Please do not include secrets, proprietary telemetry, or sensitive command
output in issues, fixtures, or pull requests. Report security concerns using
the process in [`SECURITY.md`](SECURITY.md).
