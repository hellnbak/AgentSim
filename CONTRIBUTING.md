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

Detection-AST contributions must include malicious and benign normalized-event
fixtures, group/time-boundary tests, required-field coverage, and renderer
limitations. Generated rules must remain candidates until a human reviewer
promotes them outside AgentSim.

## Collectors, external adapters, and plugins

Collectors must read exported data only, enforce bounded input, normalize to
the public event schema, and remove sensitive values. Do not add a live SIEM
credential/query connector to the public core.

External adapters may emit version-pinned plans but may not execute a tool or
send a network request. Execution belongs in an explicitly installed
`agentsim.external_executors` plugin. New plugin contracts must preserve API
1.0 or introduce a clearly versioned new contract. See
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
