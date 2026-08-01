# Contributing to AgentSim

Thank you for helping improve AgentSim. Contributions should preserve its focus
on transparent, defensive telemetry generation.

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
python -m py_compile core.py scenarios.py tactics.py web_ui.py
python -m unittest discover -s tests -v
python core.py --dry-run --iterations 6 --speed 0 --seed 42
python core.py --scenario all --variant both --speed 0
```

Tests must not execute commands from the catalog. Mock process execution or use
dry-run mode.

## Command safety policy

Changes to `tactics.py` receive extra scrutiny. Every command must:

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

Commands that contact a service must live in the cloud phase so the engine's
explicit network opt-in applies. Explain what data the command reads and which
credentials it may use in the pull request.

## Agentic scenario safety policy

Changes to `scenarios.py` must preserve simulation-only execution. Scenario
fixtures may describe proposed file, tool, credential, or network activity,
but they must not implement it. Every new malicious trace must:

- use synthetic resources and redact prompt, argument, result, and payload data;
- set execution metadata explicitly, including `executed: false` for proposed
  sensitive or network actions;
- include a benign twin that differs in the security-relevant context;
- include deterministic validation that matches the malicious trace and rejects
  its benign twin; and
- document framework mappings as descriptive references, not claims of complete
  coverage or certification.

Tests for scenario changes must write artifacts only to a temporary directory
and must not patch around the simulation-only boundary.

## Detection contributions

Place rules under the relevant `detections/` subdirectory and document them in
`DETECTIONS.md`. Include:

- the expected data source and required fields;
- ATT&CK mappings;
- known false positives and tuning guidance; and
- a sample or test showing that the rule matches AgentSim telemetry.

Detection examples must use obvious placeholders for environment-specific
indexes and tables.

## Pull requests

Keep changes focused and include:

1. A concise description of the behavioral artifact or defect.
2. Safety and compatibility implications.
3. Tests for code changes.
4. Documentation updates for interface, command, or mapping changes.
5. Confirmation that the checks above pass on a supported Python version.

Please do not include secrets, proprietary telemetry, or sensitive command
output in issues, fixtures, or pull requests. Report security concerns using
the process in [`SECURITY.md`](SECURITY.md).
