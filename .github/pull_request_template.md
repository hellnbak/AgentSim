## Summary

Describe the behavior or defect addressed.

## Safety and compatibility

- [ ] Commands remain static, read-only, bounded, and non-interactive.
- [ ] Network behavior is absent or protected by the explicit opt-in.
- [ ] Agentic scenarios remain simulation-only and use synthetic, redacted data.
- [ ] New malicious traces include benign twins and deterministic validation.
- [ ] Scenario detectors do not consult labels or descriptive message text.
- [ ] Custom pack and schema changes preserve the fail-closed safety checks.
- [ ] Built-in content digest/signature updates are assigned to a release maintainer.
- [ ] Offline collectors remain bounded, read-only, and sensitive-value safe.
- [ ] External adapters emit plans only and do not execute or send requests.
- [ ] Plugin discovery does not import third-party code.
- [ ] ATT&CK mappings use official sources.
- [ ] Supported operating systems were considered.

## Verification

- [ ] `python -m py_compile core.py mcp_lab.py scenarios.py tactics.py web_ui.py`
- [ ] `python -m unittest discover -s tests -v`
- [ ] `agentsim lab run all`
- [ ] `agentsim detection generate endpoint.discovery.processes --format sigma`
- [ ] `python core.py --dry-run --iterations 6 --speed 0 --seed 42`
- [ ] `python core.py --scenario all --variant both --mutations 1 --mutation-seed 42 --speed 0`
- [ ] `python core.py --mcp-lab`
- [ ] Documentation was updated where needed.
