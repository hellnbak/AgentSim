## Summary

Describe the behavior or defect addressed.

## Safety and compatibility

- [ ] Commands remain static, read-only, bounded, and non-interactive.
- [ ] Network behavior is absent or protected by the explicit opt-in.
- [ ] Agentic scenarios remain simulation-only and use synthetic, redacted data.
- [ ] New malicious traces include benign twins and deterministic validation.
- [ ] ATT&CK mappings use official sources.
- [ ] Supported operating systems were considered.

## Verification

- [ ] `python -m py_compile core.py scenarios.py tactics.py web_ui.py`
- [ ] `python -m unittest discover -s tests -v`
- [ ] `python core.py --dry-run --iterations 6 --speed 0 --seed 42`
- [ ] `python core.py --scenario all --variant both --speed 0`
- [ ] Documentation was updated where needed.
