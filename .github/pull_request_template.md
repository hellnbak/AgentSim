## Summary

Describe the behavior or defect addressed.

## Safety and compatibility

- [ ] Commands remain static, read-only, bounded, and non-interactive.
- [ ] Network behavior is absent or protected by the explicit opt-in.
- [ ] ATT&CK mappings use official sources.
- [ ] Supported operating systems were considered.

## Verification

- [ ] `python -m py_compile core.py tactics.py web_ui.py`
- [ ] `python -m unittest discover -s tests -v`
- [ ] `python core.py --dry-run --iterations 6 --speed 0 --seed 42`
- [ ] Documentation was updated where needed.
