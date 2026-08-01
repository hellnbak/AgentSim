# Changelog

Notable changes to AgentSim are documented here. The project follows semantic
versioning while its public interfaces mature.

## 0.2.0 - 2026-08-01

- Added a simulation-only agentic scenario engine for indirect prompt
  injection, MCP tool poisoning, and synthetic decoy-secret exfiltration.
- Added malicious/benign twin traces, JSONL ground truth, and deterministic
  validation reports.
- Added scenario selection, live checkpoint metrics, and artifact downloads to
  the Web dashboard.
- Added CLI scenario discovery and execution options.
- Documented agent-runtime data requirements, safety guarantees, framework
  mappings, and SIEM validation workflow.

## 0.1.0 - 2026-08-01

- Added cross-platform endpoint behavior simulation and ATT&CK Navigator export.
- Added the local Web dashboard and detection examples for Sigma, Microsoft
  Defender XDR, Splunk, CrowdStrike Falcon LogScale, Graylog, and Panther.
