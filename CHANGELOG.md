# Changelog

Notable changes to AgentSim are documented here. The project follows semantic
versioning while its public interfaces mature.

## 0.3.0 - 2026-08-01

- Replaced hard-coded scenario definitions with validated declarative JSON
  packs and published machine-readable pack and event schemas.
- Expanded the benchmark from 3 to 13 scenarios covering cross-session memory,
  RAG integrity, multi-agent trust and cascading failures, deceptive approvals,
  code execution intent, policy evasion, resource abuse, and MCP identity,
  confused-deputy, token, session, and SSRF controls.
- Added multi-session, multi-agent, causal, delegation, approval, taint, data
  lineage, principal, and versioned-policy fields in event schema v2 while
  retaining v1 JSONL loading support.
- Added semantic-preserving mutations, confusion-matrix scorecards,
  checkpoints-to-detection metrics, and field/framework coverage reporting.
- Added JUnit, SARIF, OpenTelemetry-compatible JSONL, and portable ZIP evidence
  exports for CI and detection-engineering workflows.
- Added a transport-free, in-memory MCP JSON-RPC authorization lab.
- Added agent-event detection examples for Microsoft KQL, Splunk, CrowdStrike
  Falcon LogScale/Next-Gen SIEM, Graylog, Panther, Elastic EQL, and Sigma.
- Updated the dashboard with mutation controls, expanded lifecycle stages,
  benchmark metrics, and evidence-bundle download.

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
