# Changelog

Notable changes to AgentSim are documented here. The project follows semantic
versioning while its public interfaces mature.

## 0.4.0 - 2026-08-01

- Repositioned AgentSim as detection-first adversary emulation built around the
  **EMULATE → OBSERVE → DETECT → DEFEND → RETEST** workflow.
- Added a proper `agentsim` package with typed ability, campaign, target,
  authorization, lifecycle-event, and result models while preserving legacy
  CLI and module compatibility.
- Added checksummed ability and campaign packs plus an independently
  checksummed reviewed static argv command catalog; campaigns and abilities
  reject unknown executable fields.
- Added scoped, expiring authorization manifests, target allowlists and CIDRs,
  production lockout, network triple-consent, action/process/time limits, and
  state-change cleanup requirements.
- Added provider/target compatibility checks during planning and explicit
  kill-switch cancellation evidence with a bounded cleanup-process reserve.
- Added simulation, localhost, and named-Docker-container execution providers
  behind a common `ExecutionProvider` interface. Simulation is the default.
- Added directed campaign planning and execution, single-ability regression
  runs, lifecycle schema v3, immutable manifest hashes, SQLite history,
  defensive recommendations, and portable evidence bundles.
- Migrated the original read-only endpoint discovery behavior into eight
  abilities and two foundation campaigns.
- Added the dashboard Authorized Campaign Foundation with simulation-only
  execution, lifecycle results, cleanup status, and persistent history.
- Changed legacy endpoint behavior to safe preview by default; local execution
  now requires the explicit `--execute-local` compatibility flag.

- Added six malicious/benign scenario pairs for model fallback downgrade,
  planner/executor policy disagreement, approval replay, cross-tenant context
  confusion, emergent tool-chain escalation, and agent registry poisoning.
- Added high-confidence control-plane detection examples for Microsoft KQL,
  Splunk, CrowdStrike Falcon LogScale/Next-Gen SIEM, Graylog, Panther, Elastic
  EQL, and Sigma.
- Added a local Detection Debugger with trace filtering, expected/observed
  outcomes, ordered detector conditions, signal checkpoint highlighting, and
  detection-latency context for human analysts.

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
