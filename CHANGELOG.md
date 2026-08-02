# Changelog

Notable changes to AgentSim are documented here. The project follows semantic
versioning while its public interfaces mature.

## 1.2.0 - 2026-08-02

- Added a canonical, content-safe agent trace contract with trace, session,
  conversation, agent, principal, turn, tool, delegation, memory, lineage,
  policy, approval, MCP authorization, taint, outcome, and usage metadata.
- Added adapters for generic agent-runtime, OpenTelemetry GenAI, and MCP audit
  records. Prompt, message, argument, result, response, payload, credential,
  secret, password, and unsafe token fields are discarded before persistence.
- Added dry-run-first, exact-target, read-only telemetry connectors for Splunk,
  Elastic, CrowdStrike LogScale, Microsoft Sentinel, Panther, and Graylog.
  Live execution requires two explicit flags, HTTPS (except loopback), an
  environment-sourced credential, and a bounded 24-hour/10,000-record query.
- Added live detection outcomes that distinguish a true `missed` analytic from
  a `visibility_gap`, plus redacted SQLite query history and optional campaign
  detection/artifact linkage.
- Added an instrumented reference-agent runtime with fixed synthetic tools,
  malicious/benign twins, causal policy traces, reset verification, a guarded
  loopback HTTP surface, and a hardened Docker Compose profile.
- Doubled deterministic control fixtures from ten to twenty and expanded the
  declarative benchmark from nineteen to twenty-nine scenarios. New coverage
  includes cross-turn goal hijacking, tool-definition/result provenance
  poisoning, configuration/supply-chain tampering, replay, delayed
  exfiltration, deceptive summaries, MCP scope challenge abuse, and retrieval
  source substitution.
- Added public schemas for agent trace events, redacted query plans, and
  reference-lab results, plus Python/CLI/Web APIs and plugin API 1.0 telemetry
  connector entry points.
- Made SQLite lifecycle handling and local platform discovery deterministic on
  Windows as well as Linux and macOS.

## 1.0.0 - 2026-08-02

- Stabilized the detection-first workflow across endpoint, cloud, and agentic
  testing with a public v1 CLI, Python API, Web API, schemas, and plugin API.
- Added bounded offline JSON/JSONL collectors and redacted normalization for
  OTel, Sysmon, auditd, CloudTrail, CrowdStrike, Splunk, and agent-runtime data.
- Added a vendor-neutral detection AST for predicates, boolean/negative logic,
  ordered sequences, windows, thresholds/distinct counts, parent-child
  lineage, causal graphs, and entity grouping.
- Added expected-source/required-field coverage, ground-truth correlation,
  gap findings, runbooks, regression evaluation, and defensive scorecards.
- Added transparent human-review candidate generation and renderers for Sigma,
  KQL, SPL, CrowdStrike LogScale, Elastic EQL, Panther, and Graylog.
- Added ten disposable in-memory agentic security fixtures covering prompt,
  memory, RAG, MCP, confused-deputy, delegation, approval, decoy-secret, and
  resource-budget controls while preserving the non-executing scenario engine.
- Added version-pinned, hashed, non-executing Atomic Red Team, Stratus Red
  Team, and MITRE CALDERA adapter plans.
- Added Attack Flow STIX 2.1 campaign import/export with reviewed ability
  mapping, cycle rejection, and review-draft imports.
- Added RSA PKCS#1 v1.5 SHA-256 signatures to built-in ability, campaign, and
  reviewed-command content plus a public trust store and maintainer signing
  helper. The release private key is not distributed.
- Added plugin API 1.0 entry points for collectors, detection renderers, and
  separately installed external executors; discovery does not import plugins.
- Expanded SQLite history with detection/artifact records and expanded every
  campaign evidence ZIP with scorecard, runbooks, candidates, and Attack Flow.
- Added v1 CLI commands for telemetry, detection, defense, lab, external plans,
  Attack Flow, and plugin discovery with CI-friendly exit codes.
- Added Web v1 catalog, campaign, synthetic detection/coverage, and disposable
  agentic-lab APIs plus a dashboard validation workspace.
- Published normalized-event, detection-rule, external-plan, and signed-pack
  schemas and replaced the future-roadmap documentation with v1 operations,
  safety, provider, and plugin guidance.

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
