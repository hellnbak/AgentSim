# Changelog

Notable changes to AgentSim are documented here. The project follows semantic
versioning while its public interfaces mature.

## 1.7.0 - 2026-08-02

- Added content-safe mappings from canonical agent trace events to pinned
  OpenTelemetry Semantic Conventions 1.43.0, ECS 9.4.0, and OCSF 1.8.0
  profiles, with explicit AgentSim extension namespaces and native field
  coverage instead of overstating standard-native semantics.
- Added offline ECS and OCSF collectors plus canonical import/round-trip APIs,
  `agentsim telemetry mappings`, and bounded batch `telemetry map` conversion.
- Added cross-runtime conformance that round-trips fixed reference-agent events
  through every portable profile and reports field-level invariant failures,
  profile pins, check counts, native coverage, and non-execution safety facts.
- Added strict pack provenance with HTTPS repository, immutable revision,
  source path, authorship, license, and timestamped review metadata bound into
  the existing RSA signature payload.
- Added signed community ability, campaign, and detection-pack review with
  explicitly supplied public trust stores, checksum/signature/provenance/
  structure/safety gates, bounded findings, and approved/review/blocked
  verdicts. External stores cannot replace built-in trust keys.
- Added a reviewed lab-artifact reference contract that constrains artifacts to
  an explicit local lab root, rejects traversal and symlinks, verifies size and
  SHA-256 by streaming, and always denies public-core execution and network use.
- Added portable mapping loss, community provenance substitution, and artifact
  reference substitution scenarios, expanding the benchmark to 41 scenarios,
  82 baseline malicious/benign checks, and 23 disposable/reference fixtures.
- Added stable Python APIs, CLI commands, six JSON schemas, signed and artifact
  examples, package data, CI smoke coverage, and a Web Portability and Trust
  workbench for mapping, conformance, pack review, and artifact verification.
- Updated architecture, telemetry, scenario, security, contribution,
  reference-lab, roadmap, and release documentation for the v1.7 boundaries.

## 1.6.0 - 2026-08-02

- Added a bounded, digest-protected Agent Security Flight Recorder bundle that
  retains structural agent/tool/topology/policy metadata while excluding
  prompts, messages, arguments, results, responses, credentials, and payload
  values.
- Added an optional OpenAI Agents SDK trace processor that never invokes
  content-bearing span export, plus agent-runtime, OpenTelemetry GenAI, and
  OTLP/HTTP JSON ingestion and an explicit loopback-only JSON receiver.
- Added deterministic pseudonymous synthetic twins that preserve causal and
  detection-relevant structure while remaining non-executing.
- Added baseline/candidate Detection CI over telemetry assurance, multi-agent
  invariants, answer-key-free detection-pack transitions, and event retention,
  with pass/review/block semantics and JSON, Markdown, JUnit, and SARIF output.
- Added CLI and Python APIs for flight recording, OTLP serving, twin export,
  and Detection CI, plus two strict public JSON schemas and package metadata.
- Added eleven checksum-labeled, simulation-only endpoint/cloud
  control-validation abilities and four directed endpoint, cloud, and hybrid
  campaigns. Preview content is network denied, production locked,
  state-change free, and cannot use local or Docker providers.
- Added a Web Flight Recorder timeline, safe demo, twin download, interactive
  Detection CI comparison, and JSON/Markdown/SARIF downloads.
- Documented the safe extension boundary for a future lab-only payload artifact
  reference without permitting payload content in abilities, campaigns, or the
  public execution core.
- Added unit, CLI, API, content, schema, GUI, package, and simulation-safety
  tests and updated architecture, telemetry, security, contribution, ability,
  campaign, roadmap, and release documentation.

## 1.5.0 - 2026-08-02

- Added strict, content-safe alert and operator-annotation contracts plus
  alert-to-trace/evidence reconciliation with matched, ambiguous, and unmatched
  outcomes.
- Added feedback integrity findings for unresolved targets/evidence, trace
  disagreement, evidence-digest mismatch, agent-authored final verdicts,
  contradictory dispositions, and dismissal of high-risk traces.
- Added malicious/benign detection snapshots and configurable drift gates for
  recall, false-positive rate, benign rejection, alert reconciliation, and
  mean checkpoints to detection.
- Added `agentsim defense reconcile` and `agentsim defense drift`, stable Python
  APIs, three public JSON schemas, bounded inputs, JSON reports, and
  configurable CI exit thresholds.
- Added five malicious/benign scenarios covering alert-verdict poisoning,
  trace reconciliation confusion, operator annotation trust abuse, tuning
  recall collapse, and cross-agent feedback-loop alert suppression. The
  benchmark now contains thirty-eight scenarios and seventy-six baseline
  checks.
- Added the `detection-feedback-integrity` disposable/reference fixture with
  alert, feedback, reconciliation, tuning, coverage, and policy checkpoints.
  The reference corpus now includes twenty-two fixtures and 152 events.
- Expanded the answer-key-free Agent Security Core pack from twelve to fifteen
  rules with feedback identity/evidence tampering, trace/tenant reconciliation,
  and causal tuning/coverage regression detections. The reference sweep detects
  twelve rules with zero visibility gaps.
- Added a dashboard feedback workspace showing reconciliation and annotation
  coverage, prioritized conflicts, feedback/drift scores, and per-metric tuning
  deltas over a fixed synthetic corpus.
- Added focused unit, CLI, API, scenario, pack, schema, Web, and reference-lab
  tests plus updated architecture, detection, telemetry, security, scenario,
  contribution, roadmap, and lab documentation.

## 1.4.0 - 2026-08-02

- Added bounded multi-agent investigation reports with content-safe nodes,
  parent/caused-by/delegation/memory/data-lineage edges, per-trace summaries,
  prioritized findings, and root-to-finding evidence paths.
- Added delegation endpoint and principal-continuity invariants, cross-agent
  handoff checks, goal fingerprint/integrity checks, and shared-memory
  provenance/retention/lineage checks with operator remediation.
- Extended the canonical agent trace contract to 1.1 with optional structured
  delegation endpoint, identity binding, goal, and memory control fields plus
  agent-runtime and dotted semantic aliases.
- Added bounded `graph_path` and `graph_fanout` detection AST primitives and
  expanded the answer-key-free Agent Security Core pack from ten to twelve
  rules. The reference corpus detects nine rules with zero visibility gaps.
- Added four malicious/benign multi-agent campaign scenarios for delegation
  identity drift, shared-memory retention escape, cross-agent goal drift, and
  cascading trust fan-out, expanding the benchmark to thirty-three scenarios.
- Added a twenty-first disposable control and a longer three-agent reference
  trace with malicious and benign goal, delegation, memory, policy, and tool
  checkpoints. The benign twin passes every new invariant.
- Added `agentsim telemetry investigate`, a stable Python API, a public JSON
  schema, package/CI integration, and configurable investigation exit gates.
- Added an interactive Web investigation workbench with trace and severity
  filters, graph metrics, agent-aware causal checkpoints, click-highlighted
  evidence, reconstructed attack paths, and operator remediation.
- Made the hardened Docker reference lab's documented loopback API work on
  Docker Desktop while retaining localhost-only publication and fixed inputs.
- Updated the roadmap, architecture, telemetry, detection, scenario, security,
  contributor, reference-lab, and Web documentation for the v1.4 interfaces.

## 1.3.0 - 2026-08-02

- Added a telemetry-assurance doctor with `healthy`, `degraded`, and `unusable`
  outcomes, a 0–100 score, bounded remediation findings, and CI-configurable
  exit behavior.
- Added checks for invalid/substituted timestamps, missing or duplicate event
  IDs, incomplete/generated agent identity, unresolved and cross-trace causal
  links, causal time inversion, and accidental content-field exposure.
- Preserved multi-parent `caused_by_event_ids` through agent, OTel GenAI, and
  MCP normalization and recorded source timestamp/identity provenance without
  retaining raw sensitive values.
- Added a strict detection-pack contract, ten-rule built-in agent-security
  pack, and answer-key-free sweeps that distinguish `detected`,
  `not_detected`, and `visibility_gap`.
- Added stable Python and CLI entry points, three public JSON schemas, packaged
  built-in content, and dashboard assurance results over the disposable
  reference-agent corpus.
- Added explicit malicious/benign MCP authorization checkpoints for audience,
  resource, scopes, and per-client consent, closing the two default-pack
  visibility gaps in the reference corpus.
- Added a versioned README roadmap centered on multi-agent graph analytics,
  detection feedback and schema mapping, signed community content, and stable
  defensive evidence contracts while reaffirming exploitation/C2 non-goals.

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
