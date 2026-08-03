# Security Policy

## Supported versions

Security fixes are applied to the latest v1 release on the default branch.

| Version | Supported |
| --- | --- |
| Latest `1.x` | Yes |
| `0.x` and older snapshots | No |

## Reporting a vulnerability

Use the repository host's private vulnerability-reporting feature when it is
available. Include the affected version, reproduction steps, impact, and any
suggested mitigation.

If private reporting is unavailable, open a public issue asking the maintainers
for a private contact channel, but do not include vulnerability details or
sensitive system output in that issue.

Please allow maintainers a reasonable opportunity to investigate and publish a
fix before public disclosure. You can expect acknowledgement within seven days
and a status update after the initial assessment.

## Operational safety

AgentSim is simulation-first. Local or Docker providers may create child
processes only after an explicit mode, allowlisted target, and unexpired
authorization manifest are supplied. Unexpected command execution, policy
bypass, target-scope bypass, shell injection, cleanup failure, exposure of
captured output, or remote access to the local Web UI should be treated as
security issues.

Ability and campaign content is untrusted input. Ability files must only
reference reviewed `catalog://` commands; campaign files must only reference
abilities. A parser accepting embedded commands, scripts, payloads, downloads,
or arbitrary interpolation is a security issue.

The lab-artifact reference contract must not weaken that parser boundary. It
may identify an immutable local file under an explicit lab root and verify
provenance, path, SHA-256, size, type, platform, and non-execution controls.
Traversal, symlinks, path escape, substitutions, returned artifact bytes, or
execution by the public core are security issues. A future payload-capable
executor must remain separately reviewed and must independently enforce an
exact disposable target, lab-only authority, preflight controls, resource
limits, and cleanup/evidence. Inline bytes, URLs, downloads, shell fragments,
unpinned artifacts, credential material, and production targets remain invalid.

The safety engine must fail closed for expired authority, unallowlisted targets
or abilities, wildcard target scope, production lockout, elevation, network
policy, process/action/time limits, and missing cleanup. Cleanup must be
attempted after preparation or execution failure. Lifecycle evidence must not
contain raw command output, tokens, prompts, secrets, or sensitive payloads.

Agentic scenario mode has a stricter contract: it must never invoke a tool,
read a real file or credential, or open a network connection. All resources,
tool definitions, endpoints, results, and hashes in scenario artifacts must be
synthetic. A regression that violates this contract is a security issue.

Custom scenario packs are untrusted input. Their validation must remain
fail-closed for non-synthetic resource identifiers, executable action events,
token or payload recording, detector label leakage, and malicious/benign
control separation. The MCP lab must remain transport-free, use only fixed
synthetic authorization facts, and never accept or store a real bearer token.

Offline telemetry exports are untrusted input. Collector size/record bounds,
sensitive-field redaction, non-executable detection AST parsing, regex limits,
and bounded evidence must remain fail closed. Report any path that evaluates
telemetry as code, records sensitive field values, or silently contacts a
vendor as a security issue.

Detection packs are also untrusted input. They must remain bounded declarative
data, declare every field used by a rule, reject duplicate identifiers and
scenario answer keys, and never import code or deploy vendor rules. Telemetry
assurance must not retain raw invalid timestamps or content-bearing values, and
must report—rather than hide—generated identities, broken causal links, and
redaction-boundary violations.

Portable OTel/ECS/OCSF records are untrusted input. Profile pins, record-size
limits, content redaction, native-versus-extension separation, and
cross-runtime invariant checks must fail closed. Mapping an AgentSim-only field
into an invented standard-native field, silently dropping a required security
invariant, or accepting content-bearing extensions is a security issue.

Multi-agent investigation accepts at most 5,000 normalized events and must
traverse only explicit content-safe record identifiers. Graph construction,
invariant evidence, Web rendering, and report export must never retain prompt,
message, argument, result, response, token, credential, or payload values.
Cross-trace causal edges are rejected. A change that permits unbounded graph
depth, evaluates telemetry as code, hides a failed identity/goal/memory
invariant, or renders untrusted HTML is a security issue.

`graph_path` and `graph_fanout` are declarative detection expressions. Their
link fields and depth must remain bounded, their traversal must stay inside the
rule grouping boundary, and detection-pack field declarations must cover every
link and distinct-entity field.

Detection feedback bundles are untrusted input. They must accept only bounded
alerts and enumerated structured annotations, reject unknown/free-form fields,
require stable identifiers, and never retain prompt, message, argument,
response, result, credential, token, payload, or analyst narrative content.
An unresolved or contradictory annotation, evidence-digest mismatch,
agent-authored final verdict, trace disagreement, or high-risk trace dismissal
must be reported rather than silently used for tuning.

Detection drift is offline and advisory. Snapshot counts and thresholds must be
validated and bounded; a comparison must never deploy, promote, suppress,
update, or delete a vendor rule. Any path from a feedback or drift report to
automatic production detection mutation is outside AgentSim's security model
and should be treated as a security issue.

Flight bundles and OTLP JSON are untrusted input. Event, request, attribute,
counter, identifier, and file-size limits; strict fields; digest validation;
and content-key redaction must remain fail closed. Runtime processors must not
call a general span export method or raise into the application. The OTLP
receiver must remain loopback-only with explicit opt-in and no outbound path.
Synthetic twins must pseudonymize identity fields and remain non-executing.

Detection CI must use explicit malicious, benign, or unknown ground truth and
must not infer it from a detector result. Reports may block a merge but cannot
change an agent, deploy a rule, suppress an alert, or mutate vendor state.

Live telemetry connectors are read-only query clients and are disabled until
both execution and network access are explicitly enabled. Wildcard datasets or
targets, windows over 24 hours, limits over 10,000 records, responses over 32
MiB, remote plaintext HTTP, redirects, URL credentials, and credentials not
provided through the named environment variable must fail closed. Connector
plans and SQLite audits must never contain a credential value or authorization
header. Creating or modifying vendor content is outside the connector scope.

The reference-agent HTTP lab is synthetic-only. Host loopback requires an
explicit opt-in, and non-loopback binding requires the disposable-container
guard. Its request accepts only a fixture ID; it must never accept prompts,
tool definitions, arguments, tokens, credentials, or arbitrary code. A host
process, filesystem change, outbound network request, external tool call, or
failure to reset state is a security issue.

Release-foundation ability, campaign, and command content is RSA-signed.
Checksum-only preview packs must be visibly labeled, simulation-only, network
denied, production locked, and state-change free. Signature bypass, trust-store
substitution, acceptance of an untrusted key ID, or a content change that
preserves verification is a security issue. The release private key must never
be committed or distributed with a package.

Community packs additionally require strict provenance and an explicitly
trusted public key. Provenance must pin an HTTPS repository, immutable
revision, repository-relative source path, authorship, license, reviewer,
review timestamp, and policy. Provenance is covered by the signature. External
trust stores may add but never replace built-in key IDs. Approval without all
checksum, signature, provenance, structure, and safety checks is a security
issue. Review must not import code, retain uploaded content, or resolve an
executable command.

External adapters in the public core must remain non-executing. They may create
typed, version-pinned plans but must not start tools, send CALDERA requests,
load credentials, or install dependencies. Third-party plugins are trusted
code only after explicit loading; plugin discovery must not import them.
