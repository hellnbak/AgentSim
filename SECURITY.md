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

Built-in ability, campaign, and command content is RSA-signed. Signature
bypass, trust-store substitution, acceptance of an untrusted key ID, or a
content change that preserves verification is a security issue. The release
private key must never be committed or distributed with a package.

External adapters in the public core must remain non-executing. They may create
typed, version-pinned plans but must not start tools, send CALDERA requests,
load credentials, or install dependencies. Third-party plugins are trusted
code only after explicit loading; plugin discovery must not import them.
