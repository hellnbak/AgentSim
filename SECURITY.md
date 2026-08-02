# Security Policy

## Supported versions

AgentSim is currently pre-1.0. Security fixes are applied to the latest version
on the default branch.

| Version | Supported |
| --- | --- |
| Latest `0.4.x` | Yes |
| Older snapshots | No |

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
