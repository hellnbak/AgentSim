# Security Policy

## Supported versions

AgentSim is currently pre-1.0. Security fixes are applied to the latest version
on the default branch.

| Version | Supported |
| --- | --- |
| Latest `0.2.x` | Yes |
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

AgentSim intentionally creates child processes and runs discovery commands.
Unexpected command execution, bypass of the network opt-in, shell injection,
exposure of captured command output, or remote access to the local Web UI should
be treated as security issues.

Agentic scenario mode has a stricter contract: it must never invoke a tool,
read a real file or credential, or open a network connection. All resources,
tool definitions, endpoints, results, and hashes in scenario artifacts must be
synthetic. A regression that violates this contract is a security issue.
