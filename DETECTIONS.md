# AgentSim Detection Engineering Guide

These experimental detections target behavioral telemetry produced by
AgentSim. They are starting points, not production-ready controls. Field names,
process ancestry, event latency, and command-line visibility vary across data
sources.

MITRE ATT&CK® mappings describe the discovery behavior being simulated. A
mapping does not guarantee complete coverage of an ATT&CK technique.

## Data requirements

Collect process-creation events with, where available:

- event time and host/device identifier;
- process name, full command line, and process ID; and
- parent process name, command line, and process ID.

AgentSim does not forward events. Confirm that your EDR, audit policy, Sysmon,
or equivalent sensor records child processes created by Python and the shell.

## Included examples

### Cross-OS command hallucination (Sigma)

File: [`detections/sigma/llm_hallucination.yml`](detections/sigma/llm_hallucination.yml)

Detects a Windows command shell carrying common Unix discovery syntax, or a
POSIX shell carrying common Windows discovery syntax. This aligns with
AgentSim's hallucination-rate behavior.

Expected false positives include WSL, compatibility layers, shell tutorials,
build systems, and administrators intentionally testing cross-platform scripts.
Tune on parent process, user, host role, and known automation.

### Rapid cross-shell pivot (Microsoft Defender XDR KQL)

File: [`detections/kql/agent_pivot.kql`](detections/kql/agent_pivot.kql)

Finds a single initiating process that launches both CMD and PowerShell within
a ten-second window. This can identify the Windows retry/pivot behavior.

Software deployment, CI workers, configuration management, and administrative
wrappers commonly use both shells. Replace the example lookback and tune the
initiating-process filters for your environment.

### High-velocity discovery burst (Splunk SPL)

File: [`detections/splunk/velocity_recon.spl`](detections/splunk/velocity_recon.spl)

Counts distinct discovery command families launched by one parent process in a
five-second bucket. The example assumes CIM-style Endpoint.Processes fields and
contains an explicit index placeholder.

Tune the time bucket and distinct-command threshold for sensor batching and
normal automation. A five-second search bucket is not the same as an exact
sliding five-second window.

## Additional hunting ideas

### Nested shell execution

Look for Python spawning a shell that immediately launches a second shell with
discovery syntax. Parent/child/grandchild correlation is more robust than a
single command-line match. AgentSim's `--evasion-rate` produces this pattern,
but the behavior is not proof of successful EDR evasion.

### Multi-cloud probing

When `--allow-network` is enabled, one Python parent may rapidly launch more
than one of `aws`, `az`, and `gcloud`. Correlate process events with cloud audit
logs and require two or more distinct CLI families to reduce noise.

### Context-loss bursts

Repeated `whoami` executions followed by several different discovery commands
from the same Python parent can indicate AgentSim's context-loss behavior. This
pattern is also common in health checks and scripted diagnostics, so baseline
the parent executable and service account.

## Validation workflow

1. Run `python core.py --dry-run --seed 42` to review the planned commands.
2. Use an authorized test endpoint with the required process telemetry enabled.
3. Run a short local simulation without `--allow-network`.
4. Confirm raw events contain the required ancestry and command-line fields.
5. Run the query, record misses, then tune field mappings and thresholds.
6. Test known administrative automation before enabling any alert.

Do not use `--allow-network` solely to test local process detections; dry-run
shows cloud selections, and local cloud CLI process creation should be performed
only with explicit authorization.

## ATT&CK references

The current command catalog uses ATT&CK Enterprise v19.1 mappings. Relevant
official technique pages include:

- [System Information Discovery (T1082)](https://attack.mitre.org/techniques/T1082/)
- [System Owner/User Discovery (T1033)](https://attack.mitre.org/techniques/T1033/)
- [Local Account Discovery (T1087.001)](https://attack.mitre.org/techniques/T1087/001/)
- [Process Discovery (T1057)](https://attack.mitre.org/techniques/T1057/)
- [Local Groups Discovery (T1069.001)](https://attack.mitre.org/techniques/T1069/001/)
- [System Network Connections Discovery (T1049)](https://attack.mitre.org/techniques/T1049/)
- [System Network Configuration Discovery (T1016)](https://attack.mitre.org/techniques/T1016/)
- [Cloud Service Discovery (T1526)](https://attack.mitre.org/techniques/T1526/)
