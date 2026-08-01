# AgentSim

AgentSim is a small defensive testing tool that simulates the command-selection
patterns of an autonomous agent. It creates endpoint process telemetry for
detection engineering without using an LLM, exploitation code, credential
access, persistence, or lateral movement.

The simulator uses a randomized OODA-style loop and a static catalog of
read-only commands mapped to MITRE ATT&CK® Enterprise techniques. It supports
Windows, Linux, and macOS, includes a local Web dashboard, and exports a layer
for ATT&CK Navigator.

> [!CAUTION]
> AgentSim executes local operating-system commands by default. Run it only on
> systems you own or are explicitly authorized to test. Start with `--dry-run`
> and review [Scope and safety](#scope-and-safety) before generating telemetry.

## What it simulates

AgentSim models behavioral patterns that can help exercise detections:

- rapid, varied host-discovery commands;
- incorrect commands caused by losing track of the host OS;
- baseline discovery repeated after simulated context loss;
- retries and shell pivots after command errors;
- nested shell execution; and
- transitions from host discovery to privilege/network discovery and optional
  cloud service discovery.

It is a randomized state machine, not an LLM or an adversary-emulation
framework. It does not make decisions from command output beyond recognizing a
small set of error strings.

## Requirements

- Python 3.9 or newer
- No third-party dependencies for the CLI
- Flask 3.1 or newer for the Web UI

The target commands themselves vary by platform. Missing utilities are treated
as command failures, which is useful when testing retry behavior.

## Quick start

Clone or download the repository, then preview a deterministic run without
executing commands:

```bash
python core.py --dry-run --iterations 12 --seed 42
```

Run the local, read-only command set:

```bash
python core.py --iterations 20
```

The simulation writes `agent_sim_layer.json` in the current directory. Upload
that file to [ATT&CK Navigator](https://mitre.github.io/attack-navigator/enterprise/)
to inspect the selected techniques.

### Web UI

Create a virtual environment and install the Web dependency:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python web_ui.py
```

On Windows PowerShell, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

Open `http://127.0.0.1:5000`. The development server binds only to localhost.
The dashboard lets you tune the simulation, choose a seed, enable dry-run mode,
and explicitly opt in to cloud network actions.

You can also install the project and use console commands:

```bash
python -m pip install .
agentsim --dry-run
agentsim-web
```

## CLI options

| Option | Default | Description |
| --- | ---: | --- |
| `-i`, `--iterations` | `20` | Number of cycles; must be at least 1. |
| `--speed` | `100` | Delay between actions in milliseconds; may be 0. |
| `--hallucination-rate` | `0.15` | Chance of trying syntax from the wrong OS. |
| `--context-loss-rate` | `0.05` | Chance of re-running baseline discovery. |
| `--retry-rate` | `0.30` | Chance of retrying after an access error. |
| `--evasion-rate` | `0.10` | Chance of wrapping a command in nested shells. |
| `--dry-run` | off | Select and log commands without executing them. |
| `--allow-network` | off | Permit read-only cloud CLI requests. |
| `--seed` | random | Make command selection reproducible. |
| `--output` | `agent_sim_layer.json` | Navigator layer output path. |

All rate values must be between `0.0` and `1.0`.

## Simulation phases

1. **Host Discovery** — system information, current user, local accounts, and
   processes.
2. **Privilege and Network Discovery** — local groups, network connections, and
   network configuration.
3. **Cloud Service Discovery** — AWS, Azure, or Google Cloud CLI queries. Real
   execution is skipped unless `--allow-network` is supplied.

Runs with fewer than three iterations execute only the earliest phases. Longer
runs distribute cycles across all three phases in order.

## Scope and safety

- The trusted command catalog in [`tactics.py`](tactics.py) contains discovery
  commands only; it does not modify files, users, services, or network settings.
- Read-only does not mean impact-free. Discovery can expose sensitive system
  metadata to the local console and endpoint tooling, consume resources, or
  trigger security alerts.
- AgentSim captures command output in memory only to recognize errors. It does
  not print, persist, or transmit that output.
- Cloud commands are disabled by default. With `--allow-network`, installed
  cloud CLIs may make authenticated read-only API requests using the current
  user's configuration and credentials.
- AgentSim does not send telemetry to a SIEM or EDR. Your existing process
  monitoring must collect the child-process activity it creates.
- Nested-shell behavior is conspicuous simulation telemetry, not a claim that
  shell wrapping bypasses EDR controls.

For vulnerabilities in AgentSim itself, follow [`SECURITY.md`](SECURITY.md).

## Detection content

The [`detections/`](detections/) directory contains experimental examples for
Sigma, Microsoft Defender XDR KQL, and Splunk SPL. See
[`DETECTIONS.md`](DETECTIONS.md) for data requirements, limitations, and tuning
guidance. Validate the queries against your own schema before production use.

## Development

Run the test suite without executing the command catalog:

```bash
python -m unittest discover -s tests -v
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the command safety policy and pull
request checklist. Community expectations are in
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Project status

AgentSim is experimental defensive tooling. ATT&CK mappings and example
detections should be reviewed as the ATT&CK catalog and telemetry schemas
evolve.

## License and attribution

AgentSim is available under the [MIT License](LICENSE).

MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation.
AgentSim is not affiliated with, sponsored by, or endorsed by MITRE. See
[`NOTICE`](NOTICE) for the required ATT&CK attribution.
