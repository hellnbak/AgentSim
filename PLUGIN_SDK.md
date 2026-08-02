# Plugin SDK 1.0

AgentSim v1 exposes stable entry-point contracts for functionality that should
not be built into or implicitly trusted by the public core.

## Entry-point groups

| Kind | Group | Required method |
| --- | --- | --- |
| Collector | `agentsim.collectors` | `collect(source)` |
| Detection renderer | `agentsim.detection_renderers` | `render(candidate)` |
| External executor | `agentsim.external_executors` | `execute(plan)` |

Every plugin object must expose `api_version = "1.0"`.

Example project metadata:

```toml
[project.entry-points."agentsim.collectors"]
example = "example_agentsim_plugin:ExampleCollector"
```

Example collector:

```python
class ExampleCollector:
    api_version = "1.0"

    def collect(self, source):
        # Return an iterable of agentsim.models.NormalizedEvent.
        # Do not include prompts, tokens, credentials, secrets, or payloads.
        return ()
```

## Discovery and loading

```bash
agentsim plugin list
```

Discovery reads package entry-point metadata and returns name, kind, import
target, distribution, and version. It deliberately does not import plugin code.

Python callers may explicitly load a reviewed plugin:

```python
from agentsim.plugins import load_plugin

collector = load_plugin("collector", "example")
```

Loading third-party code is a trust decision. AgentSim checks only that exactly
one named entry point exists and that the loaded object declares API version
`1.0`.

## Compatibility policy

- The `1.x` AgentSim line preserves API `1.0` protocol method names and entry
  point groups.
- New optional behavior may be added without changing the API version.
- A breaking method or data-contract change requires a new plugin API version.
- Plugin distribution version and external tool version are separate. External
  executors must validate both.

## Security requirements

Collectors must be read-only, bounded, and redact sensitive content before
returning events. Renderers must treat candidates as data and must not deploy
them. External executors must independently enforce authorization, target
scope, version pins, cleanup, resource policy, audit evidence, and secret
redaction. No plugin may claim built-in AgentSim trust or signing identity.
