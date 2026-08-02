# AgentSim reference-agent lab

This disposable service exercises AgentSim's fixed synthetic tools and policy
checkpoints over loopback HTTP. It never executes a host command, reads a host
file, opens an outbound connection, or accepts a prompt, token, payload, or
arbitrary tool definition.

MCP fixtures emit a separate `mcp.authorization.checked` checkpoint with fixed
synthetic client/server IDs, audience, resource, bounded scopes, audience
validity, and per-client-consent validity. Malicious and benign twins exercise
both failing and passing authorization outcomes without accepting a token.

The `multi-agent-delegation-cascade` fixture emits malicious and benign
eight-checkpoint graphs across orchestrator, research, and execution agents.
It covers bound goal fingerprints, two immutable delegation envelopes,
principal continuity, shared-memory provenance/retention, a synthetic tool
proposal, and policy outcome. The malicious proposal is denied; the benign
twin only changes the resettable in-memory dictionary.

Start the hardened container:

```sh
docker compose -f labs/reference-agent/compose.yaml up --build
```

Inspect its synthetic fixture catalog:

```sh
curl http://127.0.0.1:8765/fixtures
```

Run one malicious/benign control pair:

```sh
curl -X POST http://127.0.0.1:8765/run \
  -H 'Content-Type: application/json' \
  -d '{"fixture_id":"tool-definition-poisoning"}'
```

The container is read-only, drops all Linux capabilities, uses a
project-private bridge, publishes only to host loopback, and resets its
in-memory state after every request. The server has no outbound request path
and accepts only enumerated fixture IDs. Stop it with `docker compose down`.
