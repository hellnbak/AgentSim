# AgentSim reference-agent lab

This disposable service exercises AgentSim's fixed synthetic tools and policy
checkpoints over loopback HTTP. It never executes a host command, reads a host
file, opens an outbound connection, or accepts a prompt, token, payload, or
arbitrary tool definition.

MCP fixtures emit a separate `mcp.authorization.checked` checkpoint with fixed
synthetic client/server IDs, audience, resource, bounded scopes, audience
validity, and per-client-consent validity. Malicious and benign twins exercise
both failing and passing authorization outcomes without accepting a token.

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

The container is read-only, drops all Linux capabilities, uses a private
Docker network, publishes only to host loopback, and resets its in-memory state
after every request. Stop it with `docker compose down`.
