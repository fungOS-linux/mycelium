# mycelium-gateway

A small loopback HTTP gateway for stable `*.myc` service names.

It does not own DNS and it does not own service discovery. Those stay with
Mycelium and the host resolver. The gateway owns the narrow piece a Spore
cannot: binding a listener, authenticating local callers, and forwarding by
`Host`.

```text
app / Soil Spore
  -> http://ai.myc:8080
  -> mycelium-gateway
  -> configured route (local Bifrost, MCP bridge, Soil launcher, ...)
```

Routes are a deliberately small table, loaded from JSON and hot-reloaded when
the file changes:

```json
{
  "default_route": "bifrost",
  "routes": [
    {
      "name": "bifrost",
      "hosts": ["*"],
      "upstream": "http://127.0.0.1:4000",
      "priority": 0
    },
    {
      "name": "mcp",
      "hosts": ["mcp.myc"],
      "upstream": "http://127.0.0.1:8000",
      "priority": 10
    }
  ]
}
```

The most specific `Host` wins: an exact `ai.myc` route beats `*.myc`, then
`priority` breaks ties, then route name. `default_route` is the fallback when no
host pattern matches.

Run it on a nonprivileged port for development:

```sh
cargo run -p mycelium-gateway -- --listen 127.0.0.1:8080 \
  --routes crates/mycelium-gateway/examples/routes.json
```

Use a bearer token for local callers:

```sh
printf '%s\n' "$LOCAL_TOKEN" > "$HOME/.config/mycelium/gateway.token"
cargo run -p mycelium-gateway -- --listen 127.0.0.1:8080 \
  --routes crates/mycelium-gateway/examples/routes.json \
  --token-file "$HOME/.config/mycelium/gateway.token"
```

Then every request must send `Authorization: Bearer $LOCAL_TOKEN`. `/healthz`
is intentionally unauthenticated so a supervisor can check liveness without
holding the caller token.

The gateway authenticates the caller and forwards `Authorization` unchanged.
Point it at a service that accepts the same token (for example the Bifrost local
key), or put credential injection in the layer that owns the upstream secret.

Requests and responses are proxied, not replayed. Response bodies are streamed,
so SSE chat completions arrive incrementally. Request bodies are bounded at
32 MiB. HTTP Upgrade/WebSocket traffic is not proxied yet.

The gateway binds one address and does not terminate TLS. Binding `:80` or
`:443` requires a privileged supervisor; that belongs to the Spore/Confluence
ingress layer, not to an application process. Ingress should terminate TLS and
forward plain HTTP to this loopback listener.

## Current scope

This slice uses a static JSON route file. Mycelium service records are the
intended source for that file: the route table is the narrow handoff point, and
a service-discovery reconciler can regenerate it without granting Spores a
listening socket. Service-record reconciliation, TLS termination, and
Palisade-backed caller identity are follow-ups, not implemented here.
