# mycelium-gateway

A small loopback HTTP gateway for stable `*.myc` service names.

It does not own DNS and it does not own service discovery. Those stay with
Mycelium and the host resolver. The gateway owns the narrow piece a Spore
cannot: binding a listener, authenticating local callers, and forwarding by
`Host`.

```text
app / Soil Spore
  -> https://ai.myc
  -> host-owned :443 socket (launchd/systemd)
  -> mycelium-https-forwarder
  -> mycelium-gateway :8443 (TLS)
  -> configured route (local Bifrost, MCP bridge, Soil launcher, ...)
```

The gateway terminates TLS when given `--tls-cert` and `--tls-key`. The privileged
socket stays with the service manager: `mycelium-https-forwarder` accepts the
`443` socket and forwards raw bytes to the gateway on loopback `8443`. It has no
keys and cannot authorize requests, so certificate custody remains with the
gateway process.

Routes are a deliberately small table, loaded from JSON and hot-reloaded when
the file changes:

```json
{
  "mycelium_bin": "/Users/example/.local/bin/mycelium",
  "service_refresh_secs": 15,
  "default_route": "bifrost",
  "routes": [
    {
      "name": "bifrost",
      "hosts": ["ai.myc"],
      "upstream": "http://127.0.0.1:4001",
      "service_kind": "ai",
      "priority": 10
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

### Local-first service discovery

`upstream` is the local backend and is always tried first. When `service_kind`
is set, the gateway refreshes the authenticated Mycelium service catalog every
`service_refresh_secs` and appends matching endpoints:

1. the static local `upstream`;
2. fresh service endpoints owned by this node;
3. fresh endpoints owned by other nodes.

Only connection failures advance to the next candidate. A timeout or an
HTTP response does not retry, because replaying a non-idempotent request could
duplicate work. Remote loopback hints are ignored; a peer's `127.0.0.1` is not
this host. `mycelium_bin` is required for any route with `service_kind`.

The caller's bearer token is forwarded only to the local static upstream and
local service endpoints. A remote candidate is unauthenticated unless the
route sets `remote_token_env`, which names an environment variable holding the
remote bearer token. This keeps the local app key from leaking to peers.

`/healthz` reports the route count, discovered endpoint count, local node id,
and whether auth is required.

Run it on a nonprivileged port for development:

```sh
cargo run -p mycelium-gateway -- --listen 127.0.0.1:8080 \
  --routes crates/mycelium-gateway/examples/routes.json
```

### HTTPS ingress

The CLI owns the normal local setup:

```sh
mycelium gateway install --write --trust-cert
mycelium gateway status
mycelium doctor
```

`gateway install` writes a local CA and leaf certificate (or retains an
existing certificate pair), installs the default capability routes, copies the
gateway/forwarder binaries under `$MYCELIUM_HOME/bin`, and installs the host
services: two LaunchAgents on macOS, a gateway service plus a socket-activated
forwarder on Linux. `--trust-cert` adds the issuing CA to the login keychain on
macOS or the system CA store on Linux; it is deliberately explicit because it
changes the host's trust settings. `mycelium setup --local-gateway
--trust-cert` runs the same installation after enrollment. `mycelium doctor
--fix --trust-cert` repairs an existing installation, and plain `mycelium
doctor` exits non-zero when a check fails so it can gate scripts.

Linux units live in `/etc/systemd/system`: `mycelium-gateway.service`,
`mycelium-https.socket`, and `mycelium-https.service`. Installing them needs
passwordless sudo (the CLI uses `sudo -n` and fails loudly otherwise). Use
`--listen 127.0.0.1:PORT` when another service already owns the default
gateway port; the installed unit is the source of truth, so later reinstalls
keep that address.

`gateway install` refuses to start when the configured gateway address or
`:443` is already held by a different process, so a leftover system LaunchDaemon
or another service is reported instead of being silently duplicated. `gateway
uninstall` removes only the Mycelium user agents/systemd units and the Linux CA
entry; it never touches `/Library/LaunchDaemons` or unrelated units.

The gateway does not manage DNS. Hosts that do not already resolve `.myc`
wildcards locally need bootstrap entries (for example
`127.0.0.1 ai.myc api.myc mcp.myc home.myc webhook.myc` in `/etc/hosts`) until
the Mycelium DNS resolver owns the zone.

For a custom certificate or route table, use the installer flags directly:

```sh
mycelium gateway install --write \
  --routes /path/to/routes.json \
  --cert /path/to/server.pem \
  --key /path/to/server-key.pem \
  --trust-cert
```

The certificate must cover every `Host` the gateway serves (`ai.myc`,
`home.myc`, a wildcard such as `*.myc`, or an explicit SAN list). The browser
trust decision is separate from gateway authorization; trust the issuing CA in
the browser keychain if the certificate is not publicly trusted. On Linux,
`--trust-cert` installs `/usr/local/share/ca-certificates/mycelium-gateway.crt`
and runs `update-ca-certificates`; browsers that use their own NSS store may
still need the CA imported separately.

For development, run the gateway directly on a nonprivileged port:

```sh
mycelium-gateway --listen 127.0.0.1:8443 \
  --routes "$HOME/.mycelium/gateway/routes.json" \
  --tls-cert "$HOME/.mycelium/gateway/server.pem" \
  --tls-key "$HOME/.mycelium/gateway/server-key.pem"
```

On macOS, launchd can own `:443` for an unprivileged LaunchAgent. The agent is
started on the first connection and runs the forwarder as the logged-in user:

```xml
<key>Sockets</key><dict><key>HTTPS</key><dict>
  <key>SockNodeName</key><string>127.0.0.1</string>
  <key>SockServiceName</key><integer>443</integer>
  <key>SockFamily</key><string>IPv4</string>
  <key>SockType</key><string>stream</string>
  <key>SockProtocol</key><string>TCP</string>
</dict></dict>
```

Point its `ProgramArguments` at `mycelium-https-forwarder --target
127.0.0.1:8443`; keep the gateway itself in a separate agent or supervisor on
`127.0.0.1:8443`. No root process is required, and the gateway does not run with
privileged socket ownership. The same split works with a systemd socket unit on
Linux.

Binding `:443` directly in the gateway would require a privileged supervisor and
is not the intended deployment. Use the socket-activated forwarder so the
listener and the process holding TLS keys have different privileges.

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

For the local static upstream, the gateway authenticates the caller and
forwards `Authorization` unchanged. Point it at a service that accepts the same
token (for example the Bifrost local key), or put credential injection in the
layer that owns the upstream secret. Remote discovery candidates use
`remote_token_env` as described above.

Requests and responses are proxied, not replayed. Response bodies are streamed,
so SSE chat completions arrive incrementally. Request bodies are bounded at
32 MiB. HTTP Upgrade/WebSocket traffic is not proxied yet. `x-forwarded-proto`
reports `https` on the TLS listener.

The gateway binds one address. Binding `:80` or `:443` belongs to the
Spore/Confluence ingress layer: the service manager owns the privileged socket,
`mycelium-https-forwarder` moves raw bytes, and the gateway terminates TLS on a
loopback port. This keeps the privileged listener free of certificates and
request authorization.

## Current scope

This slice uses a static JSON route file. Mycelium service records are the
intended source for that file: the route table is the narrow handoff point, and
a service-discovery reconciler can regenerate it without granting Spores a
listening socket. Service-record reconciliation and Palisade-backed caller
identity are follow-ups. TLS termination and the host-owned HTTPS forwarder are
implemented here.
