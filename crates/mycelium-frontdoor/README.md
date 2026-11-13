# mycelium-frontdoor

A small loopback HTTP frontdoor for stable `*.myc` service names.

It does not own DNS and it does not own service discovery. Those stay with
Mycelium and the host resolver. The frontdoor owns the narrow piece a Spore
cannot: binding a listener, authenticating local callers, and forwarding by
`Host`.

```text
app / Soil Spore
  -> https://ai.myc
  -> host-owned :443 socket (launchd/systemd)
  -> mycelium-https-forwarder
  -> mycelium-frontdoor :8443 (TLS)
  -> configured route (local Bifrost, MCP bridge, Soil launcher, ...)
```

The frontdoor terminates TLS when given `--tls-cert` and `--tls-key`. The privileged
socket stays with the service manager: `mycelium-https-forwarder` accepts the
`443` socket and forwards raw bytes to the frontdoor on loopback `8443`. It has no
keys and cannot authorize requests, so certificate custody remains with the
frontdoor process.

Routes are a deliberately small table, loaded from JSON and hot-reloaded when
the file changes:

```json
{
  "mycelium_bin": "/Users/example/.local/bin/mycelium",
  "service_refresh_secs": 15,
  "default_route": "ai",
  "routes": [
    {
      "name": "ai",
      "hosts": ["ai.myc"],
      "upstream": ["http://127.0.0.1:4001", "https://ai.fpl.dev"],
      "service_kind": "ai",
      "remote_token_file": "/Users/example/.fpl/bifrost-api-key",
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

`upstream` accepts one URL or an ordered list. The frontdoor does not trust the
written order to describe locality: it derives candidates from the addresses
and the service catalog.

The most specific `Host` wins: an exact `ai.myc` route beats `*.myc`, then
`priority` breaks ties, then route name. `default_route` is the fallback when no
host pattern matches.

### Local-first service discovery

Candidates are tried in one order, derived rather than configured:

1. this machine: loopback `upstream` entries;
2. this mesh: fresh service endpoints owned by this node, then other nodes;
3. the public edge: non-loopback `upstream` entries, in written order.

With `service_kind` set, the frontdoor refreshes the authenticated Mycelium service
catalog every `service_refresh_secs`. Only connection failures advance to the
next candidate. A timeout or an HTTP response does not retry, because replaying a
non-idempotent request could duplicate work. Remote loopback hints are ignored; a
peer's `127.0.0.1` is not this host. `mycelium_bin` is required for any route
with `service_kind`.

### Credentials per target

- loopback candidates — the caller's `Authorization` is forwarded unchanged;
- configured non-loopback `upstream` entries — the caller's `Authorization` is
  forwarded, unless the route sets `remote_token_env` or `remote_token_file`, in
  which case that credential replaces it;
- discovered peers — only the configured remote credential is sent. A peer never
  receives a credential minted for this host, and a discovered peer is skipped
  with a log line when no remote credential is configured.

`remote_token_file` reads the token at request time, so rotating the file does
not need a frontdoor restart and the secret never has to appear in a launchd plist
or systemd unit.

### Token accounting

The frontdoor is the one hop every client shares, so it is where tokens are
counted. For completion requests it reads the OpenAI `usage` object from the JSON
body or from the final SSE event. A streaming request that did not ask for usage
gets `stream_options.include_usage` added, unless the client set the field
explicitly or `metering.stream_usage` is `false`.

Counters are kept per route and per model, plus a rolling 60-second window for
throughput. Requests whose upstream reports no usage are counted as **unmetered**
rather than estimated: an estimate that looks exact is worse than a visible gap.

```sh
curl -sk https://ai.myc/.mycelium/usage   # JSON snapshot
curl -sk https://ai.myc/.mycelium/metrics # Prometheus text
mycelium frontdoor usage [--json]
mycelium frontdoor usage --fleet [--json]
```

With `--usage PATH`, the frontdoor persists the counters (schema
`mycelium.frontdoor-usage.v1`) and `myceliumd` republishes them in gossiped
`platform_metrics` as `mycelium_ai.*`. `mycelium frontdoor usage --fleet` sums the
fresh snapshots each peer reports. A stale snapshot is not gossiped, so a stopped
frontdoor disappears from the fleet total instead of looking idle. One request
traverses one frontdoor; do not chain `.myc` frontdoors or the same tokens are counted
twice.

`/healthz` reports the route count, discovered endpoint count, local node id,
auth requirement, and whether stream metering is on.

Run it on a nonprivileged port for development:

```sh
cargo run -p mycelium-frontdoor -- --listen 127.0.0.1:8080 \
  --routes crates/mycelium-frontdoor/examples/routes.json
```

### HTTPS ingress

The CLI owns the normal local setup:

```sh
mycelium frontdoor install --write --trust-cert
mycelium frontdoor status
mycelium doctor
```

`frontdoor install` writes a local CA and leaf certificate (or retains an
existing certificate pair), installs the default capability routes, copies the
frontdoor/forwarder binaries under `$MYCELIUM_HOME/bin`, and installs the host
services: two LaunchAgents on macOS, a frontdoor service plus a socket-activated
forwarder on Linux. `--trust-cert` adds the issuing CA to the login keychain on
macOS or the system CA store on Linux; it is deliberately explicit because it
changes the host's trust settings. `mycelium setup --local-frontdoor
--trust-cert` runs the same installation after enrollment. `mycelium doctor
--fix --trust-cert` repairs an existing installation, and plain `mycelium
doctor` exits non-zero when a check fails so it can gate scripts.

Linux units live in `/etc/systemd/system`: `mycelium-frontdoor.service`,
`mycelium-https.socket`, and `mycelium-https.service`. Installing them needs
passwordless sudo (the CLI uses `sudo -n` and fails loudly otherwise). Use
`--listen 127.0.0.1:PORT` when another service already owns the default
frontdoor port; the installed unit is the source of truth, so later reinstalls
keep that address.

`frontdoor install` refuses to start when the configured frontdoor address or
`:443` is already held by a different process, so a leftover system LaunchDaemon
or another service is reported instead of being silently duplicated. `frontdoor
uninstall` removes only the Mycelium user agents/systemd units and the Linux CA
entry; it never touches `/Library/LaunchDaemons` or unrelated units.

The frontdoor does not manage DNS. Hosts that do not already resolve `.myc`
wildcards locally need bootstrap entries (for example
`127.0.0.1 ai.myc api.myc mcp.myc home.myc webhook.myc store.myc` in
`/etc/hosts`) until the Mycelium DNS resolver owns the zone.

For a custom certificate or route table, use the installer flags directly:

```sh
mycelium frontdoor install --write \
  --routes /path/to/routes.json \
  --cert /path/to/server.pem \
  --key /path/to/server-key.pem \
  --trust-cert
```

The certificate must cover every `Host` the frontdoor serves (`ai.myc`,
`home.myc`, a wildcard such as `*.myc`, or an explicit SAN list). The browser
trust decision is separate from frontdoor authorization; trust the issuing CA in
the browser keychain if the certificate is not publicly trusted. On Linux,
`--trust-cert` installs `/usr/local/share/ca-certificates/mycelium-frontdoor.crt`
and runs `update-ca-certificates`; browsers that use their own NSS store may
still need the CA imported separately.

For development, run the frontdoor directly on a nonprivileged port:

```sh
mycelium-frontdoor --listen 127.0.0.1:8443 \
  --routes "$HOME/.mycelium/frontdoor/routes.json" \
  --tls-cert "$HOME/.mycelium/frontdoor/server.pem" \
  --tls-key "$HOME/.mycelium/frontdoor/server-key.pem"
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
127.0.0.1:8443`; keep the frontdoor itself in a separate agent or supervisor on
`127.0.0.1:8443`. No root process is required, and the frontdoor does not run with
privileged socket ownership. The same split works with a systemd socket unit on
Linux.

Binding `:443` directly in the frontdoor would require a privileged supervisor and
is not the intended deployment. Use the socket-activated forwarder so the
listener and the process holding TLS keys have different privileges.

For `:80`, run `mycelium-http-redirect` as the socket-activated agent on the
`HTTP` socket. It answers every request with `301 Moved Permanently` to the same
`https://` URL and never proxies a request body:

```xml
<key>Sockets</key><dict><key>HTTP</key><dict>
  <key>SockNodeName</key><string>127.0.0.1</string>
  <key>SockServiceName</key><integer>80</integer>
  <key>SockFamily</key><string>IPv4</string>
  <key>SockType</key><string>stream</string>
  <key>SockProtocol</key><string>TCP</string>
</dict></dict>
```

Point its `ProgramArguments` at `mycelium-http-redirect`; it activates the
socket named `HTTP` and needs no privileged listener of its own. This listener
is intentionally TLS-only in the other direction: a plaintext request either
moves to HTTPS or fails, and no request is forwarded over plaintext.

Use a bearer token for local callers:

```sh
printf '%s\n' "$LOCAL_TOKEN" > "$HOME/.config/mycelium/frontdoor.token"
cargo run -p mycelium-frontdoor -- --listen 127.0.0.1:8080 \
  --routes crates/mycelium-frontdoor/examples/routes.json \
  --token-file "$HOME/.config/mycelium/frontdoor.token"
```

Then every request must send `Authorization: Bearer $LOCAL_TOKEN`. `/healthz`
is intentionally unauthenticated so a supervisor can check liveness without
holding the caller token.

For the local static upstream, the frontdoor authenticates the caller and
forwards `Authorization` unchanged. Point it at a service that accepts the same
token (for example the Bifrost local key), or use `remote_token_file` to hold the
edge credential.

Requests and responses are proxied, not replayed. Response bodies are streamed,
so SSE chat completions arrive incrementally, except that successful
non-streaming completion responses are buffered (bounded at 32 MiB) to read their
`usage` object. Request bodies are bounded at 32 MiB. HTTP Upgrade/WebSocket
traffic is not proxied yet. `x-forwarded-proto` reports `https` on the TLS
listener.

The frontdoor binds one address. Binding `:443` belongs to the
Spore/Confluence ingress layer: the service manager owns the privileged socket,
`mycelium-https-forwarder` moves raw bytes, and the frontdoor terminates TLS on a
loopback port. `:80` is a redirect-only listener (`mycelium-http-redirect`), so
it never carries a request body or a credential. This keeps both privileged
listeners free of certificates and request authorization.

## Current scope

This slice uses a static JSON route file. Mycelium service records are the
intended source for that file: the route table is the narrow handoff point, and
a service-discovery reconciler can regenerate it without granting Spores a
listening socket. Service-record reconciliation and Palisade-backed caller
identity are follow-ups. TLS termination and the host-owned HTTPS forwarder are
implemented here.
