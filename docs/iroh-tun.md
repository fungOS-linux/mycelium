# The daemon-owned L3 tunnel

`iroh-tun` is a userspace IP-over-iroh tunnel: one IP packet per QUIC datagram,
identity is an iroh endpoint id, and routes are learned from the service catalog.
The process is small and stateless; **myceliumd owns it**.

Registration is a daemon responsibility, not a client one. The catalog and the
observation lease are both daemon state. A client that registers itself leaves a
stale observation until its TTL when it crashes, and the node then looks alive
while routing nowhere. So the daemon keeps the key, spawns the child, restarts
it, and publishes an observation that expires on its own if the daemon stops.

## The split

| the daemon owns | the child owns |
|---|---|
| identity (key file), claimed overlay prefixes | the route table it actually learned |
| the process lifetime and its restart policy | the tun device and the iroh endpoint |
| the published observation and its expiry | the catalog beat and its failure count |

Nothing is published unless both agree. The daemon's claim is a function of
(config, child alive, status fresh); the child's evidence is the status document
it writes every beat. A wedged child disappears from the catalog instead of
lingering as a route to nowhere.

## Files

| path | what |
|---|---|
| `~/.mycelium/iroh-tun.json` | config; the file's existence is the enable switch |
| `~/.mycelium/iroh-tun.key` | 64 hex characters, 0600, created on first enable |
| `~/.mycelium/iroh-tun-status.json` | the child's own report, rewritten every beat |
| `~/.mycelium/iroh-tun.log` | child stdout/stderr; the last line is the exit reason |

Config is re-read on every supervisor tick, so `mycelium iroh-tun config --write`
takes effect without restarting the daemon. A config that cannot be parsed stops
the tunnel and is reported by `doctor`; running a tunnel the file contradicts
would be worse than being down.

```json
{
  "tun": "utun220",
  "mtu": 1280,
  "overlay": ["10.42.0.0/24"],
  "refresh_secs": 15,
  "listen": "192.0.2.10:4400"
}
```

`overlay` is what this node answers for, as peers see it: prefixes are masked,
deduplicated and sorted, and a default route (`0.0.0.0/0`) is refused because a
claim about every address is not a claim about one node. Empty is legal — a
client-only node reaches the overlay and advertises nothing, which is how the
first node in a fleet bootstraps.

`binary` and `mycelium_binary` default to siblings of the daemon binary, then to
`PATH`. The child needs the `mycelium` CLI to read the catalog: without it the
child exits at startup with the reason in the log, rather than running blind.

## What peers see

One observation, kind `iroh-tun`, published through the same signed topology
gossip as every other service:

```json
{
  "kind": "iroh-tun",
  "endpoints": ["iroh://<endpoint-id>"],
  "protocols": ["quic"],
  "attributes": {
    "node_id": "neo",
    "endpoint_id": "<endpoint-id>",
    "overlay": "10.42.0.0/24,192.168.10.0/24",
    "tun": "utun220",
    "mtu": "1280",
    "routes": "2",
    "refresh_failures": "0",
    "addresses": "192.0.2.10:4400"
  }
}
```

`addresses` is only ever a specific socket address; a wildcard bind is not a
hint and is omitted. Consumers build `prefix -> endpoint id` routes from
`attributes.overlay`; `iroh-tun` itself reads exactly this shape from
`mycelium services --json`.

The lease is 60 seconds and is renewed every 30. A daemon that stops renewing
stops being on the overlay, and peers drop the route without a retraction.

## Runbook

```bash
mycelium iroh-tun config --tun utun220 --overlay 10.42.0.0/24 --write
mycelium iroh-tun status          # identity, what it claims, what it learned
mycelium doctor                   # is the kind published; does the tunnel route
mycelium doctor --fix             # bounce a configured tunnel that is not working
```

`doctor` asks two questions that `ifconfig` cannot answer: whether the local node
publishes the `iroh-tun` kind, and whether the tunnel has learned at least one
peer prefix. A device that exists with no peers looks identical to a healthy one
from the outside. "No peers yet" is a warning, not a failure: the first node on
an overlay has nobody to learn from and has to run before a second node can
exist.

## Not yet implemented

- **Kernel route installation.** The child learns prefixes and reports them; it
does not add routes to the host. Until that lands, an operator adds the peer
prefixes to the tun by hand, and the status document describes the tunnel's table
rather than the kernel's.
- **Privilege split.** The whole process holds the tun fd. The intended shape is
a small privileged helper that owns only the device.

The child already refuses oversize packets with a checksummed ICMP
fragmentation-needed notice (rather than dropping them silently) and drops any
packet whose source does not match a prefix owned by the sending peer; both have
unit tests in `iroh-tun`.
