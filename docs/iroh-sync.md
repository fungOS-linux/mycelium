# Optional Iroh peer sync

Iroh can carry Mycelium's existing signed gossip between enrolled peers. It
does not carry Unibus traffic, grant access, enroll a new peer, or apply LAN
routes or WireGuard tunnels. TCP/mTLS remains available independently.

Build the optional CLI/daemon runtime:

```sh
cargo install --path crates/mycelium-cli --features iroh-sync --locked
```

On each already-enrolled peer, retain the existing `MYCELIUM_PEER_CA`,
`MYCELIUM_PEER_CERT`, and `MYCELIUM_PEER_KEY` settings. The TLS SAN this peer
advertises can come from `MYCELIUM_IROH_SERVER_NAME` in the daemon environment
or from `"server_name"` in `iroh-sync.json`; it must be a name/IP present in
**that peer's certificate SAN**. When both are set they must agree, otherwise
the daemon refuses to advertise a name its certificate does not carry.

The runtime uses UDP port 7444 for stable saved connection hints across restart;
`MYCELIUM_IROH_PORT` overrides it (zero/invalid values fail). IPv6 is used when
available. Cloud firewalls must allow this UDP port from intended sites or peers;
TCP 7443 permission alone is insufficient. Physical and overlay interfaces are
prioritized over container interfaces when public hints reach the 16-address
bound; excluded scoped link-local addresses are not remotely dialable.

```sh
mycelium sync enable --write --server-name peer.example
mycelium sync export --qr
```

The command applies the change to the running daemon: the Iroh transport is
rebuilt in place and the peer identity, the signed observation log, and the
TCP gossip path are untouched. No daemon stop/start cycle is needed. Export may
briefly fail until local address discovery completes. The QR contains public
connection hints and the TLS name; no private key, authority grant, SSH
permission, or enrollment secret is included.

Save the exported JSON (or scanned QR content) on the other enrolled peer:

```sh
mycelium sync join rendezvous.json --write
mycelium peers --json
mycelium scan
mycelium services --json
```

`join` also applies the seed to the running daemon. `mycelium sync status`
reports the effective state, and `mycelium sync reload` re-reads the
configuration on demand. `SIGHUP` to the daemon performs the same reload, so a
system-managed service can be reconfigured without a restart.

Rendezvous export expires after two minutes, refreshed every 30 seconds. Import
rejects expired/future data. Explicitly imported seeds persist across restarts;
their old addresses are connection hints, **not fresh availability evidence**.
Only one side needs an outgoing bootstrap seed. Once gossip connects, peers
publish signed, two-minute sync hints every 30 seconds. The runtime learns
fresh hints automatically and checks them against the owner's signed Iroh key
binding before dialing. Hints nominate a path, never membership or access.
For new peers, use the claim flow below. A disconnected new peer still needs
one bootstrap hint/claim; discovery cannot cross an entirely disconnected mesh.

## Automatic fallback

Authenticated TCP connections are preferred. Every five seconds, the Iroh
scheduler considers saved seeds and fresh learned hints for peers without a
live authenticated TCP connection. TCP dialing continues independently, so a
recovered direct route is retried without intervention. Existing healthy Iroh
streams are retained when TCP recovers, avoiding teardown/reconnect churn.
Silently stalled streams close after 45 seconds without a complete received
frame; blocked writes fail after 15 seconds. Connection cleanup releases the
TCP path count, allowing fallback even when the old socket never reported EOF.
Discovery adds at most two outgoing repair links, rather than an all-to-all
mesh. The runtime limits total outgoing tasks to 32 and retries failures with exponential
backoff capped at 60 seconds. Expired learned hints cannot start new dials;
saved bootstrap seeds retain their original, explicitly configured hints.

Within Iroh, direct QUIC paths and encrypted relay paths use the same peer
authentication. Direct-first is mandatory and explicit in configuration:
`iroh-sync.json` carries `"direct_first": true` (the default, and the only
value accepted by `validate()`). Iroh prefers a direct QUIC path whenever one
is reachable; a relay is used only when no direct path can be established.
Public relays remain disabled by default. Enable them explicitly on the
participating peers when NAT/firewalls prevent direct QUIC:

```sh
mycelium sync relays enable --write
```

The relay policy is applied to the running daemon immediately; no service
restart is required. Use `relays disable --write` to restore direct-only policy.
No public DNS record,
UPnP mapping, cloud firewall rule, WireGuard route, or ACL is changed. Removing
TCP access alone does not guarantee Iroh connectivity: direct UDP must work or
relay policy must be enabled. TLS SAN checks and both TLS/Iroh signed bindings
remain mandatory for Iroh, including relayed connections.

### What a relay operator can observe

Mycelium's signed gossip is end-to-end encrypted from Iroh endpoint to Iroh
endpoint (QUIC/TLS with inner mTLS), so a relay forwards ciphertext only. A
relay operator can observe **metadata**: the two endpoint ids (public iroh
keys), relay session timing and durations, packet sizes and counts, and the
relaying server's view of each endpoint's source IP/port. It cannot read
hardware, health, security, or bus payloads, and it cannot forge a peer
identity because the inner mTLS certificate and signed envelopes are verified
beyond the relay. Relayed connections are therefore a privacy downgrade in
metadata terms only, not a confidentiality one.

### Rollback to direct-only

```sh
mycelium sync relays disable --write   # sets public_relays=false, keeps seeds
```

That revokes the relay list: the runtime clears relay hints from every
rendezvous and refuses new relay dials, leaving direct QUIC (and authenticated
TCP) only. Existing direct connections are unaffected. To remove all Iroh
bootstrap state as well, restore `iroh-sync.json` from backup or delete it and
run `mycelium sync reload`; the transport key in `iroh-secret.key` may be
retained for a stable identity. Backups: `~/.mycelium/iroh-sync.json.bak-*`.

## Enroll a new peer using a QR claim

Both machines need the optional `iroh-sync` build. On an existing enrolled
authority with its enrollment CA and live Iroh sync runtime:

```sh
mycelium pair --kind peer --iroh --qr \
  --name new-peer --site your-site \
  --enrollment-ca "$HOME/.mycelium/authority" \
  --ttl 15m
```

Optional `--unix-user USER --role ROLE` uses the existing SSH invitation policy
and requires the authority's SSH CA (`--ca PATH`). A peer-only claim grants no
SSH access. No `--gateway`, OIDC login, or TCP `--peer` seed is required.
Pairing requires the authority's fresh sync rendezvous so the new peer has a
persistent connection after the short-lived pairing listener closes.

Scan the QR and save its **secret claim** in a private file on the new machine:

```sh
mycelium setup --claim-file /path/to/private-claim.txt
mycelium peers --json
```

The ordinary setup path generates keys locally, redeems the one-use claim,
installs the existing CA-signed peer identity and daemon service, and saves an
Iroh sync seed and TLS server name before starting the daemon. It refuses to
replace an existing peer identity/sync configuration. Consumed claim files are
removed by the existing setup workflow. Do not post claim QR codes publicly or
include them in screenshots/logs; unlike `sync export`, they contain a secret.

LAN/direct routing is the default. For relay-assisted enrollment, explicitly
add `--public-relays`; the new peer will enable public relays for its persistent
sync connection too. Enable relays on the authority sync runtime separately if
it also needs them for WAN reachability. Pairing publishes no public DNS record
and creates no UPnP port mapping. Cross-site NAT/relay qualification is still
separate from the loopback enrollment tests.

The ephemeral pairing key is pinned by the claim and uses `mycelium/pair/1`,
separate from persistent `mycelium/sync/1`. Requests still pass through the same
invitation redemption handler, including TTL/one-use checks. Exchanges have a
30-second deadline, 128 KiB frames and four concurrent slots; only a peer
invitation is supported. The listener closes after acknowledged redemption or
expiry. If transport fails after issuance/consumption, create a new claim after
checking the enrollment staging directory; one-use claims are not retryable
after credentials have been issued.

## Trust and transport

The Iroh transport key is separately generated and retained in
`$MYCELIUM_HOME/iroh-secret.key` (0600); it is not the peer signing key or a human
identity. The underlying connection pins the Iroh endpoint key. Inner mTLS
then verifies the existing fleet CA and certificate SAN; the existing gossip
stream retains signed envelopes and transport-certificate binding checks.
No accept-all TLS verifier or new access authority exists.

The runtime also publishes the Iroh endpoint key in a peer-signed transport
binding. Iroh sessions require both that binding (matched against the actual
QUIC remote endpoint ID) and the existing TLS certificate fingerprint binding
before artifact or SSH-renewal exchanges are authorized. Logs report
`authenticated Iroh peer ... endpoint ...` when both checks succeed. Keys are
not rotated to establish this relationship. Older peers do not receive the new
binding kind unless they advertise `transport.iroh-key-binding` support.

This runtime check uses existing signed gossip plus inner mTLS. The portable
authority-signed membership proofs described in `fleet-identity.md` are not
yet issued by enrollment and do not replace mTLS.

`iroh-sync.json` is strict, bounded JSON, with at most 32 unique seeds:

```json
{"public_relays":false,"direct_first":true,"server_name":"peer.example","seeds":[]}
```

`server_name` is optional; it is the TLS SAN this peer advertises for its own
Iroh endpoint. It is a public name, never a credential or an access grant.
Unknown fields are rejected, and an invalid configuration is reported instead
of being applied: the running transport keeps the last valid configuration.

Public n0 relays are opt-in via `public_relays: true` followed by a reload
(the write already reloads the daemon). With them disabled, this slice requires
reachable direct addresses (LAN or
an existing routed overlay). WAN/NAT hole-punch and relay behavior has not
been qualified across the fleet. Public DNS endpoint lookup/publication and
UPnP/PCP/NAT-PMP port mapping are disabled. Iroh does not deploy WireGuard.

Incoming sync is capped at 32 sessions; QUIC permits one bidirectional stream
and no unidirectional streams per connection. Handshake stages time out after
15 seconds; outgoing retries back off from 1 to 60 seconds. Gossip retains its
existing digest cadence and bounded batches, with a 1 MiB input frame limit
enforced before allocation grows beyond the bound.

Runtime-owned `iroh-sync-endpoints.json` publishes expiring leases through the
existing Iroh discovery projection on `scan`; application-owned
`iroh-endpoints.json` remains untouched. The public rendezvous file is separate
from enrollment and credentials. Removing the sync configuration and reloading
disables the runtime; retain the transport key for stable identity.

A missing or invalid sync configuration no longer prevents the daemon from
starting: the optional transport stays idle and the daemon keeps its TCP
gossip path. `mycelium sync status` reports the last error, and a corrected
configuration is applied by the next write, `mycelium sync reload`, or
`SIGHUP`.

## Verification

```sh
cargo check -p mycelium-cli --features iroh-sync --tests
cargo test -p myceliumd --features iroh-sync iroh_sync
cargo test -p myceliumd peer_framing_bounds_and_cancellation
cargo test -p mycelium-cli --features iroh-sync pair_iroh -- --test-threads=1
cargo test -p mycelium-cli --features iroh-sync sync
# Relay-only carriage (needs reachable public n0 relays; asserts no direct path):
cargo test --release -p myceliumd --features iroh-sync relay_only -- --ignored --nocapture
```

Tests use isolated loopback Iroh endpoints and freshly generated test mTLS
certificates; they do not need relays, fleet credentials, or production peers.
