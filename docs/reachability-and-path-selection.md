# Reachability and Path Selection for fungOS

Status: **Accepted for implementation (v1)**
Owners: Mycelium (discovery, identity, access, path planning); fungOS Reach
(candidate selection and failover); Unibus (session and grant enforcement).
Related: `docs/iroh-discovery.md`, `docs/fleet-identity.md`, `docs/scope-audit.md`.

## 1. Summary

fungOS needs one reachability layer that can use, in order:

1. the local LAN,
2. durable site-to-site WireGuard links,
3. iroh direct sessions,
4. iroh relay fallback.

Mycelium must not become a full VPN/overlay for every node, and fungOS must not
reimplement iroh's QUIC, NAT traversal, Pkarr discovery, or relays. Equally,
iroh must not become the identity root or the policy owner.

The clean split is:

| Layer | Owns |
| --- | --- |
| Mycelium | Node/peer identity, access grants (SSH/host), discovery, site model, WireGuard plan, candidate endpoints |
| fungOS Reach | Candidate normalization, health probing, path ordering, failover, hysteresis |
| Unibus | Envelopes, message-flow grants, registry, QoS, stream contracts, direct-session authorization |
| Iroh | Optional direct/relay carrier, endpoint key, NAT traversal |
| WireGuard | Site-to-site L3 underlay with explicit, narrow routes |
| LAN | First-class direct path; no overlay required |

Iroh is a component, not a competitor. The competing implementations to avoid
are another relay network, another Pkarr/DHT, or another hole-punching stack.

## 2. Goals

- Prefer LAN when both peers are on the same segment.
- Prefer a healthy site-to-site WireGuard path across sites.
- Use iroh direct when no IP route exists or is healthy.
- Use iroh relay only when direct paths fail.
- Keep LAN and WireGuard usable without iroh at runtime.
- Let multiple screens hold independent active assignments at once.
- Keep Mycelium reachability independent of Unibus view state.
- Keep Unibus authorization independent of reachability.
- Never expose a public listener or a static stream token as a shortcut.
- Make path selection observable: class, candidate, health, rejection reason.

## 3. Non-goals

- A new mesh VPN or full-tunnel overlay for all machines.
- Reimplementing iroh/Pkarr/DERP/STUN.
- Making Pkarr or Mycelium DNS an authorization source.
- Making the Unibus hub a bulk media relay.
- Encoding live link health permanently into DNS.
- Routing overlapping RFC1918 site subnets end-to-end.
- Replacing Unibus grants with Mycelium SSH grants (or vice versa).

## 4. Path classes

```
Lan        same broadcast/segment or directly routed local subnet
SiteLink   Mycelium-planned WireGuard `/32` or explicit site prefix
IrohDirect iroh direct path (LAN/WG/public UDP after hole punching)
IrohRelay  iroh relay fallback
```

Default hard order: **Lan > SiteLink > IrohDirect > IrohRelay**.

The order is policy, not a measurement. Within a class, measured RTT/health may
reorder candidates. Crossing classes requires an explicit policy exception.

## 5. PathPlan

Mycelium/fungOS produce a `PathPlan`, not a single address:

```json
{
  "schema_version": 1,
  "target": "media-edge.home.myc",
  "observed_at": 1793069000,
  "expires_at": 1793069300,
  "candidates": [
    {
      "class": "lan",
      "addr": "10.0.0.34",
      "port": 18089,
      "site": "shop",
      "cost": 0,
      "expires_at": 1793069300,
      "provenance": "mycelium/service-catalog"
    },
    {
      "class": "site_link",
      "addr": "100.77.1.10",
      "port": 18089,
      "site": "home",
      "cost": 10,
      "expires_at": 1793069300,
      "provenance": "mycelium/wireguard-plan"
    },
    {
      "class": "iroh_direct",
      "endpoint_id": "<64 lowercase hex>",
      "alpns": ["unibus/1"],
      "relay_urls": ["https://relay.example.net/"],
      "site": "home",
      "cost": 20,
      "expires_at": 1793069200,
      "provenance": "mycelium/iroh-observation"
    }
  ]
}
```

Rules:

- Candidates are typed. A bare IP is not enough; the class and provenance are
  part of the plan.
- Every candidate has an expiry. No candidate may be served indefinitely from
  a stale cache.
- Discovery only supplies candidates. It does not prove reachability.
- The plan contains no credentials, grants, private keys, or bearer tokens.
- The wire contract is `mycelium/reach-candidate.v1`; `PathPlan` is the
  in-memory type. Adding a transport must not require a Mycelium daemon release.
- An iroh endpoint may emit separate `iroh_direct` and `iroh_relay` candidates
  from the same endpoint ID. Direct is attempted first; relay is a distinct
  class, not an implicit fallback inside the direct candidate.

### 5.1 PathDecision

`fungos-reach` returns a decision, not just a chosen address:

```json
{
  "schema_version": 1,
  "target": "media-edge.home.myc",
  "selected": {
    "class": "site_link",
    "addr": "100.77.1.10",
    "port": 18089,
    "rtt_ms": 18
  },
  "rejected": [
    {"class": "lan", "reason": "no candidate"},
    {"class": "iroh_relay", "reason": "not attempted; higher class healthy"}
  ],
  "reason": "lan absent; wireguard healthy",
  "expires_at": 1793069300
}
```

Decision states are `selected`, `probing`, and `unavailable`. A fallback must
name the failed class and reason. No silent path changes.

### 5.2 Ownership

- `mycelium/reach-candidate.v1` is emitted by Mycelium and may be carried in the
  service catalog, DNS, or the existing topology/resource snapshot.
- `fungos.reach.v1` is the local selector API and the status/decision contract.
- Unibus links the selector library or calls the local `reachd` socket; it does
  not parse Mycelium internals or duplicate discovery.
- No new cross-site routing protocol is introduced. The candidate contract is
  the boundary.

## 6. Discovery sources

### 6.1 Mycelium service catalog

The canonical source. It can carry typed endpoints, site scope, freshness,
provenance, and service aliases. Unibus and fungOS Reach consume this directly.

### 6.2 Mycelium DNS (`*.myc`)

DNS is a compatibility/discovery surface, not the policy engine.

- `A`/`AAAA` for LAN and WireGuard addresses.
- `SVCB`/`TXT` may carry priorities, ALPNs, and Pkarr/iroh endpoint hints.
- Queries are site-scoped. Never return an ambiguous bare `192.168.0.x`.
- A DNS failure must degrade to retained, explicitly stale candidates, not an
  empty zone that silently breaks all routing.
- Dynamic health belongs in the Reach/Selector, not in DNS TTLs.

Example shop-side view of a home media edge:

```text
media-edge.home.myc. 30 IN A 100.77.1.10
media-edge.home.myc. 30 IN SVCB 10 iroh= endpoint=... relay=https://relay.example.net/ alpn=unibus/1
```

A local (same-site) query may instead return the LAN address. The resolver is
split-horizon by site; it must never return both sites' identical RFC1918
prefix as a single answer.

### 6.3 Pkarr / iroh endpoint records

Pkarr is public rendezvous: endpoint key to relay/direct hints.

- Publish only endpoint IDs, ALPNs, and credential-free relay hints.
- Never publish ACLs, grants, workspace state, or private topology.
- Mycelium signs the binding from its peer identity to the iroh endpoint key.
- Consumers must pin the iroh key and verify the binding; a Pkarr record alone
  is not authorization.

### 6.4 WireGuard site links

Mycelium plans and supervises links. Each link exports only what is required:

- one `/32` per participating edge, or an explicit, non-overlapping site prefix;
- never both sites' `192.168.0.0/24` routes;
- edge-local proxy/NAT to LAN services;
- persistent keepalive only where NAT requires it;
- direct path when a stable public endpoint exists; otherwise relay/iroh for
  rendezvous, but not as a permanent full tunnel.

## 7. Selection algorithm

For each target:

1. **Resolve** a fresh `PathPlan` from Mycelium.
2. **Filter** expired, disallowed, or wrong-tenant candidates.
3. **Group** by class and apply hard order.
4. **Probe** the best candidate in the current class:
   - LAN: short TCP/QUIC connect or existing session;
   - SiteLink: WireGuard handshake/route health and service connect;
   - IrohDirect: iroh connect with direct paths;
   - IrohRelay: iroh connect allowing relays.
5. **Score** within the class using measured RTT and recent success rate.
6. **Fail over** to the next candidate after a bounded timeout.
7. **Hysteresis**: do not switch classes for a single transient failure; require
   a stable failure window or a strictly better class.
8. **Re-resolve** on path failure, expiry, site change, or interface change.

The selector must return a reason:

```
selected: SiteLink 100.77.1.10:18089 (LAN absent; WG healthy; rtt=18ms)
rejected: IrohRelay (not reached; SiteLink healthy)
```

No silent path changes. No silent `success:false` on a zero-screen send.

## 8. Identity and authorization

There are two separate authorization questions:

1. **Carrier identity** — is this endpoint key the peer we think it is?
2. **Application authorization** — may this peer publish/consume this contract
   in this zone/anchor?

The chain:

```
Mycelium peer identity
  -> signed binding to WireGuard/mTLS/iroh/SSH credential
  -> iroh endpoint key pinned at handshake
  -> Unibus grant (fpl-auth NodeClaims) decides protocol/zone access
```

- Mycelium SSH access does **not** imply Unibus publish/consume rights.
- An Unibus grant does **not** imply shell/host access.
- Pkarr and DNS are discovery, never ACLs.
- Revocation is bounded by short-lived proofs/grants plus explicit revocations;
  a disconnected consumer must not trust stale policy forever.

## 9. Iroh integration

Iroh is an **optional carrier**:

- It provides direct/relay connectivity, hole punching, QUIC, and endpoint-key
  identity.
- It may use LAN, WireGuard, public direct, or relay internally; that is its
  job.
- fungOS should not require iroh for LAN or site-link paths.
- Do not expose a generic unauthenticated HTTP tunnel over iroh. Advertise a
  real ALPN only after the authorized protocol exists.
- Treat iroh's direct address as an implementation detail; the application
  chooses a class, not a socket.

Potential configuration constraints:

- `RelayMode` per deployment (disabled for pure-LAN, allowed for roaming).
- Bind/probe the WireGuard address when site-link preference matters.
- Publish only the endpoint/address hints consistent with policy.
- Keep iroh behind a fungOS Reach feature flag so LAN-only builds do not link it.

## 10. Unibus integration

Unibus exposes the session contract; Reach supplies the carrier.

Sketch:

```rust
enum Carrier {
    Ip(IpAddr),          // LAN or SiteLink; Unibus QUIC/TCP
    Iroh(EndpointId),    // direct or relay; iroh handles NAT
}

trait PathSelector {
    fn select(&self, target: &Target) -> PathDecision;
}
```

- Unibus validates the grant **after** the carrier is established.
- `unibus.direct.v1` remains hub-authorized, edge-to-edge, offline-verified.
- The hub is not a bulk media relay. Live media uses direct sessions; bulk
  content uses the content plane.
- A carrier failure is reported as a transport error, not a grant failure.

## 11. fungOS runtime

Build one owner of path selection, not one per app:

- `fungos-reach`: a library crate plus a thin `reachd` daemon. The library owns
  types, policy, and selection; the daemon shares a live cache and probe state
  between processes.
- Mycelium adapter: service catalog, DNS, WireGuard plan, iroh observations.
- Unibus adapter: `Carrier` dialing and session binding.
- Metrics: selected class, candidate, RTT, failures, fallback reason, stale
  records, resolution source.
- Lifecycle: start after network identity; react to site/interface changes;
  expose a read-only status command.

Default policy:

```json
{
  "schema_version": 1,
  "class_order": ["lan", "site_link", "iroh_direct", "iroh_relay"],
  "stale_grace_seconds": 300,
  "probe_timeouts_ms": {
    "lan": 500,
    "site_link": 1500,
    "iroh_direct": 3000,
    "iroh_relay": 5000
  },
  "hysteresis": {"failures": 3, "window_seconds": 30},
  "relay_mode": "allowlisted",
  "relay_allowlist": ["https://relay.example.net/"]
}
```

Local API:

```text
reach.resolve TARGET        -> PathPlan
reach.decide TARGET         -> PathDecision
reach.dial TARGET ALPN      -> Carrier handle (Unibus binds the session)
reach.status [TARGET]       -> selected/rejected candidates and reasons
reach.watch TARGET          -> bounded change stream
```

Applications ask Reach for a target. They do not hardcode LAN IPs, WireGuard
addresses, Pkarr keys, or iroh relays.

## 12. Failure modes

| Failure | Required behavior |
| --- | --- |
| DNS/mesh zone empty | Serve retained candidates within stale grace; log loudly; never silently empty all routes |
| myceliumd down | LAN/site links remain usable; discovery degrades with bounded staleness |
| WireGuard down | Fall through to iroh direct/relay; report class change |
| Iroh relay down | LAN/site links unaffected; report unavailable |
| Overlapping subnets | Never install both site prefixes; use `/32` edges and proxy/NAT |
| NAT rebinding | Re-resolve and re-probe; keep the endpoint key pinned |
| Expired grant | Reject at Unibus even if the carrier is healthy |
| Stale Pkarr record | Validate expiry and binding; do not treat as proof |
| Site change (laptop moves) | Re-evaluate site, candidates, and policy; do not keep the old site label |

## 13. Security and privacy

- Pkarr and public DNS leak endpoint/relay existence. Publish only what is
  intended to be public.
- Private topology, ACLs, workspace state, and grants stay in Mycelium/Unibus.
- No static stream tokens in workspace documents.
- No full-tunnel overlay by default; WireGuard `AllowedIPs` are explicit and
  minimal.
- Endpoint-key substitution is rejected by the signed binding plus handshake
  pinning.
- The TV remains a LAN client of the shop media edge; it never needs a
  cross-site route or a WireGuard key.

## 14. Testing and acceptance

Unit tests:

- candidate ordering and class policy;
- stale/expired candidate rejection;
- hysteresis and failover;
- no cross-class switch on one transient failure;
- overlapping prefix rejection;
- signed endpoint binding verification;
- grant denial after a healthy carrier connect.

Integration:

- Two peers on the same LAN select LAN; no relay traffic.
- Two sites with overlapping `192.168.0.0/24` use edge `/32`s and a local proxy.
- WireGuard down -> iroh direct; iroh direct down -> relay; LAN still works.
- myceliumd down -> retained candidates within grace; after grace, explicit
  unavailable, not fake success.
- Shop TV selects the shop media edge over LAN; shop edge selects home origin
  over WireGuard or iroh.
- Two displays hold different active workspaces simultaneously.
- A third, non-ADB client can drive `screen-shop-tv` through Unibus/DCP.

Acceptance for the first slice:

1. `PathPlan` schema and selector land in a library with tests.
2. Mycelium service catalog emits LAN/WG/iroh candidates with expiry.
3. Unibus can dial a selected `Carrier` and enforce its existing grant.
4. A shop media edge serves the TV over LAN while the WAN side uses WG/iroh.
5. Status output explains the chosen path and why alternatives were rejected.

## 15. Rollout

1. **Schema + selector library** (no behavior change).
2. **Mycelium candidates** for existing site links and iroh observations.
3. **Unibus carrier adapter** behind a feature flag.
4. **Shop media edge** pilot; keep home URLs out of shop workspace docs.
5. **Screen output bridge** (`screen-shop-tv`) for Canvas/Unibus control.
6. **Multi-screen test**: two screens, independent assignments, one cross-site
   path, local fan-out.
7. **Retire ad-hoc ADB/overlay paths** once the bridge and edge are verified.

## 16. Resolved decisions

| Question | Decision |
| --- | --- |
| Candidate schema | New versioned `mycelium/reach-candidate.v1`; service catalog is a carrier, not the schema owner. |
| Where Reach lives | Separate `fungos-reach` crate + `reachd` daemon in fungOS. Mycelium is a dependency, not the owner. |
| DNS record shape | `A`/`AAAA` for IP paths; `SVCB` for Mycelium-native priorities/hints; Pkarr records for iroh interoperability. TXT only as a Pkarr-compatible fallback. |
| Stale grace | 300 seconds for cached candidates, with explicit stale status. LAN/WG sessions already established may outlive candidate expiry. |
| Probe timeouts | LAN 500 ms, site link 1500 ms, iroh direct 3000 ms, iroh relay 5000 ms. |
| Hysteresis | Three failures in a 30-second window before a class downgrade; a recovered higher class requires one successful probe plus a 10-second stability window. |
| Prefer WG over public direct | Do not publish public direct hints for site-link peers. Bind/probe the WireGuard address and filter iroh direct to the no-IP-path case. |
| Who applies WireGuard | Mycelium plans and verifies; a privileged host reconciler applies it. `fungos-reach` never mutates routes or firewall state. |
| Relay allowlist | Mycelium owns the per-site allowlist; Reach rejects unknown relays. Pkarr-only hints are discovery, not an allow decision. |
| Iroh dependency | Optional Cargo feature. LAN-only and site-link-only builds must not link iroh. |

## 17. Implementation plan

1. **`fungos-reach` types + selector.** Land `PathPlan`, `PathDecision`,
   class ordering, expiry, hysteresis, and unit tests. No network behavior yet.
2. **Mycelium candidate exporter.** Emit `mycelium/reach-candidate.v1` from the
   service catalog, DNS views, WireGuard plan, and iroh observations. Include
   provenance and expiry on every candidate.
3. **`reachd` + status.** Local socket, `reach.status`, metrics, and bounded
   change events. Keep the selector callable as a library for Unibus.
4. **Unibus carrier adapter.** `Carrier::Ip` and optional `Carrier::Iroh`; dial
   the selected carrier, then enforce the existing Unibus grant. No hub media
   relay.
5. **Shop media edge pilot.** Put a media edge on an always-on shop host; serve
   the TV over LAN and pull the home origin over WireGuard or iroh. Rewrite shop
   workspace stream URLs to the edge.
6. **`screen-shop-tv` bridge.** A host with authorized ADB applies Canvas
   workspace assignments to the TV over `canvas-tvctl`; the TV checkpoint is
   only a cache.
7. **Multi-screen test.** Two displays with independent assignments, one
   cross-site path, local fan-out, and a third Unibus client driving the TV.
8. **Retire ad-hoc paths.** Remove home URLs and per-host ADB assumptions from
   shop workspace docs after the bridge and edge pass acceptance.

Exit criteria for v1: the selector passes its unit/integration tests, a shop TV
plays through the shop edge, the shop edge reaches home over WG or iroh, a
non-ADB client can switch `screen-shop-tv`, and the status output explains every
selected and rejected path.

## 18. Decision

Adopt **one reachability owner**, **typed PathPlans**, **hard class ordering**,
and **iroh as an optional carrier**. Use WireGuard for durable site links, LAN
where it is best, and iroh for endpoint-only/NAT-bound paths. Do not build a
second relay network, do not make Pkarr an ACL, and do not make every node join
a full overlay.

## 19. Worked example: shop TV to home media origin

Shop site: `10.0.0.0/24`, TV at `10.0.0.44`, media edge at `10.0.0.34`.
Home site: `192.168.0.0/24`, media origin at `192.168.0.67`.

```text
TV 10.0.0.44
  └─ HLS http://10.0.0.34:18089/komo4.m3u8        (LAN, no overlay)
       └─ shop media edge
            └─ Unibus stream to home origin
                 ├─ SiteLink 100.77.1.10:18089   (preferred)
                 └─ IrohDirect/Relay endpoint=…  (fallback)
                      └─ home media origin 192.168.0.67:18089
```

What happens:

1. The TV resolves only the shop-local edge. It never sees WireGuard, iroh, or
   home LAN addresses.
2. Shop Reach resolves `media-edge.home.myc`; it has no LAN candidate (different
   site), prefers the healthy SiteLink candidate, and reports the rejected iroh
   candidates in `reach.status`.
3. The shop edge pulls one cross-site copy and fans out locally to every shop
   screen. A second shop screen does not create a second WireGuard/iroh flow.
4. If the WireGuard link drops, Reach fails over to iroh direct, then relay, and
   logs the class change. The TV’s LAN URL does not change.
5. If the home daemon is down, the shop edge reports `unavailable`; it does not
   silently serve a stale or wrong stream.
6. Workspace control for `screen-shop-tv` travels separately over Canvas/Unibus
   and never carries media bytes through the Unibus hub.
