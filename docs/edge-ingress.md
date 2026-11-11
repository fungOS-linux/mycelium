# Edge ingress and node profiles

Status: design. Nothing here is implemented yet.

## What this replaces

An earlier draft gave ingress a time-bounded *lease* with a fencing epoch, one
holder per name at a time. That is wrong for this system. `soil:records` is local
plus sync, so the fleet is eventually consistent by construction: a request may
land on any node, and correctness cannot depend on which one served it. An
exclusive holder buys a failover stall, a split-brain mode and a fencing token in
exchange for guarantees the records model already provides. There is no lease.

## Decisions

1. **Any eligible node serves any request.** No leader, no owner, no epoch.
2. **Eligibility is a node profile, not a grant.** Grants
   (`AccessStatement::Grant`, and Unibus L1 grants) stay scoped to data and spore
   access. Whether a machine may terminate public traffic is a property of the
   machine: always-on, wired, mains power, healthy.
3. **Stickiness is a routing hint, not ownership.** A client keeps talking to the
   same node while that node is alive, because sessions are cheaper than
   reconnection, not because the node holds a right to it.
4. **Failover is a re-pick, not a handover.** When a node leaves, the sessions
   that mapped to it re-establish somewhere else. Nothing waits for a TTL to
   expire and nothing has to be fenced.
5. **Node selection prefers observed stability.** Laptops and battery-powered
   nodes are never ingress candidates, no matter how healthy they look right now.
6. **Clocks are corrected and jittered.** Any remaining deadline (certificates,
   connector credentials) compares against the skew-corrected clock and renews
   with jitter, so N nodes never act on the same tick.

## Topology

```text
                Cloudflare (TLS, *.fpl.dev)
                          |
        +-----------------+------------------+
        |                 |                  |
   cloudflared       cloudflared        cloudflared      (profile-qualified only)
        |                 |                  |
   palisade          palisade           palisade         (loopback, every node)
        |                 |                  |
   *.myc services    *.myc services     *.myc services
```

Palisade listens on loopback on every node and serves `.myc` whether or not that
node is publicly reachable. That keeps local work identical everywhere and keeps
the laptop usable offline. The connector is the only thing the profile gates.

`cloudflared` is not anycast. Each connector dials out, and Cloudflare picks a live
connector per request, which gives seconds-scale failover and no session affinity.
That is the right failure model here, and it is why stickiness has to be a hint we
carry rather than a property we assume.

## Sticky routing without ownership

Pick the target by rendezvous hashing over the *currently healthy* eligible set:

```text
target = argmax(node) hash(node_id, session_key)
```

`node_id` comes from the mesh, `session_key` is a cookie set on the first response.
When a node disappears the set shrinks, and only the sessions that hashed to that
node move. No coordination, no handover message, no lease.

Session state that has to survive the move belongs in `soil:records`, which already
syncs. A node that cannot answer from local records is a node that has not
converged, and the honest response is to re-pick rather than to guess.

## The node profile

Derived from what is already gossiped, not configured by hand:

```text
power      mains vs battery, UPS, recent brownouts
link       wired vs wifi, flap count over 7 days
presence   median continuous session, restart count
capacity   load, free memory, thermal state
```

It answers one question: *would putting public traffic here make the fleet worse?*
A node with four hours of uptime today is a worse candidate than one that has been
up for three weeks, even if both are idle right now.

The profile is a weight, not a gate, with two hard exclusions: battery-powered
nodes and nodes that have never held a connection longer than the current ingress
session. It decays toward neutral so a recovered node is not punished forever.

## What stays time-bounded

Nothing in the request path. The remaining deadlines are credentials and
certificates:

- connector credentials - replaced by rotation, not by expiry races
- serving certificates - issued ahead of expiry with jitter, swapped by file
  replacement so the edge picks them up without a restart

Both compare against the skew-corrected clock. A 15-second deadline on a fleet
with second-scale skew is a coin flip, and that is the reason the clock work
matters here rather than being a side quest.

## Settled

- **Transport.** Cloudflare Tunnel, for now: a connector per profile-qualified
  node, no inbound ports. The signed iroh endpoint map explored elsewhere stays
  on the table, but it is not the first move.
- **L4 with anycast, mTLS terminated at the edge, routing after.** The edge sees
  the client certificate, decides, and only then routes to a node. That keeps
  mTLS a real gate on the public path, and it means the client identity travels
  as a signed assertion rather than as a re-verified chain downstream. The node
  side must verify that signature and must not accept an unsigned actor header
  from any other source.

## Ingress policy

A published name has two independent properties. Both default to the narrow
value, so a name is private and unauthenticated-by-omission until its owner says
otherwise:

| | `auth = none` | `auth = optional` | `auth = required` |
|---|---|---|---|
| **public** | static content; no identity | guests allowed, identity when signed in (store, rooms) | SSO required (home) |
| **overlay** | fleet only | fleet only, identity when present | fleet only + SSO |

- `visibility` is `overlay` unless the lease asks for `public`; `auth` is `none`
  unless the lease asks for more. A public name still needs an edge route, and a
  zone may tighten a name (public to overlay, none to optional to required) but
  never loosen one.
- `optional` never rejects. The edge guarantees `soil:principal` is always
  present — `oidc:<issuer>#<subject>` when a session exists, `anon:<opaque>`
  otherwise — and strips any inbound copy of that header first, so an upstream may
  trust it. Feature elevation ("more if signed in") is the application's job.
- Guests get a stable `anon:` identity from an `HttpOnly; Secure; SameSite=Lax`
  cookie minted on first visit. Stable enough for rate limits and carts, and not
  a login.
- `required` reuses the Vouch redirect; an anonymous request never reaches the
  upstream.
- Audience and group checks are deliberately out of scope here: whether a
  principal may use a name is a Mycelium grant / OIDC ACL question, not an edge
  question. For now `required` means "any principal from the configured issuer".
- The overlay DNS address (`<prefix>::53`) is never published publicly. A public
  AAAA for a ULA only invites queries nobody can answer.

## Order of work

The edge does not have to be built before it is useful. The local loopback
gateway is already an edge; everything else is an outer ring.

1. **Names come from the catalog.** A lease publishes its labels in
   `value.names`; the daemon composes them with the zone suffix and every consumer
   reads that one projection, so the gateway derives its host table from the
   catalog instead of `~/.mycelium/gateway/routes.json`. `routes.json` stays only
   for overrides that no service can express, such as a public fallback upstream
   or a per-route token. Until this lands, every node needs a hand-edited route
   file, which is the opposite of anycast.
2. **Principal.** Palisade already answers who: vouch, mTLS or bearer, one
   per-location choice. What is missing is turning its assertion into Soil's
   `oidc:<issuer>#<subject>` and refusing an unsigned actor header. This is
   needed, not deferred.
3. **Outer ring.** Managed `cloudflared` first, then a configurable L4 edge with
   SNI once there is a reason to own it. Nothing above this line depends on
   which outer ring wins.

Deferred on purpose, to be revisited once the above works:

- **Stickiness.** A re-pick per request is fine until a session spans requests.
- **Observability and rollout.** No request attribution, connector health or
  canary yet.
- **Certificate issuance.** Palisade reloads what it is given; who issues and
  rotates is `pulse.myc`'s problem long term.
- **Edge actor key custody** (`mycelium-ya35`).

Spore names are not a gap in this list. A Spore gets its names in its package
manifest, and installing it publishes the lease that step 1 already understands.


## Related threads

- Confluence ingress architecture: signed endpoint maps, L4 proxying, mTLS
  (`delta://thread/ksQQzeG0sNqlSu6LzAxr6hhYrZLOAAi82pIBxBAGDbsLqAxICYR-0Az4EauY`)
- Myceliumd timer for Pulse runs: clock, jitter, scheduling in Soil
  (`delta://thread/ksQQ_LEmCUWyQ9C0bsjXuJeFQZLOAG5HUpIBxBBQmJ687KtA65mCXPfncMaP`)
- fungOS core planes: which project owns identity, transport and ACLs
  (`delta://thread/ksQQzo4bqCV9Sq640uIDjiLwuZLOAAVRqZIBxBBQmJ687KtA65mCXPfncMaP`)
