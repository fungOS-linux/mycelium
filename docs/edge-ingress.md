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

## Open questions

- **Transport.** Cloudflare Tunnel is the current assumption: a connector per
  node, no inbound ports. The alternative explored elsewhere was a signed iroh
  endpoint map published by Mycelium that an edge reads to route directly. That
  keeps certificates on the nodes and avoids the tunnel, at the cost of owning
  the routing consistency problem ourselves. Not decided.
- **L4 vs L7.** Terminating at the edge lets us apply per-location policy and
  rewrite headers, but discards client certificates. Passing through at L4 keeps
  mTLS end to end but gives up host-based routing. The local `.myc` path can keep
  mTLS either way; the public path cannot without Cloudflare client-certificate
  auth.
- **Which names may be sticky at all.** A node that dies mid-stream costs a
  reconnect. For a terminal that is acceptable; for a long upload it may not be.

## Related threads

- Confluence ingress architecture: signed endpoint maps, L4 proxying, mTLS
  (`delta://thread/ksQQzeG0sNqlSu6LzAxr6hhYrZLOAAi82pIBxBAGDbsLqAxICYR-0Az4EauY`)
- Myceliumd timer for Pulse runs: clock, jitter, scheduling in Soil
  (`delta://thread/ksQQ_LEmCUWyQ9C0bsjXuJeFQZLOAG5HUpIBxBBQmJ687KtA65mCXPfncMaP`)
- fungOS core planes: which project owns identity, transport and ACLs
  (`delta://thread/ksQQzo4bqCV9Sq640uIDjiLwuZLOAAVRqZIBxBBQmJ687KtA65mCXPfncMaP`)
