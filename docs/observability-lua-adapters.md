# Observability Lua adapters

These optional adapters use the existing bounded command ABI. They add no
HTTP networking, credential access, or clock access to the Lua sandbox, and
they perform no writes: a scrape observes a metrics endpoint, it never
manages one. Copy the wanted file into the matching Mycelium home directory,
then restart the daemon once so it loads the new adapter.

```sh
cp crates/mycelium-plugins-lua/plugins/prometheus.lua "$MYCELIUM_HOME/plugins/"
cp crates/mycelium-plugins-lua/plugins/grafana.lua   "$MYCELIUM_HOME/plugins/"
cp crates/mycelium-plugins-lua/recognizers/prometheus.lua "$MYCELIUM_HOME/recognizers/"
```

Plugin driver names are `lua:prometheus` and `lua:grafana`. Pin the driver
explicitly (`mycelium add host --driver lua:prometheus`) when a generic OS
driver would otherwise win recognition on the same host.

## Boundary

* The host is always loopback (`127.0.0.1`) and the scheme is always plain
  HTTP. There is no parameter for a remote host, a scheme, a userinfo, a query
  string, or a fragment, so the adapter cannot be pointed at another machine
  and cannot carry a credential.
* Every scrape is bounded twice: the plugin truncates the reply to a fixed
  window and the plugin host rejects output above 1 MiB.
* The adapters need `curl` (and `head`, for the Prometheus exposition window)
  on the target host.
* A successful scrape proves that a metrics endpoint answered. It is not
  evidence that the endpoint stays reachable, that the data is correct, or
  that the operator may scrape it from anywhere else. Scrape authorization
  stays with Prometheus and whatever fronts it.

## Prometheus

`plugins/prometheus.lua` observes a Prometheus exposition endpoint and the
target inventory of a Prometheus server.

| Capability | What it returns |
|---|---|
| `system.identify` | vendor, model (`prometheus`, `node_exporter`, or `prometheus-compatible`), version, hostname |
| `prometheus.metrics` | family, sample, and line counts, `up`, scrape duration, version, and a bounded family-name sample |
| `prometheus.targets` | scrape target inventory projected to `job`, `instance`, and `health` |

Optional parameters: `port` (default `9090`) and `path` (default `/metrics`,
or `/api/v1/targets` for the target inventory).

The exposition parser accepts the Prometheus text format (0.0.4) and
OpenMetrics-style comments. HTML error pages, `404 page not found`, empty
bodies, and bodies whose lines are not Prometheus samples are refused with an
explicit message instead of being reported as an empty metric set. The target
inventory is deliberately lossy: scrape URLs and last-error strings are
dropped, because a configured target may embed credentials. Only `job`,
`instance`, and `health` are projected, which is enough to correlate scrape
targets with topology, container, and hypervisor observations.

The target list is bounded by the host JSON decoder (depth and node bounds).
A target inventory larger than those bounds fails loudly rather than being
silently truncated.

`recognizers/prometheus.lua` is the passive counterpart: it turns a
`_prometheus._tcp` or `_node-exporter._tcp` advertisement into a stable device
fact. It requires an explicit `id` (or `uuid`) TXT record, so an anonymous
advertisement stays anonymous. A recognized advertisement is an observation
with a lease, not a managed device and not an access grant.

For endpoints that the daemon itself does not run, publish the observation
through `application-services.json` instead (see `application-services.md`).
Mycelium observes and gossips that lease; it still does not authorize a
scrape.

## Grafana

`plugins/grafana.lua` observes the unauthenticated Grafana health endpoint.

| Capability | What it returns |
|---|---|
| `system.identify` | vendor, model, version, hostname |
| `grafana.health` | `database` status, `version`, and a boolean `healthy` |

Optional parameters: `port` (default `3000`) and `path` (default
`/api/health`, the only accepted path). Grafana API keys, cookies, sessions,
and the build commit are never read, stored, or projected.

## Verification

```sh
cargo check -p mycelium-plugins-lua --tests
cargo test -p mycelium-plugins-lua --test prometheus_plugin
cargo test -p mycelium-plugins-lua --test prometheus_recognizer
cargo test -p mycelium-plugins-lua --test grafana_plugin
```

The tests use recording transports: they need no credentials, contact no live
metrics endpoint, and assert that non-metrics responses, credential-bearing
paths, and credential-bearing target fields are all refused.
