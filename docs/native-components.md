# Native components and the wasm32 boundary

This is the inventory behind `install.sh`. "Native" here means a Mach-O or ELF
executable that runs directly on the host. A `wasm32-wasip2` Spore is listed as
wasm even when a native host process loads it.

The goal is fewer host executables, not fewer capabilities: every native process
should own one unavoidable host boundary, and everything above that boundary
should be a Spore where the runtime already provides the capability.

## Inventory

### Mycelium workspace

| Artifact | Crate | Installer role | Required | Boundary | Notes |
|---|---|---|---|---|---|
| `mycelium` | `mycelium-cli` | CLI, enrollment, daemon via hidden `_serve` | yes | Unix socket, PKI, host state | Canonical user-facing binary; launchd/systemd run `mycelium _serve`. |
| `myceliumd` | `myceliumd` | Standalone daemon binary | no | same as `_serve` | The managed service runs `mycelium _serve`, which links the `myceliumd` crate. The binary is not a separate feature; keep it as a compatibility/debug artifact until the package/service audit is complete. |
| `mycelium-frontdoor` | `mycelium-frontdoor` | Loopback TLS/Host router for `*.myc` services | operator | loopback listener, TLS keys | Could be a hidden `mycelium` mode; separate binary keeps its dependency graph out of the CLI. |
| `mycelium-ingress` | `mycelium-cli` (second `[[bin]]`) | Socket-activated `:443` byte forwarder and `:80` redirect | operator | privileged socket activation | One binary, two modes (`https`, `http-redirect`), two supervised processes. It is a binary target in the `mycelium-cli` crate, not its own crate. Keep the keyless process split; it can become `mycelium _ingress`. |
| `mycelium-dns-resolver` | `mycelium-driver-dnsmasq` | Legacy standalone resolver runner | migration only | dnsmasq child, DNS socket | `mycelium dns resolver run` is canonical. The installer now retires legacy `mycelium-dns-resolver` agents before applying the new resolver; remove the artifact after that migration has shipped. |
| `geoded` | `geoded` | Owner-only credential lease broker | opt-in | Unix socket, file-backed secret store | Installed only with `--geode`; its user service is upgraded by re-running that flag. |

### Tunnel

| Artifact | Source | Installer role | Required | Boundary | Notes |
|---|---|---|---|---|---|
| `iroh-tun` | `ajmwagar/iroh-tun` | L3 IPv6 tunnel child; root LaunchDaemon/systemd unit | VPN | `/dev/net/tun` or utun, iroh endpoint | Stays standalone by design. Depend on it with a pinned Cargo git dependency if shared types are needed, but do not fold its process into Mycelium. |

### VFS

| Artifact | Source | Installer role | Required | Boundary | Notes |
|---|---|---|---|---|---|
| `fungos-vfs` | `fungOS-linux/fungos-vfs` | Content CLI | VFS | filesystem, CID store | Keep native. |
| `fungos-vfs-provider` | same | Unibus content provider | VFS | Unibus client, file store | Candidate to fold into `fungos-vfs` as a subcommand. |
| `fungos-vfs-fetch` | same | Content fetch helper | VFS | network, file store | Candidate to fold into `fungos-vfs` as a subcommand. |
| `fungos-vfs-fuse` | same | FUSE mount | VFS with mount | kernel FUSE | Must stay native. |

### Soil

| Artifact | Source | Installer role | Required | Boundary | Notes |
|---|---|---|---|---|---|
| `soil` (`soil-shell`) | `fungOS-linux/soil` | CLI/shell | Soil | host process, VFS, terminal | Keep native as the host shell. |
| `soil-home` | soil runtime artifact | Home/namespace web view | Soil | HTTP + route file | Strong Spore candidate: rendering and route presentation can run in `soil-http-host`; the host grants file/route access. |
| `soil-store` | soil runtime artifact | Spore storefront and package verifier | Soil | HTTP + package files + signing | Split: storefront/listing can become a Spore; key custody, signing, and install approval stay native. |
| `soil-spore` | soil | Spore pack/sign/verify CLI | build tool | filesystem, signing keys | Keep native: it is the packaging/signing boundary. |
| `files-serve` | soil runtime artifact | Small static file server | optional | filesystem + HTTP | Strong Spore or `soil-http-host` candidate; eliminate a process if the host already serves static routes. |

### Build and desktop

| Artifact | Source | Installer role | Required | Boundary | Notes |
|---|---|---|---|---|---|
| `fpl-bob` | `FuturePresentLabs/bob` | sccache/sccache-dist client setup and remote build orchestration | optional | SSH, process spawn, compiler cache | Keep native; it launches processes and manages SSH/remote state. |
| `fungOS.app` (`canvas-winit`) | Studio / Canvas | macOS desktop app | macOS | window server, GPU, raw input | Keep native. The app may load wasm guests, but the window/GPU owner cannot be wasm. |

### Host dependencies

These are not built by the installer but are required by at least one component.

| Dependency | Used by | Needed when |
|---|---|---|
| `dnsmasq` | DNS resolver driver | DNS component; `mycelium dns resolver init` fails if absent |
| `openssl` | tunnel identity generation | VPN component |
| `curl`, `git` | source bootstrap and release downloads | first install / source build |
| `cargo`, `rustc` | source builds | no prebuilt binaries |
| `unzip` | `fungOS.app` archive install | macOS `--app-url` |
| `jq` | installer overlay detection (optional) | DNS zone parsing fallback |
| `macFUSE` / `libfuse` + `/dev/fuse` | VFS mount | VFS component |
| `systemd` user + system manager | Linux services | Linux installs |
| `systemd-resolved` 258+ | Linux DNS suffix delegation | preferred Linux DNS path |
| `ca-certificates` / `update-ca-certificates` | Linux frontdoor trust | operator `--trust-cert` |
| `ssh`, `tar` | `fpl-bob` remote builds | build offload |
| `sccache` | `fpl-bob` | downloaded and pinned by `fpl-bob setup`, not by the installer |

## Duplicates and consolidation order

### 1. Keep the daemon and DNS functionality; shrink artifacts after migration

`myceliumd` is a **crate**, and `mycelium _serve` is the managed process that
links it. The installer's launchd/systemd unit already runs `_serve`; dropping
the standalone `myceliumd` binary does not drop gossip, enrollment, or the
daemon. Keep the standalone binary for now as a compatibility/debug artifact
until the package and service audit is complete.

The DNS path is the same shape: `mycelium dns resolver run` is the canonical
service entry point, while `mycelium-dns-resolver` is the legacy binary used by
older LaunchAgents/systemd units. The installer now retires those legacy agents
before applying the current resolver, so dropping the legacy artifact is a
later cleanup, not a feature removal.

### 2. Consolidate HTTP and HTTPS ingress

`mycelium-ingress` is a second binary target in the `mycelium-cli` crate with two
modes: `https --target` moves raw bytes for the TLS frontdoor, and
`http-redirect` answers port 80 with a 301. They run as separate supervised
processes so the `:443` relay still never parses HTTP. The former
`mycelium-http-redirect` binary is gone; the previous `mycelium-https-forwarder`
service is retired during upgrade. A later cleanup can add a hidden
`mycelium _ingress` mode and point both units at `mycelium`, but the process
split and keyless boundary stay either way.

### 3. Decide whether the frontdoor is a binary or a mode

`mycelium-frontdoor` depends on axum/rustls and is intentionally separate from the
control-plane CLI. Folding it into `mycelium _frontdoor` would reduce one artifact
but grow the CLI dependency graph. This is a size/simplicity tradeoff, not a
correctness issue. My recommendation: keep the frontdoor separate until the
wasm32/Spore host story makes the frontdoor a capability of a smaller host.

### 4. Keep `iroh-tun` standalone

`iroh-tun` stays a standalone Unix process. Its tunnel device is a separate
privileged boundary, and keeping it independent is the Unix-principal choice.
Mycelium may depend on it through a pinned Cargo git dependency for shared
types, but the root service continues to execute the root-owned `iroh-tun`
binary from its own release. This avoids version skew through pinning, not
through vendoring.

### 5. Merge VFS provider/fetch into the VFS CLI

`fungos-vfs-provider` and `fungos-vfs-fetch` are subcommands in practice. One
`fungos-vfs` binary with `provider` and `fetch` modes removes two artifacts;
`fungos-vfs-fuse` stays separate because it owns the mount.

### 6. Move Soil presentation into Spores

`soil-home` and `files-serve` are the easiest wins: both are route/render
servers with narrow file access. `soil-store` needs a split because signing and
install approval are native authority, but its listing/verification display can
be a Spore. This is where wasm32 pays off: one host process (`soil`/`soil-http`)
serves many Spores instead of launching one native server per view.

## What must stay native

- OS tunnel devices and packet I/O (`iroh-tun`).
- FUSE mounts (`fungos-vfs-fuse`).
- Privileged socket activation (`mycelium-ingress`) and TLS key custody (frontdoor).
- Unix-socket daemon state, PKI, enrollment, and update activation (`mycelium`).
- Credential/key custody (`geoded`, `soil-spore` signing).
- Process/SSH orchestration (`fpl-bob`).
- Window server, GPU surfaces, and raw input (`canvas-winit` / `fungOS.app`).

## What should become wasm32

Use `wasm32-wasip2` for policy, rendering, and orchestration that runs inside an
already-authenticated Soil host:

- home and storefront views;
- static file serving;
- update/fleet status renderers;
- operator dashboards and diagnostics views;
- VFS content browsers once the host exposes the needed file/index capabilities.

The rule: **a Spore asks the host for a capability; it never gets an ambient
socket, key, tun device, or process-spawn handle.** That keeps the native
surface auditable and makes the release smaller, not just differently shaped.

The first release-script wasm32 hook should be a `wasm` artifact profile that
builds `spores-public` for `wasm32-wasip2` and stages the resulting `.wasm`
files beside the native archives. It should not try to turn `soil-home` or
`soil-store` into host processes on the way.

## Auto-start contract

The installer must leave these managed, not merely started:

- **macOS**: `dev.fpl.mycelium` LaunchAgent with `RunAtLoad` and `KeepAlive`;
  the root DNS/tunnel jobs are LaunchDaemons. The installer verifies that the
  LaunchAgent owns the live PID, so a CLI-started daemon cannot mask a failed
  service.
- **Linux**: `mycelium.service` in the user manager, enabled with `systemctl
  --user enable`; root DNS and tunnel units are system units. The installer
  waits for the unit to be active and the socket to appear.
- **DNS**: the current resolver is a persistent root daemon/unit; legacy
  `mycelium-dns-resolver` user agents are booted out and renamed before the new
  resolver is applied.
- **Geode**: only when `--geode` is selected; its user service is enabled and
  restarted on upgrade.

A daemon that is running but not owned by the service manager is not an
installed service. The repair path stops the unmanaged process, unloads the
old job, bootstraps the managed job, and verifies both the manager state and
the socket.

## Release ownership

The Mycelium repository can release its workspace artifacts today. `iroh-tun`,
`fungos-vfs`, Soil, `fpl-bob`, and `fungOS.app` still have independent source
trees and should get their own release jobs or be folded into this workspace
first. See [releasing.md](releasing.md) for the no-GitHub-Actions release path.
