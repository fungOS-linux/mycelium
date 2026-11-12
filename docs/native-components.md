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
| `myceliumd` | `myceliumd` | Standalone daemon binary | no | same as `_serve` | Installer ships it, but no service definition uses it. Duplicate artifact candidate. |
| `mycelium-gateway` | `mycelium-gateway` | Loopback TLS/Host router for `*.myc` services | operator | loopback listener, TLS keys | Could be a hidden `mycelium` mode; separate binary keeps its dependency graph out of the CLI. |
| `mycelium-https-forwarder` | `mycelium-cli` | Socket-activated `:443` byte forwarder | operator | privileged socket activation | Separate process by design; it holds no keys. Same binary can host a hidden mode. |
| `mycelium-dns-resolver` | `mycelium-driver-dnsmasq` | Legacy standalone resolver runner | no | dnsmasq child, DNS socket | `mycelium dns resolver run` is the canonical path. Installer ships both. Duplicate artifact candidate. |
| `geoded` | `geoded` | Owner-only credential lease broker | optional | Unix socket, file-backed secret store | Installer builds it but installs no service. Move behind an explicit `--geode` component or fold into a hidden CLI mode. |

### Tunnel

| Artifact | Source | Installer role | Required | Boundary | Notes |
|---|---|---|---|---|---|
| `iroh-tun` | `ajmwagar/iroh-tun` | L3 IPv6 tunnel child; root LaunchDaemon/systemd unit | VPN | `/dev/net/tun` or utun, iroh endpoint | Cannot be wasm: it owns an OS tunnel device. Natural candidate to move into the Mycelium workspace as `mycelium _iroh-tun` or a `mycelium-iroh-tun` crate, which removes a separate repository/release. |

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
| `ca-certificates` / `update-ca-certificates` | Linux gateway trust | operator `--trust-cert` |
| `ssh`, `tar` | `fpl-bob` remote builds | build offload |
| `sccache` | `fpl-bob` | downloaded and pinned by `fpl-bob setup`, not by the installer |

## Duplicates and consolidation order

### 1. Drop duplicate daemon/resolver artifacts

`myceliumd` and `mycelium-dns-resolver` are not wired by the installer service
definitions. The canonical entry points already exist:

- `mycelium _serve` is what launchd/systemd start.
- `mycelium dns resolver run` is what the DNS unit starts.

Removing these two binaries from release artifacts and `install.sh` is the
lowest-risk reduction: the source crates remain, but the release surface shrinks.
Keep the standalone targets for one release as debugging tools if needed, then
remove them.

### 2. Fold the HTTPS forwarder into `mycelium`

`mycelium-https-forwarder` is a tiny process with a security-relevant split: it
accepts the privileged socket and has no keys. That split should remain, but it
does not need a separate executable. Add a hidden `mycelium _https-forwarder`
mode and point the socket units at the `mycelium` binary. The process remains
unprivileged, keyless, and socket-activated.

### 3. Decide whether the gateway is a binary or a mode

`mycelium-gateway` depends on axum/rustls and is intentionally separate from the
control-plane CLI. Folding it into `mycelium _gateway` would reduce one artifact
but grow the CLI dependency graph. This is a size/simplicity tradeoff, not a
correctness issue. My recommendation: keep the gateway separate until the
wasm32/Spore host story makes the gateway a capability of a smaller host.

### 4. Move `iroh-tun` into the Mycelium workspace

This is the highest-value consolidation after the duplicates: it removes a
cross-repository release, a version-skew source, and one root-owned artifact.
The root service would execute root-owned `mycelium _iroh-tun`; the user daemon
would publish the status exactly as it does now. The process split stays.

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
- Privileged socket activation and TLS key custody (`https-forwarder`, gateway).
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

## Release ownership

The Mycelium repository can release its workspace artifacts today. `iroh-tun`,
`fungos-vfs`, Soil, `fpl-bob`, and `fungOS.app` still have independent source
trees and should get their own release jobs or be folded into this workspace
first. See [releasing.md](releasing.md) for the no-GitHub-Actions release path.
