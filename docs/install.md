# One-command workstation install

`install.sh` is the single entry point for a Mycelium workstation. It builds or
installs the core binaries, enrolls the node, and then asks which optional
components to install:

```sh
curl -fsSL https://raw.githubusercontent.com/fungOS-linux/mycelium/master/install.sh | bash
```

Use `--yes` for the recommended defaults, or answer the component prompts. The
prompts run in this order: IPv6 VPN (then sudo), VFS, Soil + `fungOS.app`, build
offload, operator surface, optional geode broker, enrollment. Every prompt can be
answered up front with the flags below. With no terminal, pass `--yes` or every
component flag; the installer stops rather than silently assuming defaults. A
source build is the default until these installer and `iroh-tun` supervisor
changes are in a signed release. The installer disables automatic updates for a local build by default
(the signed channel can otherwise replace it with an older release); pass
`--enable-updates` to keep them enabled.

> Until this branch lands on `master`, the raw `master` one-liner installs an
> older tree that cannot publish an external tunnel. Run the checkout directly:
> `./install.sh --source .`. The one-liner above is the command users should get
> once the branch is merged.

## Platform support

| | macOS | Linux |
|---|---|---|
| User services | LaunchAgents | `systemd --user` units |
| Root tunnel / DNS | LaunchDaemons | systemd system units |
| DNS suffix routing | `/etc/resolver/<suffix>` | systemd-resolved 258+ delegate; older hosts use a root stub and rewrite `/etc/resolv.conf` after backing it up |
| VFS mount | macFUSE | `/dev/fuse` |
| `fungOS.app` | Installed from an app bundle | macOS-only; skipped, while the Soil CLI/runtime still install |

The Linux path assumes a systemd host. Without a user systemd session, VFS,
Soil, and the user DNS listener still write their units, but startup can fail;
the installer reports the component. The privileged tunnel and DNS wiring still
use system units. User units start at login; run `loginctl enable-linger <user>`
if they must start before a login session exists.

## Components

| Component | What it does |
|---|---|
| Core (always) | Builds `mycelium`, `myceliumd`, the gateway, the DNS resolver and `geoded`; installs them under `~/.mycelium/bin` and `~/.local/bin`; enrolls or repairs the node. |
| Operator (default) | Installs the loopback HTTPS gateway and CA trust, agent skills, and shell completion. |
| VPN (default) | Builds `iroh-tun`, assigns an IPv6 overlay prefix, and installs a root-owned LaunchDaemon (macOS) or systemd unit (Linux). |
| VFS (default) | Builds `fungos-vfs` and its provider/fetch/FUSE binaries, creates the content root and mount point, and installs user services when their prerequisites exist. |
| Soil (default) | Builds the `soil` CLI, creates the fungOS data directories, installs `fungOS.app` on macOS when a bundle is supplied or present, and installs `soil-home`/`soil-store` as LaunchAgents or systemd user units when the runtime binaries are available. A failed CLI build is reported but does not block the app or runtime setup. |
| Geode (opt-in) | Installs the `geoded` broker and a user service with a private store under `~/.geode`. Re-run with `--geode` to upgrade it; omitting the flag leaves an existing service alone. |
| Build offload (default) | Builds `fpl-bob`, writes the sccache client configuration, and records the optional sccache-dist scheduler and remote build hosts. |

## The privileged tunnel

The user daemon owns the tunnel identity, the endpoint id, and the published
`iroh-tun` observation. It does **not** create the utun itself: macOS requires
root for that. Instead, the installer writes an `external: true` tunnel config
and installs a root-owned service:

- `/usr/local/libexec/mycelium/iroh-tun-root` runs the tunnel as root.
- Root-owned copies of `mycelium` and `iroh-tun` are used; root never executes a
  binary from the user's home.
- The status file lives in a root-owned directory (`/var/run/mycelium` on macOS,
  `/run/mycelium` on Linux), so a user-created symlink cannot redirect a root
  write. The user daemon reads the file and publishes the observation.
- The tunnel key remains user-owned at `~/.mycelium/iroh-tun.key`; the root
  wrapper reads it at runtime, so it is not embedded in a world-readable plist.

The installer asks for sudo immediately after you accept the VPN prompt, before
the long core build, and reuses that authorization for the DNS resolver service.
If you decline the VPN, the DNS resolver still needs root when its component
runs. Decline the VPN prompt (`--no-vpn`) if you do not want a tunnel root
service; that does not remove the DNS service's root requirement.

The installer starts the tunnel process; it does **not** add kernel routes. The
child learns peer prefixes and reports them, but route installation is still a
documented `iroh-tun` gap (see [iroh-tun.md](iroh-tun.md)). The overlay is
transport-ready, not yet a routed network without the operator adding routes.

To remove the root service later:

```sh
# macOS
sudo launchctl bootout system/dev.fpl.iroh-tun
sudo rm -f /Library/LaunchDaemons/dev.fpl.iroh-tun.plist
# Linux
sudo systemctl disable --now mycelium-iroh-tun
sudo rm -f /etc/systemd/system/mycelium-iroh-tun.service

mycelium iroh-tun config --enabled false --write
```

The root copies and status directory can then be removed:

```sh
sudo rm -rf /usr/local/libexec/mycelium /var/run/mycelium
```

## Useful invocations

```sh
# Recommended defaults, no prompts
./install.sh --yes --source .

# Use prebuilt binaries instead of building
./install.sh --bin-dir target/release

# Core and DNS only, no enrollment
./install.sh --no-enroll --no-vpn --no-vfs --no-soil --no-bob --no-operator

# Existing node: update binaries and restart the daemon, no enrollment
./install.sh --no-enroll --no-vpn

# Keep the signed update channel enabled
./install.sh --yes --enable-updates

# Enable or upgrade the optional geode broker later
./install.sh --geode

# Non-interactive claim redemption
curl -fsSL https://raw.githubusercontent.com/fungOS-linux/mycelium/master/install.sh \
  | bash -s -- --yes --claim MYC1-...

# See the plan without changing the machine
./install.sh --dry-run --yes --source .
```

`--dry-run` prints the component plan and the commands it would run. It does
not write files, start services, or ask for sudo.

## Component prerequisites

- **VPN**: an IPv6 overlay prefix. The installer detects this node's existing
  IPv6 `.myc` address when the daemon has one; otherwise pass `--overlay`.
- **DNS**: `dnsmasq` at a known path (`/usr/sbin`, `/usr/bin`, or the Homebrew
  paths). `mycelium dns resolver init` refuses to create a policy without it.
  The installer retires legacy `mycelium-dns-resolver` user agents before it
  applies the current resolver; the current root service/unit is persistent.
- **VFS FUSE**: macFUSE on macOS, `/dev/fuse` on Linux. Without it the VFS
  binaries are installed but the mount service is skipped.
- **Linux services**: a systemd host with a user session for the VFS, Soil, and
  user DNS units. A host without a user bus keeps the written units but cannot
  start them.
- **Linux DNS**: systemd-resolved 258+ provides suffix delegation without
  changing the default resolver. Older hosts use the root stub, which backs up
  `/etc/resolv.conf` and points it at `127.0.0.1`. That stub runs the CLI from
  `~/.mycelium/bin` so it inherits the user's mesh home; prefer 258+ where
  available.
- **VFS content provider**: a Unibus client config; pass `--vfs-config`. Without
  it the provider service is skipped.
- **Soil runtime services**: `--soil-runtime DIR` containing `soil-home`,
  `soil-store`, `soil-spore`, and `files-serve`. The `soil` CLI is built from
  source; the runtime binaries are a separate deployment artifact.
- **fungOS.app**: macOS only; pass `--app PATH` or `--app-url URL` (a `.zip`).
  The app is an ad-hoc-signed development build, so Gatekeeper may reject it
  even when the bundle is complete. Linux installs the Soil runtime without the
  app.
- **Geode**: optional. `--geode` creates `~/.geode`, starts `geoded` as a user
  service, and leaves the key/store in that directory. The installer does not
  remove an existing broker when the flag is omitted.
- **bob**: the source repository may require credentials; `--bob-src` or a local
  `~/Documents/src/bob` checkout avoids a clone. Scheduler URL/token are optional
  and prompt only when the component is selected.

## Rollback

Every replaced binary is backed up beside itself as `<name>.pre-<timestamp>`,
and the source tree/target artifacts are not removed. If a new binary is bad,
restore the previous file and restart the daemon:

```sh
mv ~/.mycelium/bin/mycelium.pre-20260101T000000 ~/.mycelium/bin/mycelium
mycelium daemon stop && mycelium daemon start
```
