# Releasing without GitHub Actions

`scripts/release.sh` is the release owner for the Mycelium workspace. It builds
the installer's native binaries, writes checksums and release metadata, and
creates or updates a GitHub release through the authenticated `gh` CLI. There is
no workflow file in the loop.

This first cut releases the Mycelium workspace only. `iroh-tun`, `fungos-vfs`,
Soil, `fpl-bob`, and `fungOS.app` still come from their own source trees and
need their own release step until they are folded into this workspace (see
[native-components.md](native-components.md)).

## What gets built

The current installer surface is:

```text
mycelium
myceliumd
mycelium-gateway
mycelium-https-forwarder
mycelium-dns-resolver
geoded
```

Each target becomes one tarball containing those binaries, `BUILD-INFO`, the
licenses, and a per-target `SHA256SUMS`. The release also gets an aggregate
`SHA256SUMS`, `release-metadata.json`, and `release-set.json` for the mesh
publisher.

`myceliumd` and `mycelium-dns-resolver` are compatibility artifacts. The
consolidation plan marks them for removal; keep them in the release until the
installer stops installing them.

## Prerequisites

- A clean checkout at the tag/commit being released, with Git credentials that
  can fetch tags.
- Rust with the requested target installed (`rustup target add ...`).
- `gh` authenticated with a token that can create releases (`repo` scope):
  `gh auth login` (or `GH_TOKEN` in the environment).
- For Linux musl artifacts, `cargo-zigbuild` and Zig on the build host.
- For signed macOS artifacts, a Developer ID identity in the keychain. Set
  `APPLE_SIGNING_IDENTITY`, or pass `--apple-identity`.
- Optional: a running `myceliumd` and an authorized release signing key for
  `--mesh`.

The script never stores a token in the repository. `gh` uses its own keyring or
`GH_TOKEN`, and the release signing key is only read by `--mesh`.

## Build locally

```sh
# Host target, no upload
scripts/release.sh --version 0.2.0

# One explicit target
scripts/release.sh --version 0.2.0 --target aarch64-apple-darwin

# Both macOS architectures on a macOS release host
scripts/release.sh --version 0.2.0 \
  --target aarch64-apple-darwin \
  --target x86_64-apple-darwin

# Linux musl on Linux (or macOS with cargo-zigbuild)
scripts/release.sh --version 0.2.0 \
  --target x86_64-unknown-linux-musl \
  --target aarch64-unknown-linux-musl
```

Output is under `dist/releases/v<version>/`. A dry run prints the cargo command
and staging paths without writing `dist/`:

```sh
scripts/release.sh --version 0.2.0 --target aarch64-apple-darwin --dry-run
```

## Publish to GitHub

```sh
scripts/release.sh --version 0.2.0 \
  --target aarch64-apple-darwin \
  --target x86_64-apple-darwin \
  --publish
```

The first host creates tag `v0.2.0` at the checked-out commit and uploads the
assets. A second host can run the same command for its targets; if the release
already exists, the script uploads the additional assets. Use `--clobber` only
when replacing a bad asset deliberately.

`--draft` creates a draft release for multi-host collection. Finish it with
`gh release edit v0.2.0 --draft=false` after every target has uploaded.

## Remote Linux builds

A macOS release host can send Linux builds to an x86_64 Linux worker through
`fpl-bob remote`. The worker needs a Rust toolchain, the requested targets, and
the normal `fpl bob setup` environment; the local command needs `fpl-bob` on
`PATH` (or set `MYCELIUM_RELEASE_FPL_BOB` to its absolute path for a timer).
`agora-one` is the reference worker: Ubuntu, x86_64, Rust 1.98.1, with
`aarch64-unknown-linux-gnu` and `aarch64-linux-gnu-gcc` installed.

```sh
# x86_64 native and aarch64 cross, both on agora-one
scripts/release.sh --version 0.2.0 \
  --target x86_64-unknown-linux-gnu \
  --target aarch64-unknown-linux-gnu \
  --remote-host agora-one \
  --remote-clean \
  --publish
```

`fpl-bob remote` uploads the source tree (excluding `target/` and `.git/`), runs
the cargo command under the worker's sccache environment, and copies
`target/<target>/release` back before the script stages it. `--remote-clean`
removes the worker workspace after copy-back; use it on workers with a small
`/tmp` (agora-one currently has about 3.7 GiB free there). `--remote-session`
can isolate concurrent releases.

The worker must already have the target installed. For `aarch64-unknown-linux-gnu`
the script sets `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc`;
for `armv7-unknown-linux-gnueabihf` it uses `arm-linux-gnueabihf-gcc`. agora-one
currently has the aarch64 target and linker; adding 32-bit ARM means:

```sh
rustup target add armv7-unknown-linux-gnueabihf
sudo apt-get install gcc-arm-linux-gnueabihf
```

If `cargo-zigbuild` is installed on the worker, musl targets can use the same
remote path; otherwise build musl locally or add the target/toolchain first.

GNU artifacts inherit the worker's glibc floor. The current script does not
record that floor, so prefer musl for broad distribution and treat GNU artifacts
as worker-qualified builds.

## From a tag

Release hosts should check out the tag, not build a branch tip:

```sh
git checkout v0.2.0
scripts/release.sh --from-tag v0.2.0 --target aarch64-apple-darwin --publish
```

The script verifies `HEAD` is exactly that tag and that `Cargo.toml` carries the
same version. `--allow-dirty` exists for local qualification and is not for a
published release.

## Automatic polling without Actions

`--watch` polls `v*` tags, checks each new tag out into a temporary worktree,
and runs the same release path. It records completed tags in
`dist/releases/state/released-tags`, so a failed build is retried and a published
one is skipped.

```sh
scripts/release.sh --watch --target aarch64-apple-darwin --interval 300
```

Run one watcher per host architecture. macOS watchers produce Apple artifacts;
instead of pretending one machine can notarize both platforms, run a Linux
watcher for Linux artifacts. A supervisor keeps the watcher alive:

```ini
# ~/.config/systemd/user/mycelium-release.service
[Unit]
Description=Mycelium release watcher
[Service]
ExecStart=%h/src/mycelium/scripts/release.sh --watch --target x86_64-unknown-linux-musl
Restart=always
RestartSec=60
[Install]
WantedBy=default.target
```

On macOS, a LaunchAgent with `ProgramArguments` pointing at the script and
`KeepAlive` is enough. The watcher needs a GitHub credential and a clean
worktree; do not run it on a developer's active checkout.

## Mesh publication

`--mesh` publishes the signed release set to the running daemon after the
build:

```sh
scripts/release.sh --version 0.2.0 \
  --target aarch64-apple-darwin \
  --publish \
  --mesh \
  --signing-key ~/.mycelium/release-signing.key
```

The key is authorized by `MYCELIUM_RELEASE_KEYS` on the daemon. Mesh publication
is separate from the GitHub release: GitHub is the artifact mirror, while the
mesh `ReleaseManifest` is how enrolled hosts discover and verify an update. If
`--mesh` is omitted, the GitHub release exists but automatic update discovery
does not see it.

## Signing and notarization

`--apple-identity` runs `codesign --force --options runtime --timestamp` and
verifies each macOS binary. It does not notarize them. Apple notarization needs
an app/archive submission and cannot be stapled to a raw CLI executable; this
repository still needs a signed/notarized distribution wrapper before macOS
Gatekeeper qualification can be claimed. The script warns when macOS artifacts
are unsigned rather than silently publishing them.

Linux artifacts built with `cargo zigbuild` against musl are the portable
default. A GNU target may be used for a host-specific package, but must record
its libc floor in the release metadata; the current script does not infer one.

## What is still missing

- A cross-repository release bundle for `iroh-tun`, VFS, Soil, bob, and
  `fungOS.app`.
- Notarized macOS packaging.
- A GitHub-release-aware `packaging/install.sh` (it still expects the
  `releases.fungos.dev` layout).
- Signed manifest files uploaded beside the artifacts. Today `--mesh` signs and
  publishes the set to the mesh; the GitHub mirror carries the unsigned
  `release-set.json` and checksums.
