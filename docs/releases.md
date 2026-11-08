# Release gossip, signing, and update checks

Mycelium ships its own releases through the peer mesh. A release is a
`ReleaseManifest` carrying version, channel, target triple, protocol version,
artifact size/digest, signer, and an Ed25519 signature over those fields. The
daemon admits a release only when the signer is authorized by
`MYCELIUM_RELEASE_KEYS`; the signature and artifact digest are verified again
before activation.

## What works today

- `mycelium update status` resolves the newest signed release for the local
target and configured channel (`MYCELIUM_UPDATE_CHANNEL`, `canary` by default)
and shows whether its artifact is cached.
- `mycelium update apply --write` verifies size and digest, writes the binary
atomically, runs `_self-check`, updates systemd/launchd, and records
`UpdateState`.
- `mycelium update policy` can enable a channel-aware automatic rollout with a
minimum age, rollout window, and retry backoff; `update auto-run` is the
periodic entry point.
- `mycelium update status --fleet` projects the gossiped
`mycelium_update.*` health metrics. Each peer row now includes `latest_version`
and `needs_update`, resolved against that peer's recorded target and channel.
- `mycelium doctor` compares the running binary and recorded update state with
the newest signed release for the local channel/target. It warns when an update
is available or the binary is a local/unrecorded build, and fails when the
latest manifest's signature is invalid.

Version selection is semantic-version based. Earlier code compared version
strings, so `0.2.14` sorted below `0.2.4`.

## Signing and notarization

Release signing is Ed25519 under the fleet authority. Publishing a release
requires `release.publish` authorization; a peer cannot promote its own build.
Artifacts are content-addressed and re-hashed at activation.

Apple code signing and notarization are not implemented by this repository.
The release pipeline must `codesign` and notarize the macOS binary before
publishing its manifest. `mycelium doctor` surfaces this on macOS with
`binary signature` (`codesign --verify`) and `binary notarization`
(`spctl --assess`) checks. A locally built binary is expected to warn on both.

## Known gaps

- Peers do not gossip their update channel yet; the fleet view uses the local
  channel.
- Rollout cohorts, staged rollback, and per-target fleet policy are not
  implemented.
- A binary built outside the signed release path has no matching digest, so
  doctor reports its release as `unrecorded` rather than guessing.
- Spore distribution is a separate subsystem. Per `docs/soil-capabilities.md`
  (E.6), the Spore Store is a later slice and S3 signed manifests/generations
  must land before fetching Spores from peers or a shared store.
