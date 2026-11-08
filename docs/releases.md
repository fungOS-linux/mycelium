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

## Reporting

Use the fleet view for a per-host update report:

```sh
mycelium update status --fleet
mycelium update status --fleet --json
mycelium update report
mycelium update report --json
mycelium update report --fail-on-updates
```

`update report` summarizes the local binary and every gossiped peer:

```text
update report (channel=canary):
  local: 0.2.4 (update state), latest=0.2.4 target=aarch64-apple-darwin verdict=current
  hosts: 21 total, 5 current, 4 need update, 3 ahead, 9 unknown
  need update:
    fungos-edge-clean-01 0.1.37 -> 0.2.4
  unknown:
    fpl-beachhead-2 (release unrecorded)
  spores: no catalog (Spore Store is not implemented; see mycelium-6sm2)
```

The JSON shape is the stable contract for an updater Spore:

```json
{
  "channel": "canary",
  "local": {
    "version": "0.2.4",
    "source": "update state",
    "digest_matches": true,
    "latest_version": "0.2.4",
    "latest_target": "aarch64-apple-darwin",
    "verdict": "current"
  },
  "summary": {
    "total": 21,
    "current": 5,
    "update_available": 4,
    "ahead": 3,
    "unknown": 9
  },
  "hosts": [
    {
      "hostname": "fungos-edge-clean-01",
      "release_version": "0.1.37",
      "latest_version": "0.2.4",
      "verdict": "update-available",
      "needs_update": true
    }
  ],
  "spores": {
    "supported": false,
    "reason": "Spore Store is not implemented; see mycelium-6sm2"
  }
}
```

`--fail-on-updates` prints the report and exits non-zero when the local binary
or a peer has a known update available. Unrecorded hosts remain `unknown`
rather than causing a false failure.

## Updater Spore (planned)

An updater Spore should be a read-only renderer over the `update report --json`
contract, not an update authority. It can show fleet propagation, per-target
lag, staged/active state, and eventually Spore versions. Two prerequisites are
still missing: the Spore Store/S3 signed-manifest path (`mycelium-6sm2`) and a
narrow Mycelium read capability exposed to Soil. Until then, the CLI report is
the supported surface and the JSON shape is the interface to build against.

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
