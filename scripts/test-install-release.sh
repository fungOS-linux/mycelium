#!/usr/bin/env bash
# Tests for install.sh's release download and checksum verification.
#
# Run: scripts/test-install-release.sh
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/mycelium-install-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
ok() { printf 'ok - %s\n' "$1"; }

MYCELIUM_INSTALL_LIB=1
export MYCELIUM_INSTALL_LIB
# shellcheck disable=SC1091
source "$ROOT/install.sh"

targets=$(release_targets) || fail "no release target for $(uname -s)/$(uname -m)"
target=$(printf '%s\n' "$targets" | head -1)
version=0.0.0-test
asset="mycelium-v$version-$target.tar.gz"

fixture() {
    dir=$1
    rm -rf "$WORK/stage"
    mkdir -p "$dir" "$WORK/stage"
    printf '#!/bin/sh\necho mycelium-test\n' >"$WORK/stage/mycelium"
    chmod +x "$WORK/stage/mycelium"
    tar -C "$WORK/stage" -czf "$dir/$asset" .
    sha=$(sha256_file "$dir/$asset")
    cat >"$dir/release-metadata.json" <<EOF
{
  "version": "$version",
  "channel": "test",
  "commit": "0",
  "generated_at": "1970-01-01T00:00:00Z",
  "targets": [
    {"target": "$target", "archive": "$asset", "sha256": "$sha"}
  ]
}
EOF
    printf '%s  %s\n' "$sha" "$asset" >"$dir/SHA256SUMS"
}

release=$WORK/release
fixture "$release"
RELEASE_VERSION=$version
RELEASE_BASE="file://$release"
fetch_release
[ -x "$RELEASE_DIR/mycelium" ] || fail "release binary was not unpacked"
grep -q 'mycelium-test' "$RELEASE_DIR/mycelium" || fail "unpacked the wrong binary"
ok "downloads, verifies, and unpacks a release"
rm -rf "$RELEASE_DIR"
RELEASE_DIR=

bad=$WORK/bad
cp -R "$release" "$bad"
printf 'tampered\n' >>"$bad/$asset"
if (RELEASE_VERSION=$version; RELEASE_BASE="file://$bad"; fetch_release) >/dev/null 2>&1; then
    fail "a tampered archive was accepted"
fi
ok "rejects a tampered archive"

bad=$WORK/bad-sums
cp -R "$release" "$bad"
printf 'deadbeef  %s\n' "$asset" >"$bad/SHA256SUMS"
if (RELEASE_VERSION=$version; RELEASE_BASE="file://$bad"; fetch_release) >/dev/null 2>&1; then
    fail "disagreeing checksum sources were accepted"
fi
ok "rejects metadata and SHA256SUMS that disagree"

bad=$WORK/bad-no-sums
cp -R "$release" "$bad"
rm "$bad/SHA256SUMS"
if (RELEASE_VERSION=$version; RELEASE_BASE="file://$bad"; fetch_release) >/dev/null 2>&1; then
    fail "a release without SHA256SUMS was accepted"
fi
ok "rejects a release without SHA256SUMS"

printf 'all install release tests passed\n'
