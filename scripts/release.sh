#!/usr/bin/env bash
# Build and publish Mycelium releases without GitHub Actions.
#
# The script is intentionally a host-side release tool: it builds the
# workspace, signs what it can, writes a GitHub release, and can optionally
# publish the signed release set to the mesh. A timer or a person can run it;
# no workflow file is required.
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

VERSION=
CHANNEL=${MYCELIUM_RELEASE_CHANNEL:-canary}
TARGETS=()
OUT=${MYCELIUM_RELEASE_DIR:-$ROOT/dist/releases}
PUBLISH=0
DRY_RUN=0
ALLOW_DIRTY=0
ALLOW_VERSION_DRIFT=0
CLOBBER=0
DRAFT=0
MESH=0
FROM_TAG=
WATCH=0
WATCH_ONCE=0
INTERVAL=${MYCELIUM_RELEASE_INTERVAL:-300}
NOTES=
GH_REPO=${GH_REPO:-}
SIGNING_KEY=${MYCELIUM_RELEASE_SIGNING_KEY:-}
APPLE_IDENTITY=${APPLE_SIGNING_IDENTITY:-}

# These are the binaries the unified installer currently knows how to place.
# `myceliumd` and `mycelium-dns-resolver` are compatibility artifacts; see
# docs/native-components.md before removing them from this list.
COMPONENTS=(
    mycelium
    myceliumd
    mycelium-gateway
    mycelium-https-forwarder
    mycelium-dns-resolver
    geoded
)

ASSETS=()
BUILT_TARGETS=()

say() { printf '==> %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'USAGE'
usage: scripts/release.sh --version VERSION [options]

Builds the Mycelium workspace for one or more targets and optionally creates
or updates a GitHub release. No GitHub Actions workflow is involved.

Required (unless --watch):
  --version VERSION      release version, without the leading `v`

Targets:
  --target TRIPLE        target to build; repeatable (default: host target)
                         macOS: aarch64-apple-darwin, x86_64-apple-darwin
                         Linux: x86_64-unknown-linux-musl, aarch64-unknown-linux-musl

Publishing:
  --publish              create/upload the GitHub release with `gh`
  --draft                create the GitHub release as a draft
  --clobber              replace existing GitHub release assets
  --notes-file PATH      release notes; otherwise GitHub generates them
  --repo OWNER/REPO      GitHub repository (default: gh repo view)

Signing and mesh:
  --apple-identity NAME  codesign macOS binaries with this identity
  --mesh                 publish the signed release set to the running daemon
  --signing-key PATH     Ed25519 release key for --mesh

Automation:
  --watch                poll v* tags and release new ones; implies --publish
  --once                 with --watch, check once and exit
  --interval SECONDS     watch interval (default 300)

Other:
  --from-tag TAG         derive VERSION from TAG; HEAD must be at that tag
  --out DIR              output directory (default dist/releases)
  --allow-dirty          permit a dirty worktree
  --allow-version-drift  permit Cargo.toml version != --version
  --dry-run              print the plan; do not build or publish
  -h, --help             this text
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version) [ $# -ge 2 ] || die "--version needs a value"; VERSION=$2; shift 2 ;;
        --target) [ $# -ge 2 ] || die "--target needs a value"; TARGETS+=("$2"); shift 2 ;;
        --publish) PUBLISH=1; shift ;;
        --draft) DRAFT=1; shift ;;
        --clobber) CLOBBER=1; shift ;;
        --notes-file) [ $# -ge 2 ] || die "--notes-file needs a path"; NOTES=$2; shift 2 ;;
        --repo) [ $# -ge 2 ] || die "--repo needs OWNER/REPO"; GH_REPO=$2; shift 2 ;;
        --apple-identity) [ $# -ge 2 ] || die "--apple-identity needs a name"; APPLE_IDENTITY=$2; shift 2 ;;
        --mesh) MESH=1; shift ;;
        --signing-key) [ $# -ge 2 ] || die "--signing-key needs a path"; SIGNING_KEY=$2; shift 2 ;;
        --watch) WATCH=1; PUBLISH=1; shift ;;
        --once) WATCH_ONCE=1; shift ;;
        --interval) [ $# -ge 2 ] || die "--interval needs seconds"; INTERVAL=$2; shift 2 ;;
        --from-tag) [ $# -ge 2 ] || die "--from-tag needs a tag"; FROM_TAG=$2; shift 2 ;;
        --out) [ $# -ge 2 ] || die "--out needs a directory"; OUT=$2; shift 2 ;;
        --allow-dirty) ALLOW_DIRTY=1; shift ;;
        --allow-version-drift) ALLOW_VERSION_DRIFT=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
done

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

absolute_path() {
    case "$1" in
        /*) printf '%s' "$1" ;;
        *) printf '%s/%s' "$ROOT" "$1" ;;
    esac
}

if [ -n "$OUT" ]; then OUT=$(absolute_path "$OUT"); fi
if [ -n "$NOTES" ]; then NOTES=$(absolute_path "$NOTES"); fi
if [ -n "$SIGNING_KEY" ]; then SIGNING_KEY=$(absolute_path "$SIGNING_KEY"); fi

host_target() {
    rustc -vV 2>/dev/null | sed -n 's/^host: //p'
}

require_version() {
    [ -n "$VERSION" ] || die "--version is required (or use --from-tag)"
    case "$VERSION" in
        *[!0-9A-Za-z.+-]*) die "invalid version: $VERSION" ;;
    esac
    [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]] \
        || die "version must be semver, got: $VERSION"
}

workspace_version() {
    sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1
}

check_clean() {
    [ "$ALLOW_DIRTY" = 1 ] && return 0
    if [ -n "$(git status --porcelain)" ]; then
        die "worktree has uncommitted changes; commit them or pass --allow-dirty"
    fi
}

check_tag() {
    if [ -n "$FROM_TAG" ]; then
        VERSION=${FROM_TAG#v}
        git rev-parse --verify "$FROM_TAG^{commit}" >/dev/null 2>&1 \
            || die "tag does not exist: $FROM_TAG"
        [ "$(git rev-parse HEAD)" = "$(git rev-parse "$FROM_TAG^{commit}")" ] \
            || die "HEAD is not at $FROM_TAG; check out the tag first"
    fi
    require_version
    local manifest
    manifest=$(workspace_version)
    if [ -n "$manifest" ] && [ "$VERSION" != "$manifest" ] && [ "$ALLOW_VERSION_DRIFT" != 1 ]; then
        die "Cargo.toml says $manifest, releasing $VERSION; bump it or pass --allow-version-drift"
    fi
}

default_targets() {
    if [ ${#TARGETS[@]} -eq 0 ]; then
        local target
        target=$(host_target)
        [ -n "$target" ] || die "cannot determine host target; pass --target"
        TARGETS=("$target")
    fi
}

build_target() {
    local target=$1
    local target_dir="$ROOT/target/$target/release"
    local stage="$OUT/v$VERSION/$target"
    local build
    build=(cargo build --release --locked --target "$target"
        -p mycelium-cli --features mycelium-cli/iroh-sync
        -p mycelium-gateway -p mycelium-driver-dnsmasq -p geoded -p myceliumd)
    if [[ "$target" == *-unknown-linux-musl ]] && command -v cargo-zigbuild >/dev/null 2>&1; then
        build=(cargo zigbuild --release --locked --target "$target"
            -p mycelium-cli --features mycelium-cli/iroh-sync
            -p mycelium-gateway -p mycelium-driver-dnsmasq -p geoded -p myceliumd)
    fi
    say "Building $target"
    if [ "$DRY_RUN" = 1 ]; then
        note "+ ${build[*]}"
        note "would stage $stage"
        return 0
    fi
    "${build[@]}"

    rm -rf "$stage"
    mkdir -p "$stage"
    local binary
    for binary in "${COMPONENTS[@]}"; do
        [ -f "$target_dir/$binary" ] || die "missing build output: $target_dir/$binary"
        install -m 755 "$target_dir/$binary" "$stage/$binary"
    done

    if [[ "$target" == *-apple-darwin ]] && [ -n "$APPLE_IDENTITY" ]; then
        for binary in "${COMPONENTS[@]}"; do
            codesign --force --options runtime --timestamp \
                --sign "$APPLE_IDENTITY" "$stage/$binary"
            codesign --verify --strict "$stage/$binary"
        done
    elif [[ "$target" == *-apple-darwin ]]; then
        warn "macOS binaries are unsigned; pass --apple-identity to codesign"
    fi

    {
        printf 'version=%s\n' "$VERSION"
        printf 'channel=%s\n' "$CHANNEL"
        printf 'target=%s\n' "$target"
        printf 'commit=%s\n' "$(git rev-parse HEAD)"
        printf 'built_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'rustc=%s\n' "$(rustc --version 2>/dev/null || echo unknown)"
        printf 'components=%s\n' "${COMPONENTS[*]}"
    } >"$stage/BUILD-INFO"
    cp -f LICENSE LICENSE-APACHE "$stage/"

    : >"$stage/SHA256SUMS"
    for binary in "${COMPONENTS[@]}" BUILD-INFO LICENSE LICENSE-APACHE; do
        printf '%s  %s\n' "$(sha256_file "$stage/$binary")" "$binary" >>"$stage/SHA256SUMS"
    done

    local asset="$OUT/v$VERSION/mycelium-v$VERSION-$target.tar.gz"
    mkdir -p "$OUT/v$VERSION"
    tar -C "$stage" -czf "$asset" .
    ASSETS+=("$asset")
    BUILT_TARGETS+=("$target")
    note "wrote $asset"
}

write_release_metadata() {
    local dir="$OUT/v$VERSION"
    local set="$dir/release-set.json"
    local metadata="$dir/release-metadata.json"
    local target
    if [ "$DRY_RUN" = 1 ]; then
        note "would write $set"
        note "would write $metadata"
        return 0
    fi
    mkdir -p "$dir"
    {
        printf '{\n  "version": "%s",\n  "channel": "%s",\n  "artifacts": [' "$VERSION" "$CHANNEL"
        local first=1
        for target in "${BUILT_TARGETS[@]}"; do
            [ "$first" = 1 ] || printf ','
            first=0
            printf '\n    {"target": "%s", "binary": "%s/mycelium"}' \
                "$target" "$target"
        done
        printf '\n  ]\n}\n'
    } >"$set"
    {
        printf '{\n  "version": "%s",\n  "channel": "%s",\n  "commit": "%s",\n  "generated_at": "%s",\n  "targets": [\n' \
            "$VERSION" "$CHANNEL" "$(git rev-parse HEAD)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        local first=1
        for target in "${BUILT_TARGETS[@]}"; do
            [ "$first" = 1 ] || printf ',\n'
            first=0
            printf '    {"target": "%s", "archive": "mycelium-v%s-%s.tar.gz", "sha256": "%s"}' \
                "$target" "$VERSION" "$target" "$(sha256_file "$dir/mycelium-v$VERSION-$target.tar.gz")"
        done
        printf '\n  ]\n}\n'
    } >"$metadata"
    ASSETS+=("$set" "$metadata")
    : >"$dir/SHA256SUMS"
    local asset
    for asset in "${ASSETS[@]}"; do
        [ -f "$asset" ] || continue
        printf '%s  %s\n' "$(sha256_file "$asset")" "$(basename "$asset")" >>"$dir/SHA256SUMS"
    done
    ASSETS+=("$dir/SHA256SUMS")
}

publish_release() {
    [ "$PUBLISH" = 1 ] || return 0
    local tag="v$VERSION"
    if [ "$DRY_RUN" = 1 ]; then
        note "would publish $tag to ${GH_REPO:-the current GitHub repository} with the archives and metadata"
        return 0
    fi
    command -v gh >/dev/null 2>&1 || die "gh is required for --publish"
    gh auth status >/dev/null 2>&1 || die "gh is not authenticated; run gh auth login"
    if [ -z "$GH_REPO" ]; then
        GH_REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || true)
    fi
    [ -n "$GH_REPO" ] || die "cannot determine GitHub repository; pass --repo"
    local args=()
    if [ -n "$NOTES" ]; then
        args+=(--notes-file "$NOTES")
    else
        args+=(--generate-notes)
    fi
    if gh release view "$tag" --repo "$GH_REPO" >/dev/null 2>&1; then
        if [ "$CLOBBER" = 1 ]; then
            gh release upload "$tag" "${ASSETS[@]}" --repo "$GH_REPO" --clobber
        else
            gh release upload "$tag" "${ASSETS[@]}" --repo "$GH_REPO"
        fi
    else
        [ "$DRAFT" = 1 ] && args+=(--draft)
        [ "$CHANNEL" != stable ] && args+=(--prerelease)
        gh release create "$tag" --repo "$GH_REPO" \
            --title "Mycelium $tag" --target "$(git rev-parse HEAD)" \
            "${args[@]}" "${ASSETS[@]}"
    fi
}

publish_mesh() {
    [ "$MESH" = 1 ] || return 0
    [ -n "$SIGNING_KEY" ] || die "--mesh needs --signing-key"
    local set="$OUT/v$VERSION/release-set.json"
    if [ "$DRY_RUN" = 1 ]; then
        note "would publish $set to the mesh with $SIGNING_KEY"
        return 0
    fi
    [ -f "$set" ] || die "missing $set"
    local binary="$ROOT/target/release/mycelium"
    [ -x "$binary" ] || binary=$(command -v mycelium || true)
    [ -n "$binary" ] && [ -x "$binary" ] || die "mycelium CLI is needed for --mesh"
    "$binary" releases publish-set --manifest "$set" --signing-key "$SIGNING_KEY" --write
}

run_once() {
    check_tag
    check_clean
    default_targets
    local target
    for target in "${TARGETS[@]}"; do
        build_target "$target"
    done
    write_release_metadata
    publish_release
    publish_mesh
    say "Release $VERSION staged in $OUT/v$VERSION"
}

watch_tags() {
    [ "$PUBLISH" = 1 ] || die "--watch requires --publish"
    local state="$OUT/state"
    local released="$state/released-tags"
    mkdir -p "$state"
    touch "$released"
    while true; do
        git fetch --tags --quiet origin || warn "could not fetch tags; using local tags"
        local tag
        while IFS= read -r tag; do
            [ -n "$tag" ] || continue
            grep -qxF "$tag" "$released" 2>/dev/null && continue
            local version=${tag#v}
            local worktree="$state/worktrees/$tag"
            rm -rf "$worktree"
            if ! git worktree add --detach "$worktree" "$tag" >/dev/null 2>&1; then
                warn "could not create worktree for $tag; will retry"
                continue
            fi
            local args=(--version "$version" --channel "$CHANNEL" --publish --out "$OUT")
            local target
            for target in "${TARGETS[@]}"; do args+=(--target "$target"); done
            [ "$CLOBBER" = 1 ] && args+=(--clobber)
            [ "$DRAFT" = 1 ] && args+=(--draft)
            [ -n "$GH_REPO" ] && args+=(--repo "$GH_REPO")
            [ -n "$APPLE_IDENTITY" ] && args+=(--apple-identity "$APPLE_IDENTITY")
            [ "$MESH" = 1 ] && args+=(--mesh --signing-key "$SIGNING_KEY")
            if ( cd "$worktree" && "$worktree/scripts/release.sh" "${args[@]}" ); then
                printf '%s\n' "$tag" >>"$released"
                say "released $tag"
            else
                warn "release $tag failed; will retry"
            fi
            git worktree remove --force "$worktree" >/dev/null 2>&1 || true
        done < <(git tag -l 'v*' --sort=v:refname)
        [ "$WATCH_ONCE" = 1 ] && return 0
        sleep "$INTERVAL"
    done
}

if [ "$WATCH" = 1 ]; then
    default_targets
    if [ "$DRY_RUN" = 1 ]; then
        note "would poll v* tags for ${TARGETS[*]} and publish"
        exit 0
    fi
    watch_tags
else
    run_once
fi
