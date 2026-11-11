#!/bin/sh
# Bootstrap a Mycelium node.
#
#   curl -fsSL https://fungos.dev/install.sh | sh
#   curl -fsSL https://fungos.dev/install.sh | sh -s -- --join MYC1-…
#   curl -fsSL https://fungos.dev/install.sh | sh -s -- --new-principal
#
# Works on macOS and Linux, with no assumptions about a TTY: the script never
# prompts, so it is safe to pipe into a shell on a fresh VM.
#
# A node cannot mint its own invitation. The authority CA lives on an existing
# device, so joining is: mint there, redeem here. Without --join the script
# prints exactly that instruction and exits successfully, so a provisioner can
# run it before it has the claim.
set -eu

PREFIX=${MYCELIUM_PREFIX:-$HOME/.local}
BASE=${MYCELIUM_RELEASE_URL:-https://releases.fungos.dev/mycelium}
CHANNEL=${MYCELIUM_CHANNEL:-canary}
DRY_RUN=0
CLAIM=""
MODE=join

die() { printf 'install: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }

usage() {
    cat <<'USAGE'
usage: install.sh [--join CLAIM | --new-principal] [--dry-run]

  --join CLAIM     Redeem an invitation minted on a device you already trust.
  --new-principal  Start a new fleet: this node becomes its own authority.
  --dry-run        Print what would happen; change nothing.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --join) [ $# -ge 2 ] || die "--join needs a claim"; CLAIM=$2; shift 2 ;;
        --new-principal) MODE=new; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

case "$(uname -s)" in
    Darwin) os=apple-darwin ;;
    Linux)  os=unknown-linux-gnu ;;
    *) die "unsupported system: $(uname -s)" ;;
esac
case "$(uname -m)" in
    arm64|aarch64) arch=aarch64 ;;
    x86_64|amd64)  arch=x86_64 ;;
    *) die "unsupported architecture: $(uname -m)" ;;
esac
target="$arch-$os"

# $HOME only. /tmp does not survive a snapshot, and /bin is sealed on the
# images we run on.
bindir="$PREFIX/bin"
say "install: target $target, prefix $PREFIX"
[ "$DRY_RUN" = 1 ] && { say "install: dry run; stopping before any change"; exit 0; }

fetch() {
    if command -v curl >/dev/null 2>&1; then curl -fsSL "$1"
    elif command -v wget >/dev/null 2>&1; then wget -qO- "$1"
    else die "need curl or wget"
    fi
}

mkdir -p "$bindir"
url="$BASE/$CHANNEL/$target/mycelium"
say "install: fetching $url"
tmp="$bindir/.mycelium.download.$$"
trap 'rm -f "$tmp"' EXIT INT TERM
fetch "$url" > "$tmp" || die "download failed: $url"
chmod 755 "$tmp"
mv -f "$tmp" "$bindir/mycelium"
trap - EXIT INT TERM
say "install: installed $bindir/mycelium"

# Anything after this point is mycelium's own business. Keeping the script thin
# means the installer cannot drift from what `setup` actually does.
case "$MODE" in
    join)
        if [ -n "$CLAIM" ]; then
            claim_file="${MYCELIUM_HOME:-$HOME/.mycelium}/claim.txt"
            mkdir -p "$(dirname "$claim_file")"
            printf '%s\n' "$CLAIM" > "$claim_file"
            # The claim is a credential; setup refuses anything group- or
            # world-readable.
            chmod 600 "$claim_file"
            say "install: redeeming invitation"
            "$bindir/mycelium" setup --claim-file "$claim_file" || die "enrollment failed"
            rm -f "$claim_file"
        else
            say ""
            say "This node is installed but not enrolled."
            say ""
            say "On a device you already trust, mint an invitation:"
            say "    mycelium pair --kind peer --site <site> --iroh --public-relays"
            say ""
            say "Then redeem it here:"
            say "    mycelium setup --claim-file <claim.txt>"
            say ""
            say "--public-relays matters: without it the invitation carries only this"
            say "host's LAN and tailnet addresses, and a node anywhere else times out."
        fi
        ;;
    new)
        say "install: starting a new principal on this node"
        "$bindir/mycelium" setup --system-service || die "principal setup failed"
        ;;
esac

say ""
say "install: checking the node"
"$bindir/mycelium" doctor || die "doctor reported a problem; see the failing checks above"
say "install: systems nominal"
