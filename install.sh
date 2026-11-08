#!/bin/sh
set -eu

gateway="${MYCELIUM_GATEWAY:-https://sso.fpl.dev}"

if ! command -v curl >/dev/null 2>&1; then
  echo "mycelium install: curl is required" >&2
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "Installing the Rust toolchain..."
  curl --proto '=https' --tlsv1.2 -fsS https://sh.rustup.rs | sh -s -- -y --profile minimal
fi

rust_bin="${CARGO_HOME:-$HOME/.cargo}/bin"
PATH="$rust_bin:$PATH"
export PATH

echo "Building Mycelium from the public repository..."
cargo install --git https://github.com/ajmwagar/mycelium.git \
  mycelium-cli mycelium-gateway --locked --force

echo "Starting secure browser enrollment..."
exec mycelium setup --gateway "$gateway" "$@"
