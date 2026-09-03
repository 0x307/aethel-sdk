#!/usr/bin/env bash
#
# Re-vendor the aethel-core component from a pinned revision.
#
#   scripts/sync-core.sh            # rebuild at the revision in core/pin.toml
#   scripts/sync-core.sh <rev>      # move the pin to <rev>, then rebuild
#
# This is the one command. It re-pulls the WIT world, rebuilds the component,
# rewrites the declared hash, and leaves core/ consistent with the pin. The
# bindings in src/component.rs are generated from core/wit at compile time, so
# `cargo test` after this picks up a reshaped world with no hand edits.
#
# The build runs in a container pinned to the canonical platform and toolchain,
# because the component hash is platform-specific: the same source built on
# Windows or macOS produces different bytes. Running it in the container is what
# lets a canonical artifact be produced (and checked) from any host.
#
# Requires: docker, and network access to github.com.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pin="$repo_root/core/pin.toml"

value_of() { grep -E "^$1 *=" "$pin" | head -1 | sed -E 's/.*= *"(.*)".*/\1/'; }

core_repo="$(value_of repository)"
rust_version="$(value_of rust)"
wasm_tools_version="$(value_of 'wasm-tools')"
rev="${1:-$(value_of rev)}"

if [ -z "$core_repo" ] || [ -z "$rust_version" ] || [ -z "$wasm_tools_version" ] || [ -z "$rev" ]; then
  echo "could not read core/pin.toml" >&2
  exit 1
fi

echo "aethel-core   $core_repo"
echo "revision      $rev"
echo "rust          $rust_version"
echo "wasm-tools    $wasm_tools_version"
echo

out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

cat > "$out/build.sh" <<'INNER'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl ca-certificates git xz-utils gcc >/dev/null

# Mirror the CI runner's paths. rustc embeds them, so they are part of the
# artifact's identity.
export HOME=/home/runner
mkdir -p /home/runner/work/aethel-core
cd /home/runner/work/aethel-core
git clone -q "$CORE_REPO" aethel-core
cd aethel-core
git checkout -q "$CORE_REV"

curl -sSf https://sh.rustup.rs -o /tmp/rustup.sh
sh /tmp/rustup.sh -y --default-toolchain "$RUST_VERSION" \
  --target wasm32-unknown-unknown --profile minimal >/dev/null 2>&1
. "$HOME/.cargo/env"

curl -sSL "https://github.com/bytecodealliance/wasm-tools/releases/download/v${WASM_TOOLS_VERSION}/wasm-tools-${WASM_TOOLS_VERSION}-x86_64-linux.tar.gz" -o /tmp/wt.tgz
tar xzf /tmp/wt.tgz -C /tmp
export PATH="/tmp/wasm-tools-${WASM_TOOLS_VERSION}-x86_64-linux:$PATH"

build_once() {
  rm -rf target/wasm32-unknown-unknown/release
  # The pinned upstream revision emits these known library-only lints while
  # compiling its component. They neither affect the generated Wasm nor signal
  # a problem with the reproducible artifact this script validates.
  RUSTFLAGS="${RUSTFLAGS:-} -Aunexpected_cfgs -Adead_code -Amissing_docs" \
  cargo build --release --target wasm32-unknown-unknown \
    --no-default-features --features component --locked
  wasm-tools component new \
    target/wasm32-unknown-unknown/release/aethel_core.wasm -o "$1"
}

build_once /tmp/build1.wasm
wasm-tools validate /tmp/build1.wasm

# Every operation the world declares must survive into the artifact. A component
# that validates but is missing an export is a component that does not implement
# the world it claims.
wasm-tools component wit /tmp/build1.wasm > /tmp/embedded.wit
# (saap-prove / saap-verify on the old `attestation` interface were removed in
# aethel-core 0.1.5: superseded by saap-verify-presentation.)
for op in plp-project-at-context plp-prove-identity plp-verify \
          saap-verify-presentation verify-signature \
          htss-split htss-reconstruct; do
  grep -q "$op" /tmp/embedded.wit || { echo "MISSING from component: $op"; exit 1; }
done

# Same claim the CI job makes, made here so a local re-vendor cannot silently
# produce a one-off artifact.
build_once /tmp/build2.wasm
cmp -s /tmp/build1.wasm /tmp/build2.wasm || {
  echo "NOT REPRODUCIBLE: two builds of $CORE_REV differ"
  sha256sum /tmp/build1.wasm /tmp/build2.wasm
  exit 1
}

cp /tmp/build1.wasm /out/aethel_core.component.wasm
cp wit/aethel-core.wit /out/aethel-core.wit
cp /tmp/embedded.wit /out/embedded.wit
git rev-parse HEAD > /out/rev
( cd /tmp && sha256sum build1.wasm | sed 's#build1.wasm#aethel_core.component.wasm#' ) > /out/component.sha256
echo "built $(cat /out/component.sha256)"
INNER

# Git Bash on Windows rewrites container-absolute paths into Windows paths
# before docker sees them, so `/out/build.sh` arrives as `C:/Program Files/...`
# and the run fails. Disable that conversion, and convert the host side of the
# mount explicitly, because that one really does need to be a Windows path.
host_out="$out"
if command -v cygpath >/dev/null 2>&1; then
  host_out="$(cygpath -w "$out")"
fi
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

docker run --rm \
  -e CORE_REPO="$core_repo" \
  -e CORE_REV="$rev" \
  -e RUST_VERSION="$rust_version" \
  -e WASM_TOOLS_VERSION="$wasm_tools_version" \
  -v "$host_out:/out" \
  ubuntu:24.04 bash /out/build.sh

resolved="$(cat "$out/rev")"
mkdir -p "$repo_root/core/wit"
cp "$out/aethel-core.wit" "$repo_root/core/wit/aethel-core.wit"
cp "$out/aethel_core.component.wasm" "$repo_root/core/aethel_core.component.wasm"
cp "$out/component.sha256" "$repo_root/core/component.sha256"

# Keep the pin honest: record what was actually built, not what was asked for.
sed -i -E "s#^rev = \".*\"#rev = \"$resolved\"#" "$pin"

echo
echo "core/ is now at $resolved"
echo "  $(cat "$repo_root/core/component.sha256")"
echo
echo "next: cargo test"
