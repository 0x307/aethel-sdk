#!/usr/bin/env bash
# Prove a crates.io release works as an external default-feature consumer.
#
# This script deliberately creates its project in a fresh temporary directory
# and gives Cargo a fresh CARGO_HOME. It therefore cannot use this checkout,
# its workspace, target directory, or any local source replacement.
set -euo pipefail

readonly CRATE_NAME="aethel-sdk"

usage() {
  cat >&2 <<'EOF'
Usage: scripts/post-publish-smoke.sh <published-version> <expected-component-sha256>
       scripts/post-publish-smoke.sh --self-test

The version must be an exact crates.io aethel-sdk release. The digest must be
the lowercase SHA-256 recorded in core/component.sha256 at that release's tag.
EOF
}

is_published_version() {
  [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]]
}

is_sha256() {
  [[ $1 =~ ^[0-9a-f]{64}$ ]]
}

corrupt_digest() {
  local digest=$1
  if [[ ${digest:0:1} == 0 ]]; then
    printf '1%s\n' "${digest:1}"
  else
    printf '0%s\n' "${digest:1}"
  fi
}

assert_component_hash() {
  local actual=$1 expected=$2
  if ! is_sha256 "$actual" || ! is_sha256 "$expected"; then
    echo "component digest comparison requires lowercase SHA-256 digests" >&2
    return 1
  fi
  if [[ $actual != "$expected" ]]; then
    echo "component digest mismatch: expected $expected, published consumer declared $actual" >&2
    return 1
  fi
}

assert_consumer_lockfile() {
  local manifest=$1 lockfile=$2 version=$3
  python3 - "$manifest" "$lockfile" "$version" <<'PY'
import sys
import tomllib
from pathlib import Path

manifest_path = Path(sys.argv[1])
lockfile_path = Path(sys.argv[2])
version = sys.argv[3]
manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
dependency = manifest.get("dependencies", {}).get("aethel-sdk")
if dependency != f"={version}":
    raise SystemExit(
        "consumer manifest must pin aethel-sdk exactly as "
        f'"={version}", got {dependency!r}'
    )
if "patch" in manifest:
    raise SystemExit("consumer manifest must not contain a [patch] override")

lockfile = tomllib.loads(lockfile_path.read_text(encoding="utf-8"))
matches = [
    package
    for package in lockfile.get("package", [])
    if package.get("name") == "aethel-sdk"
]
if len(matches) != 1:
    raise SystemExit(
        f"consumer lockfile must resolve exactly one aethel-sdk package, got {len(matches)}"
    )
package = matches[0]
if package.get("version") != version:
    raise SystemExit(
        f"consumer lockfile resolved aethel-sdk {package.get('version')!r}, not {version!r}"
    )
if package.get("source") != "registry+https://github.com/rust-lang/crates.io-index":
    raise SystemExit(
        "consumer lockfile must resolve aethel-sdk from the crates.io registry, got "
        f"{package.get('source')!r}"
    )
PY
}

write_consumer() {
  local project_dir=$1
  cat >"$project_dir/src/main.rs" <<'RS'
use std::fs;
use std::io::Read;

use aethel_sdk::{artifact, verify, Identity};

fn random_sealing_key() -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut key = [0u8; 32];
    // The smoke workflow runs on GitHub's Linux host. /dev/urandom is the OS
    // CSPRNG and keeps this external consumer dependency-free.
    fs::File::open("/dev/urandom")?.read_exact(&mut key)?;
    Ok(key)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut original = Identity::generate()?;
    let expected_public_key = original.public_key().to_vec();
    println!("PASS: identity generated");

    let sealing_key = random_sealing_key()?;
    let sealed_path = std::env::current_dir()?.join(format!(
        "aethel-identity-smoke-{}-sealed.bin",
        std::process::id()
    ));
    let sealed = original.export_sealed(&sealing_key)?;
    fs::write(&sealed_path, &sealed)?;
    drop(sealed);
    drop(original);
    println!("PASS: identity sealed and persisted");

    let sealed = fs::read(&sealed_path)?;
    fs::remove_file(&sealed_path)?;
    let mut reopened = Identity::open_sealed(&sealed, &sealing_key)?;
    assert_eq!(reopened.public_key(), expected_public_key.as_slice());
    println!("PASS: identity reopened");

    let multikey = reopened.public_key_multibase();
    assert!(multikey.starts_with('z'));
    println!("PASS: public key exported as Multikey");
    // COR-15 follow-up: decode this Multikey and the signature below with the
    // SDK's public typed-key and typed-signature APIs once those APIs ship.

    let message = b"post-publish identity lifecycle smoke message";
    let signature = reopened.sign(message)?;
    assert!(verify(&expected_public_key, message, &signature)?);
    println!("PASS: signature verified");

    assert!(!verify(
        &expected_public_key,
        b"modified post-publish identity lifecycle smoke message",
        &signature
    )?);
    println!("PASS: modified message rejected");

    let mut modified_signature = signature.clone();
    modified_signature[0] ^= 1;
    let signature_rejected = verify(&expected_public_key, message, &modified_signature)
        .map(|verified| !verified)
        .unwrap_or(true);
    let other_identity = Identity::generate()?;
    let wrong_key_rejected = verify(other_identity.public_key(), message, &signature)
        .map(|verified| !verified)
        .unwrap_or(true);
    assert!(signature_rejected);
    assert!(wrong_key_rejected);
    println!("PASS: invalid signature rejected");

    println!(
        "DECLARED_COMPONENT_SHA256={}",
        artifact::declared_sha256()
    );
    println!("PASS: published identity lifecycle complete");
    Ok(())
}
RS
}

run_smoke() {
  local version=$1 expected=$2
  local scratch
  scratch=$(mktemp -d "${TMPDIR:-/tmp}/aethel-post-publish-smoke.XXXXXX")
  trap 'rm -rf "$scratch"' RETURN

  local project_dir="$scratch/aethel-identity-smoke"
  export CARGO_HOME="$scratch/cargo-home"
  export CARGO_TARGET_DIR="$scratch/cargo-target"
  cargo new --vcs none "$project_dir"
  (
    cd "$project_dir"
    cargo add "${CRATE_NAME}@=${version}"
  )
  assert_consumer_lockfile "$project_dir/Cargo.toml" "$project_dir/Cargo.lock" "$version"
  write_consumer "$project_dir"

  local output actual corrupted
  output=$(cd "$project_dir" && cargo run --quiet)
  printf '%s\n' "$output"
  actual=$(printf '%s\n' "$output" | awk -F= '/^DECLARED_COMPONENT_SHA256=[0-9a-f]{64}$/ { count++; value=$2 } END { if (count == 1) print value; else exit 1 }')
  if ! is_sha256 "${actual:-}"; then
    echo "consumer did not emit exactly one valid DECLARED_COMPONENT_SHA256 marker" >&2
    return 1
  fi
  assert_component_hash "$actual" "$expected"
  echo "PASS: expected component hash matches published crate"

  corrupted=$(corrupt_digest "$expected")
  local control_output
  if control_output=$(assert_component_hash "$actual" "$corrupted" 2>&1); then
    echo "negative control failed: corrupted expected hash was accepted" >&2
    return 1
  fi
  if [[ $control_output != component\ digest\ mismatch:* ]]; then
    echo "negative control failed for an unexpected reason: $control_output" >&2
    return 1
  fi
  echo "PASS: corrupted expected hash rejected"
}

self_test() {
  local digest=6f87f48a00d65c1a130d0b739046ea2413cead4caf758c5cd5b1113017acd348
  is_published_version "0.8.0"
  ! is_published_version "" && ! is_published_version "0.8" && ! is_published_version "v0.8.0"
  is_sha256 "$digest"
  ! is_sha256 "" && ! is_sha256 "${digest^^}" && ! is_sha256 "${digest:1}"
  [[ $(corrupt_digest "$digest") != "$digest" ]]
  assert_component_hash "$digest" "$digest"
  local negative_control
  ! negative_control=$(assert_component_hash "$digest" "$(corrupt_digest "$digest")" 2>&1)
  [[ $negative_control == component\ digest\ mismatch:* ]]

  local fixture
  fixture=$(mktemp -d "${TMPDIR:-/tmp}/aethel-post-publish-smoke-test.XXXXXX")
  trap 'rm -rf "$fixture"' RETURN
  cat >"$fixture/Cargo.toml" <<EOF
[package]
name = "fixture"
version = "0.1.0"
edition = "2021"
[dependencies]
aethel-sdk = "=0.8.0"
EOF
  cat >"$fixture/Cargo.lock" <<EOF
version = 4
[[package]]
name = "aethel-sdk"
version = "0.8.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
EOF
  assert_consumer_lockfile "$fixture/Cargo.toml" "$fixture/Cargo.lock" "0.8.0"
  sed -i 's/=0.8.0/=0.8/' "$fixture/Cargo.toml"
  ! assert_consumer_lockfile "$fixture/Cargo.toml" "$fixture/Cargo.lock" "0.8.0" 2>/dev/null
  sed -i 's/=0.8/=0.8.0/' "$fixture/Cargo.toml"
  sed -i 's#registry+https://github.com/rust-lang/crates.io-index#git+https://example.invalid/aethel-sdk#' "$fixture/Cargo.lock"
  ! assert_consumer_lockfile "$fixture/Cargo.toml" "$fixture/Cargo.lock" "0.8.0" 2>/dev/null
  echo "post-publish smoke helper self-test passed"
}

if [[ ${1:-} == "--self-test" && $# == 1 ]]; then
  self_test
  exit 0
fi
if [[ $# != 2 ]] || ! is_published_version "$1" || ! is_sha256 "$2"; then
  usage
  exit 2
fi
run_smoke "$1" "$2"
