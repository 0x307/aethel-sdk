#!/usr/bin/env bash
# Assert that the SDK uses pqc-sig only for representations and encodings.
#
# This examines Cargo's resolved feature/dependency graph, not Cargo.toml text.
# The complete SDK runtime graph must not carry a second crypto implementation
# above aethel-core's embedded component.
set -euo pipefail

check_features() {
    local features=$1

    grep -Fq 'pqc-sig feature "std"' <<<"$features" ||
        { echo "pqc-sig std feature is absent"; return 1; }
    if grep -Eq 'pqc-sig feature "(default|ml-dsa|slh-dsa|fndsa|hybrid)"' <<<"$features"; then
        echo "pqc-sig cryptographic implementation feature is enabled"
        return 1
    fi
}

check_runtime_crypto() {
    local graph=$1

    local package
    for package in ml-dsa slh-dsa fn-dsa ed25519-dalek; do
        if grep -Eq "^${package} v" <<<"$graph"; then
            echo "forbidden runtime crypto package detected: $package"
            return 1
        fi
    done
}

if [[ "${1:-}" == "--self-test" ]]; then
    temp_dir=$(mktemp -d)
    trap 'rm -rf "$temp_dir"' EXIT
    mkdir -p "$temp_dir/src"
    cat >"$temp_dir/Cargo.toml" <<'EOF'
[package]
name = "pqc-sig-ml-dsa-positive-control"
version = "0.0.0"
edition = "2021"

[dependencies]
pqc-sig = { version = "0.5", default-features = false, features = ["std", "ml-dsa"] }
EOF
    : >"$temp_dir/src/lib.rs"

    positive_features=$(cargo tree --manifest-path "$temp_dir/Cargo.toml" -e features,no-dev --prefix none)
    if check_features "$positive_features"; then
        echo "positive control failed: pqc-sig ml-dsa feature was accepted"
        exit 1
    fi
    positive_graph=$(cargo tree --manifest-path "$temp_dir/Cargo.toml" -e normal --prefix none --format '{p}')
    if check_runtime_crypto "$positive_graph"; then
        echo "positive control failed: ml-dsa was not detected in the real runtime graph"
        exit 1
    fi
    echo "positive control passed: ml-dsa was detected in pqc-sig's real runtime graph"
    exit 0
fi

features=$(cargo tree -e features,no-dev --prefix none)
runtime_graph=$(cargo tree -e normal --prefix none --format '{p}')
check_features "$features"
check_runtime_crypto "$runtime_graph"
echo "pqc-sig is std-only and the SDK runtime graph has no forbidden crypto packages"
