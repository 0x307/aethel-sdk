#!/usr/bin/env bash
# Assert that the SDK uses pqc-sig only for representations and encodings.
#
# This examines Cargo's resolved feature/dependency graph, not Cargo.toml text:
# enabling pqc-sig's ml-dsa feature would pull a second crypto implementation
# above aethel-core's embedded component.
set -euo pipefail

check_graph() {
    local features=$1
    local dependencies=$2

    grep -Fq 'pqc-sig feature "std"' <<<"$features" ||
        { echo "pqc-sig std feature is absent"; return 1; }
    if grep -Eq 'pqc-sig feature "(default|ml-dsa|slh-dsa|fndsa|hybrid)"' <<<"$features"; then
        echo "pqc-sig cryptographic implementation feature is enabled"
        return 1
    fi
    if grep -Eq '(^|[[:space:]├└])((ml-dsa)|(slh-dsa)|(fn-dsa)|(ed25519-dalek))[[:space:]]' <<<"$dependencies"; then
        echo "pqc-sig resolves a cryptographic implementation dependency"
        return 1
    fi
}

if [[ "${1:-}" == "--self-test" ]]; then
    good_features=$'pqc-sig v0.5.0\n└── pqc-sig feature "std"'
    good_dependencies=$'pqc-sig v0.5.0\n├── bs58 v0.5.1\n└── serde v1.0.229'
    check_graph "$good_features" "$good_dependencies"

    bad_features=$'pqc-sig v0.5.0\n└── pqc-sig feature "ml-dsa"'
    if check_graph "$bad_features" "$good_dependencies"; then
        echo "positive control failed: ml-dsa feature was accepted"
        exit 1
    fi
    bad_dependencies=$'pqc-sig v0.5.0\n└── ml-dsa v0.1.1'
    if check_graph "$good_features" "$bad_dependencies"; then
        echo "positive control failed: ml-dsa dependency was accepted"
        exit 1
    fi
    echo "positive controls passed: crypto features and dependencies are rejected"
    exit 0
fi

features=$(cargo tree -e features -i pqc-sig@0.5.0)
dependencies=$(cargo tree -p pqc-sig@0.5.0 -e normal)
check_graph "$features" "$dependencies"
echo "pqc-sig 0.5.0 is std-only and has no cryptographic implementation dependency"
