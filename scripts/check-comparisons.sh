#!/usr/bin/env bash
#
# Fail if a new direct equality comparison appears in src/.
#
#   scripts/check-comparisons.sh              # check the tree
#   scripts/check-comparisons.sh --self-test  # prove the check can fail
#
# aethel-core does constant-time comparison internally, in ct_verify.rs. This
# crate is not allowed to undo that. A plain `==` on a signature, a MAC, a
# proof, or reconstructed key material reintroduces exactly the timing signal
# the core exists to avoid, and it is the kind of line that looks harmless in
# review.
#
# No script can tell which bytes are secret, so this one does not try. It
# freezes the set of equality comparisons that exist in src/ today, each one
# reviewed and written down in scripts/allowed-comparisons.txt with the reason
# it is safe. A new one fails CI until somebody either replaces it with a
# constant-time primitive or adds it to that file with its own reason. The
# point is to make each new comparison a decision rather than a diff nobody
# looked twice at.
#
# src/ only. Tests compare secrets on purpose, which is their job.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
allowlist="$repo_root/scripts/allowed-comparisons.txt"

# Emit "<path><TAB><source line, trimmed>" for every equality in src/.
#
# Keyed on the text rather than the line number so that moving code around does
# not spuriously fail; the thing under review is the comparison itself.
scan() {
    local root="$1"
    find "$root" -name '*.rs' -type f | sort | while IFS= read -r file; do
        local rel="${file#"$repo_root"/}"
        awk -v rel="$rel" '
            { sub(/\/\/.*/, "") }
            /[!=]=/ {
                gsub(/^[ \t]+|[ \t]+$/, "")
                print rel "\t" $0
            }
        ' "$file"
    done
}

expected() {
    grep -vE '^\s*(#|$)' "$allowlist" | sort
}

if [[ "${1:-}" == "--self-test" ]]; then
    # A check that has never been shown to fail is not known to work. Plant a
    # comparison in a throwaway tree and confirm the scanner reports it.
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/src"
    cat > "$tmp/src/planted.rs" <<'PLANT'
fn verify(signature: &[u8], expected: &[u8]) -> bool {
    signature == expected
}
PLANT
    if scan "$tmp/src" | grep -q 'signature == expected'; then
        echo "self-test: the scanner catches a planted comparison"
        exit 0
    fi
    echo "self-test FAILED: a planted comparison was not reported" >&2
    echo "This check cannot be trusted until that is fixed." >&2
    exit 1
fi

found="$(scan "$repo_root/src" || true)"
new="$(comm -23 <(printf '%s\n' "$found" | grep -v '^$' | sort) <(expected) || true)"

if [[ -n "$new" ]]; then
    cat >&2 <<MSG
New equality comparison in src/, not in scripts/allowed-comparisons.txt:

$new

If it compares a signature, a MAC, a proof, or any secret or
authentication-bearing bytes, use a constant-time comparison instead: a plain
== leaks how many leading bytes matched, which is the timing signal
aethel-core's ct_verify.rs exists to remove, and this crate must not undo it.

If it compares public data, add the line to scripts/allowed-comparisons.txt
with a comment saying why it is safe.
MSG
    exit 1
fi

gone="$(comm -13 <(printf '%s\n' "$found" | grep -v '^$' | sort) <(expected) || true)"
if [[ -n "$gone" ]]; then
    cat >&2 <<MSG
scripts/allowed-comparisons.txt lists comparisons that no longer exist:

$gone

Remove them, so the file keeps describing the code.
MSG
    exit 1
fi

echo "no unreviewed equality comparisons in src/"
