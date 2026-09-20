#!/usr/bin/env python3
"""Check that the aethel-core dev-dependency resolves on crates.io.

`cargo publish` drops the git source and resolves

    aethel-core = { version = "0.7", git = ..., rev = ... }

against crates.io. Nothing local sees that. `the_dev_dependency_matches_the_vendored_revision`
compares two strings in two files in this repository; it cannot see the registry, and the
registry is where the failure lives.

That is how 0.5.2's publish failed: the requirement said "0.3" while every 0.3.x had been
yanked upstream. The local build was green throughout, because the git source satisfied it.

Sharper than "publish fails": at publish the requirement resolves to whatever matching release
is newest and not yanked, which need not be the pinned revision. The published crate's
execution proof can then compare the vendored component against a different revision's native
API -- the defect 0.5.2 fixed, reintroduced by the publish step itself.

This runs in CI rather than at publish, so it surfaces on the pull request that introduces it
instead of months later.

Exit codes are distinct because the reasons are not interchangeable (AC3): the 0.5.2 incident
was confusing precisely because publish reported "no such version" for what was really "every
matching version is yanked."

    0  a non-yanked release satisfies the requirement
    2  usage or network error, or a requirement form this script does not model
    3  NO_MATCH    -- no published version satisfies the requirement at all
    4  ALL_YANKED  -- versions satisfy it, but every one of them is yanked
"""

import argparse
import json
import re
import sys
import urllib.error
import urllib.request

INDEX_URL = "https://index.crates.io/ae/th/aethel-core"
CRATE = "aethel-core"

OK, USAGE, NO_MATCH, ALL_YANKED = 0, 2, 3, 4
REASONS = {OK: "ok", NO_MATCH: "no-match", ALL_YANKED: "all-yanked"}


def fail_usage(message):
    """Exit with the documented usage code.

    `sys.exit(str)` exits 1, which this script reserves for "the control did not
    fail the way it claimed". Sharing a code between those would make the negative
    control unable to tell a real miss from a broken invocation.
    """
    print(message, file=sys.stderr)
    sys.exit(USAGE)


def requirement_from_manifest(path):
    """Pull the aethel-core dev-dependency's version requirement out of Cargo.toml."""
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.lstrip().startswith(f"{CRATE} = "):
                m = re.search(r'version\s*=\s*"([^"]+)"', line)
                if not m:
                    fail_usage(
                        f"{path}: the {CRATE} dependency line carries no version requirement.\n"
                        "  `cargo publish` resolves that requirement against crates.io, so the\n"
                        "  line needs one even though the local build uses the git source."
                    )
                return m.group(1)
    fail_usage(f"{path}: no {CRATE} dependency line found.")


def parse_version(v):
    parts = v.split("-", 1)[0].split("+", 1)[0].split(".")
    return tuple(int(p) for p in parts[:3]) + (0,) * (3 - len(parts[:3]))


def caret_bounds(req):
    """Lower and upper bound for a cargo default (caret) requirement.

    Only the bare and ^-prefixed forms are modelled, because those are what this
    manifest uses. Anything else exits rather than guessing: a comparison this
    script silently got wrong would be worse than no check, since the job would
    still report green.
    """
    raw = req.strip()
    if raw.startswith("^"):
        raw = raw[1:].strip()
    if not re.fullmatch(r"\d+(\.\d+){0,2}", raw):
        fail_usage(USAGE_MSG.format(req=req))

    nums = [int(p) for p in raw.split(".")]
    lower = tuple(nums + [0] * (3 - len(nums)))

    # Caret allows changes that do not modify the left-most non-zero component.
    if nums[0] != 0:
        upper = (nums[0] + 1, 0, 0)
    elif len(nums) == 1:            # "0"     -> >=0.0.0, <1.0.0
        upper = (1, 0, 0)
    elif nums[1] != 0:              # "0.7"   -> >=0.7.0, <0.8.0
        upper = (0, nums[1] + 1, 0)
    elif len(nums) == 2:            # "0.0"   -> >=0.0.0, <0.1.0
        upper = (0, 1, 0)
    else:                           # "0.0.3" -> >=0.0.3, <0.0.4
        upper = (0, 0, nums[2] + 1)
    return lower, upper


USAGE_MSG = (
    'requirement "{req}" is not a bare or ^-prefixed version.\n'
    "  This check models only the form this manifest uses. Extend it rather than\n"
    "  loosening it: a requirement it cannot compare must not pass silently."
)


def fetch_index():
    req = urllib.request.Request(
        INDEX_URL, headers={"User-Agent": f"{CRATE}-requirement-check (aethel-sdk CI)"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            fail_usage(f"crates.io has no crate named {CRATE}.")
        fail_usage(f"could not read the crates.io index: HTTP {e.code}")
    except urllib.error.URLError as e:
        fail_usage(f"could not reach the crates.io index: {e.reason}")

    out = []
    for line in body.splitlines():
        if line.strip():
            e = json.loads(line)
            out.append((e["vers"], bool(e.get("yanked", False))))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest", default="Cargo.toml")
    ap.add_argument(
        "--requirement",
        help="check this requirement instead of the manifest's (used by the negative control)",
    )
    ap.add_argument(
        "--expect",
        choices=sorted(set(REASONS.values())),
        help="require this outcome and exit 0 when it happens; for asserting a control fails "
        "for the reason it claims to, not merely that it fails",
    )
    args = ap.parse_args()

    req = args.requirement or requirement_from_manifest(args.manifest)
    source = "--requirement" if args.requirement else args.manifest
    lower, upper = caret_bounds(req)

    releases = fetch_index()
    matching = [(v, y) for v, y in releases if lower <= parse_version(v) < upper]
    usable = [v for v, y in matching if not y]

    if not matching:
        code = NO_MATCH
        report = (
            f'no published {CRATE} release satisfies "{req}".\n'
            f"  published: {', '.join(v for v, _ in releases) or '(none)'}\n"
            "  `cargo publish` would fail to resolve this requirement."
        )
    elif not usable:
        code = ALL_YANKED
        code_versions = ", ".join(v for v, _ in matching)
        report = (
            f'every {CRATE} release satisfying "{req}" is yanked.\n'
            f"  matching but yanked: {code_versions}\n"
            "  This is not the same as the version not existing, and publish reports it\n"
            "  as though it were. That confusion is what made the 0.5.2 incident hard to read."
        )
    else:
        code = OK
        report = (
            f'"{req}" (from {source}) resolves to {CRATE} {max(usable, key=parse_version)}, '
            "not yanked."
        )

    if args.expect:
        if REASONS[code] == args.expect:
            print(f"expected {args.expect}: {report}")
            return OK
        print(
            f"expected {args.expect}, got {REASONS[code]}.\n{report}",
            file=sys.stderr,
        )
        return 1

    print(report if code == OK else f"{report}", file=sys.stdout if code == OK else sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
