#!/usr/bin/env python3
"""Assert the contents of the crate archive produced by ``cargo package``.

This intentionally validates the extracted archive rather than this checkout.
The package's include list once omitted examples/, leaving crates.io users with
a README command that could not run from the crate they downloaded.

Usage:
    scripts/validate-package.py
    scripts/validate-package.py --negative-control
"""

import argparse
import hashlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path


# This is the complete, intentionally published file set. Cargo adds its
# package metadata files (Cargo.toml, Cargo.toml.orig, Cargo.lock, and
# .cargo_vcs_info.json); they belong here because this compares the archive,
# not just the manifest's include patterns.
EXPECTED_PATHS = frozenset(
    """
    .cargo_vcs_info.json
    CHANGELOG.md
    Cargo.lock
    Cargo.toml
    Cargo.toml.orig
    LICENSE
    NOTICE
    README.md
    SECURITY-MODEL.md
    build.rs
    core/aethel_core.component.wasm
    core/component.sha256
    core/pin.toml
    core/wit/aethel-core.wit
    examples/bench_verify.rs
    examples/projection.rs
    examples/quickstart.rs
    examples/seal_fixture.rs
    scripts/allowed-comparisons.txt
    scripts/check-comparisons.sh
    scripts/sync-core.sh
    src/artifact.rs
    src/component.rs
    src/disclosure.rs
    src/identity.rs
    src/lib.rs
    src/verifier.rs
    tests/build_inputs.rs
    tests/component_execution.rs
    tests/core_provenance.rs
    tests/disclosure.rs
    tests/embedded_artifact.rs
    tests/fixtures/sealed-identity.bin
    tests/identity.rs
    tests/multikey.rs
    tests/network_isolation_negative_control.rs
    tests/persistence.rs
    tests/projection.rs
    tests/readme_pin.rs
    tests/verifier.rs
    """.split()
)


class PackageValidationError(Exception):
    """The produced crate failed one of its publication assertions."""


def package_and_extract(project_dir: Path, scratch_dir: Path) -> Path:
    """Produce a crate, then return its extracted top-level directory."""
    target_dir = scratch_dir / "cargo-target"
    subprocess.run(
        [
            "cargo",
            "package",
            "--allow-dirty",
            "--no-verify",
            "--target-dir",
            str(target_dir),
        ],
        cwd=project_dir,
        check=True,
    )

    crates = sorted((target_dir / "package").glob("*.crate"))
    if len(crates) != 1:
        raise PackageValidationError(
            f"expected exactly one generated .crate, found: "
            f"{', '.join(str(path) for path in crates) or '(none)'}"
        )

    extract_dir = scratch_dir / "extracted"
    with tarfile.open(crates[0], "r:gz") as archive:
        archive.extractall(extract_dir, filter="data")

    roots = sorted(path for path in extract_dir.iterdir() if path.is_dir())
    if len(roots) != 1:
        raise PackageValidationError(
            f"expected one top-level directory in {crates[0].name}, found: "
            f"{', '.join(path.name for path in roots) or '(none)'}"
        )
    return roots[0]


def packaged_paths(package_root: Path) -> set[str]:
    """Return archive file paths relative to the package root."""
    return {
        path.relative_to(package_root).as_posix()
        for path in package_root.rglob("*")
        if path.is_file()
    }


def assert_expected_file_set(package_root: Path) -> None:
    actual = packaged_paths(package_root)
    unexpected = sorted(actual - EXPECTED_PATHS)
    missing = sorted(EXPECTED_PATHS - actual)
    if unexpected or missing:
        messages = ["packaged file set differs from the explicit expected list:"]
        if unexpected:
            messages.append("unexpected packaged paths:\n  " + "\n  ".join(unexpected))
        if missing:
            messages.append("missing expected package paths:\n  " + "\n  ".join(missing))
        raise PackageValidationError("\n".join(messages))


def assert_embedded_wasm_hash(package_root: Path) -> None:
    """Compare two files explicitly rooted in the extracted package."""
    packaged_wasm = package_root / "core/aethel_core.component.wasm"
    packaged_hash = package_root / "core/component.sha256"
    if not packaged_wasm.is_file() or not packaged_hash.is_file():
        raise PackageValidationError(
            "unpacked crate must contain core/aethel_core.component.wasm and "
            "core/component.sha256"
        )

    declared_fields = packaged_hash.read_text(encoding="utf-8").split()
    declared = declared_fields[0] if declared_fields else "(empty component.sha256)"
    actual = hashlib.sha256(packaged_wasm.read_bytes()).hexdigest()
    if declared != actual:
        raise PackageValidationError(
            "embedded WASM hash differs inside the unpacked crate:\n"
            f"  expected (core/component.sha256): {declared}\n"
            f"  actual   (core/aethel_core.component.wasm): {actual}"
        )


def readme_runnable_paths(package_root: Path) -> dict[str, str]:
    """Extract README commands and resolve example names using packaged Cargo.toml."""
    readme = (package_root / "README.md").read_text(encoding="utf-8")
    manifest = tomllib.loads((package_root / "Cargo.toml").read_text(encoding="utf-8"))
    explicit_examples = {
        item["name"]: item["path"]
        for item in manifest.get("example", [])
        if "name" in item and "path" in item
    }

    paths = {}
    for name in re.findall(r"\bcargo\s+run\s+--example\s+([A-Za-z0-9_-]+)\b", readme):
        paths[f"cargo run --example {name}"] = explicit_examples.get(
            name, f"examples/{name}.rs"
        )
    for path in re.findall(r"\bscripts/[A-Za-z0-9_./-]+\.sh\b", readme):
        paths[path] = path
    return paths


def assert_readme_runnable_paths(package_root: Path) -> None:
    missing = [
        (command, path)
        for command, path in sorted(readme_runnable_paths(package_root).items())
        if not (package_root / path).is_file()
    ]
    if missing:
        raise PackageValidationError(
            "README runnable paths missing from the unpacked crate:\n"
            + "\n".join(f"  {command} -> {path}" for command, path in missing)
        )


def validate(project_dir: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="aethel-package-") as temp:
        package_root = package_and_extract(project_dir, Path(temp))
        assert_expected_file_set(package_root)
        assert_embedded_wasm_hash(package_root)
        assert_readme_runnable_paths(package_root)


def run_negative_control(project_dir: Path) -> None:
    """Prove examples/ omission fails, guarding the historical packaging defect."""
    with tempfile.TemporaryDirectory(prefix="aethel-package-control-") as temp:
        control_dir = Path(temp) / "checkout"
        shutil.copytree(
            project_dir,
            control_dir,
            # Keep .git so Cargo produces the same VCS metadata as it does for
            # the real checkout; only build output is irrelevant to packaging.
            ignore=shutil.ignore_patterns("target"),
        )
        manifest_path = control_dir / "Cargo.toml"
        manifest = manifest_path.read_text(encoding="utf-8")
        changed, count = re.subn(
            r'(?m)^\s*"examples/\*\*/\*",\s*(?:#.*)?\n?', "", manifest, count=1
        )
        if count != 1:
            raise PackageValidationError(
                "negative control could not remove the examples/**/* include entry"
            )
        manifest_path.write_text(changed, encoding="utf-8")

        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--project-dir", str(control_dir)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if result.returncode == 0:
            raise PackageValidationError(
                "negative control FAILED: removing examples/**/* still passed validation"
            )
        if "missing expected package paths:" not in result.stdout or "examples/" not in result.stdout:
            raise PackageValidationError(
                "negative control failed for an unexpected reason:\n" + result.stdout
            )
        print("negative control validator output (expected failure):")
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
        print("negative control caught the historical examples/**/* omission as expected")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-dir", type=Path, default=Path.cwd())
    parser.add_argument("--negative-control", action="store_true")
    args = parser.parse_args()

    try:
        project_dir = args.project_dir.resolve()
        if args.negative_control:
            run_negative_control(project_dir)
        else:
            validate(project_dir)
    except (PackageValidationError, subprocess.CalledProcessError) as error:
        print(f"package validation FAILED: {error}", file=sys.stderr)
        return 1

    print("package validation passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
