//! The README's dependency line has to name the release it ships with.
//!
//! Every earlier release is yanked, so a stale `aethel-sdk = "0.3"` in the
//! quickstart does not resolve at all: a stranger pasting it gets a Cargo error
//! before a single line of the SDK runs. The quickstart example is built in CI,
//! but it uses a path dependency, so nothing else would notice the pin drift.

#![cfg(not(target_arch = "wasm32"))]

#[test]
fn every_readme_dependency_line_names_this_minor_version() {
    let readme = include_str!("../README.md");
    let version = env!("CARGO_PKG_VERSION");
    let minor: String = version.split('.').take(2).collect::<Vec<_>>().join(".");
    let expected = format!("aethel-sdk = \"{minor}\"");

    let pins: Vec<&str> = readme
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("aethel-sdk = "))
        .collect();

    assert!(!pins.is_empty(), "README has no `aethel-sdk = ` dependency line");
    for pin in pins {
        assert_eq!(pin, expected, "README pin does not match crate version {version}");
    }
}
