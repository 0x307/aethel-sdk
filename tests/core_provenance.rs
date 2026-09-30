//! The vendored component and the linked crate must describe one build.
//!
//! `aethel-core` 0.7.0 exposes `COMPONENT_SHA256`: the digest of the canonical
//! component that revision builds. This crate vendors a component and records
//! its digest in `core/component.sha256`. Those two values answer the same
//! question from opposite directions, and nothing compared them.
//!
//! What that gap allows: `scripts/sync-core.sh` re-vendors `core/` and checks that
//! the dev-dependency is the exact crates.io pin of what it vendored. But a hand
//! edit to either, or a partial re-vendor, can leave the linked crate and the
//! embedded artifact describing different builds while a comparison of labels
//! still passes. This compares bytes.
//!
//! This is C1-03's AC4 and COR-16's, in the form that can actually hold.
//! Comparing revisions cannot work — `core/pin.toml` names merge commits, which
//! did not exist when the crate recorded its own provenance — so the comparison
//! is on the digest, which describes the artifact rather than a label.

#![cfg(not(target_arch = "wasm32"))]

/// `core/component.sha256` is `<digest>  <filename>`, as sha256sum writes it.
fn vendored_digest() -> &'static str {
    include_str!("../core/component.sha256")
        .split_whitespace()
        .next()
        .expect("core/component.sha256 is empty")
}

#[test]
fn the_linked_crate_describes_the_component_this_crate_embeds() {
    assert_eq!(
        aethel_core::COMPONENT_SHA256,
        vendored_digest(),
        "the linked aethel-core and the vendored component are different \
         builds.\n  aethel_core::COMPONENT_SHA256: {}\n  core/component.sha256:        {}\n\
         Re-vendor with scripts/sync-core.sh, which moves both together.",
        aethel_core::COMPONENT_SHA256,
        vendored_digest()
    );
}

/// The digest the crate reports is also the digest of the bytes actually shipped.
///
/// The test above compares two recorded strings. Both could agree and both be
/// wrong about the artifact in this repository, which is the failure the
/// embedded-artifact checks exist to stop. This closes the triangle: crate ==
/// record == bytes.
#[test]
fn the_linked_crate_describes_the_bytes_actually_embedded() {
    let embedded = aethel_sdk::artifact::sha256_hex(aethel_sdk::artifact::COMPONENT);
    assert_eq!(
        aethel_core::COMPONENT_SHA256, embedded,
        "the linked aethel-core describes a component whose bytes are not the \
         ones embedded here"
    );
}

/// Positive control for both comparisons.
///
/// They assert equality between strings. That proves nothing unless the
/// extraction can report a mismatch and is reading the digest field rather than
/// the filename — an extraction returning `COMPONENT_SHA256` unconditionally
/// would satisfy every assertion above.
#[test]
fn the_digest_extraction_can_fail_and_reads_the_right_field() {
    let wrong = "0000000000000000000000000000000000000000000000000000000000000000  \
                 aethel_core.component.wasm";
    let extracted = wrong.split_whitespace().next().unwrap();
    assert_ne!(
        extracted,
        aethel_core::COMPONENT_SHA256,
        "the extraction reports a match for a plainly different digest"
    );
    assert_eq!(extracted.len(), 64, "the extraction is not taking the digest field");
}
