//! The package ships a compiled component and makes a claim about its bytes.
//! These tests check the claim, and check that the checking machinery can fail.
//!
//! The second half matters as much as the first. A hash comparison that has only
//! ever been run against matching inputs is not known to detect anything, and
//! this repo's initiative has already been bitten twice by a check that looked
//! like verification and could not fail. So every assertion of the form "the
//! artifact is correct" here is paired with a positive control that feeds the
//! same machinery an artifact that is known to be wrong.

use aethel_sdk::artifact;

/// The WebAssembly Component Model preamble: `\0asm` then layer `0x000d`.
/// A *core module* is the same magic with version `0x0001`, and shipping a core
/// module while calling it a component is exactly the drift this file guards.
const COMPONENT_PREAMBLE: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];
const CORE_MODULE_PREAMBLE: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

#[test]
fn the_artifact_is_embedded_not_empty() {
    assert!(
        !artifact::COMPONENT.is_empty(),
        "no component is embedded. core/aethel_core.component.wasm is empty or missing"
    );
}

/// The embedded bytes are a component, not a core module.
///
/// aethel-core shipped a wasm-bindgen core module for most of its life. If this
/// package ever picks that up by mistake it will still be a valid `.wasm` file,
/// it will still hash to something, and nothing else here would notice.
#[test]
fn the_artifact_is_a_component_not_a_core_module() {
    let head = &artifact::COMPONENT[..8];
    assert_ne!(
        head, CORE_MODULE_PREAMBLE,
        "the embedded artifact is a core module, not a Component Model component"
    );
    assert_eq!(
        head, COMPONENT_PREAMBLE,
        "the embedded artifact is not a WebAssembly component"
    );
}

/// The AC: a test asserts the artifact hash matches the one the package declares.
#[test]
fn the_embedded_artifact_matches_the_declared_hash() {
    if let Err(mismatch) = artifact::verify_embedded() {
        panic!(
            "the embedded component is not the artifact this package declares.\n  \
             declared: {}\n  actual:   {}\n\
             Rebuild with scripts/sync-core.sh, which rewrites both.",
            mismatch.declared, mismatch.actual
        );
    }
}

/// Positive control for the test above.
///
/// Substitute one byte of the artifact and the check must fail. Without this,
/// `verify_embedded` passing tells us nothing: a function that returned `Ok(())`
/// unconditionally would look identical.
#[test]
fn a_substituted_artifact_is_rejected() {
    let mut tampered = artifact::COMPONENT.to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;

    let err = artifact::verify(&tampered).expect_err(
        "a component with a flipped byte passed the hash check. The check cannot \
         detect a substituted artifact and is worthless",
    );
    assert_eq!(err.declared, artifact::declared_sha256());
    assert_ne!(err.actual, err.declared);
}

/// Positive control, second form: a wholly different artifact, not a bit flip.
#[test]
fn an_unrelated_artifact_is_rejected() {
    let err = artifact::verify(&CORE_MODULE_PREAMBLE)
        .expect_err("an eight-byte stub passed the hash check");
    assert_ne!(err.actual, err.declared);
}

/// The declared hash is a real SHA-256 and not, say, a truncated paste.
#[test]
fn the_declared_hash_is_well_formed() {
    let declared = artifact::declared_sha256();
    assert_eq!(declared.len(), 64, "declared hash is not 64 hex characters: {declared}");
    assert!(
        declared.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "declared hash is not lowercase hex: {declared}"
    );
}

/// Positive control for the hash function itself, against a value that does not
/// come from this codebase: the SHA-256 of the empty string.
#[test]
fn the_digest_agrees_with_a_known_answer() {
    assert_eq!(
        artifact::sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

/// The pin is readable and identifies a specific aethel-core commit. "Which
/// source produced this binary" has to have an answer for the rebuild
/// instructions to mean anything.
#[test]
fn the_pinned_revision_is_a_full_commit_sha() {
    let rev = artifact::core_revision();
    assert_eq!(rev.len(), 40, "pinned rev is not a full commit sha: {rev}");
    assert!(rev.chars().all(|c| c.is_ascii_hexdigit()), "pinned rev is not hex: {rev}");
}
