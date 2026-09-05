//! SDK PLP projection privacy properties.
//!
//! These tests pin observable behavior at the SDK boundary. They are not, and
//! cannot be, a proof of the underlying M-LWE security or non-derivability of a
//! master secret.

#![cfg(not(target_arch = "wasm32"))]

use aethel_sdk::{identity::Error, Identity};

const ENTROPY: &[u8; 32] = b"deterministic entropy for tests!";
const CONTEXT: &[u8] = b"checkout-session";
const RHO: [u8; 32] = [0xA5; 32];

#[test]
fn same_context_with_fresh_randomness_produces_independent_projection_material() {
    let mut identity = Identity::from_entropy(ENTROPY).expect("identity");

    let first = identity.project_at(CONTEXT).expect("first projection");
    let second = identity.project_at(CONTEXT).expect("second projection");

    // Fresh rho gives a fresh salt and therefore a new A, preventing the
    // same-matrix averaging attack that 0X3-95 fixed.
    assert_ne!(first.salt(), second.salt(), "fresh calls shared a salt");
    assert_ne!(
        first.public_b(),
        second.public_b(),
        "fresh calls shared public projection material"
    );
    assert_ne!(
        first.to_bytes(),
        second.to_bytes(),
        "fresh calls reproduced the same projection"
    );
}

#[test]
fn different_contexts_produce_distinct_public_projection_material() {
    let mut identity = Identity::from_entropy(ENTROPY).expect("identity");

    // Randomness is held fixed deliberately. If it varied, the projections
    // would differ for that reason alone and this test would pass without
    // saying anything about the context. Holding rho constant means the only
    // varying input is the context, so a divergence here is context separation
    // and nothing else. This is an operational proxy for unlinkability, not a
    // proof of it.
    let first = identity
        .project_at_with_randomness(b"checkout-session-a", &RHO)
        .expect("first projection");
    let second = identity
        .project_at_with_randomness(b"checkout-session-b", &RHO)
        .expect("second projection");

    assert_ne!(
        first.tau(),
        second.tau(),
        "contexts were not retained by core"
    );
    assert_ne!(
        first.salt(),
        second.salt(),
        "different contexts shared a salt under identical randomness"
    );
    assert_ne!(
        first.public_b(),
        second.public_b(),
        "different contexts shared public projection material under identical randomness"
    );
}

#[test]
fn same_context_and_randomness_reproduce_identical_projection() {
    let mut identity = Identity::from_entropy(ENTROPY).expect("identity");

    let first = identity
        .project_at_with_randomness(CONTEXT, &RHO)
        .expect("first projection");
    let second = identity
        .project_at_with_randomness(CONTEXT, &RHO)
        .expect("second projection");

    assert_eq!(
        first.to_bytes(),
        second.to_bytes(),
        "identical identity, context, and randomness must reproduce canonically"
    );
}

#[test]
fn short_projection_randomness_is_a_typed_error() {
    let mut identity = Identity::from_entropy(ENTROPY).expect("identity");

    assert!(matches!(
        identity.project_at_with_randomness(CONTEXT, &[0u8; 31]),
        Err(Error::Component(
            aethel_sdk::component::aethel::core::types::IdentityError::InvalidInputLength
        ))
    ));
}

#[test]
fn projection_exposes_only_public_material() {
    let mut identity = Identity::from_entropy(ENTROPY).expect("identity");
    let projection = identity.project_at(CONTEXT).expect("projection");

    // The supported transport representation consists only of core's public
    // fields: padded tau, salt, and public_b. This is a non-exposure check, not
    // a proof that a master secret is cryptographically non-derivable.
    assert_eq!(
        projection.to_bytes().len(),
        projection.tau().len() + projection.salt().len() + projection.public_b().len() * 4
    );
    let rendered = format!("{projection:?}");
    assert!(
        !rendered.contains("deterministic entropy for tests!"),
        "projection Debug output exposed identity generation material: {rendered}"
    );
}
