//! The embedded component executes, and agrees with aethel-core's native API.
//!
//! `tests/embedded_artifact.rs` checks that the right bytes are present. That is
//! not the same claim as "you can instantiate it and call it", and the gap
//! between those two is exactly the kind this initiative has been bitten by
//! before: a check that looks like verification and stops short of the thing it
//! implies. The component builds, validates, and exposes the declared world in
//! aethel-core's CI, and none of that would notice a component that traps on
//! every call.
//!
//! So these tests load the embedded artifact in a real runtime, call it, and
//! compare against the native implementation at the same pinned revision. If the
//! component and the native API disagree, one of them is wrong and the L1
//! boundary is not a boundary.

#![cfg(not(target_arch = "wasm32"))]

use aethel_sdk::artifact;
use aethel_sdk::component::{self, aethel::core::types::IdentityError, LoadError};

/// The component instantiates from the embedded bytes. Everything else depends
/// on this, and this is the claim `embedded_artifact.rs` cannot make.
#[test]
fn the_embedded_component_instantiates() {
    component::load().expect("the embedded component failed to instantiate");
}

/// Positive control for the integrity gate in `load`.
///
/// A substituted artifact must not execute. Without this, `load` succeeding tells
/// us the happy path works and nothing about whether the gate is wired: a `load`
/// that skipped `verify` entirely would look identical from the outside.
#[test]
fn a_substituted_component_is_refused_before_it_runs() {
    let mut tampered = artifact::COMPONENT.to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;

    match component::load_bytes(&tampered) {
        Err(LoadError::Integrity(mismatch)) => {
            assert_eq!(mismatch.declared, artifact::declared_sha256());
            assert_ne!(mismatch.actual, mismatch.declared);
        }
        Err(LoadError::Runtime(e)) => panic!(
            "a tampered component reached the runtime before the hash was checked. \
             The integrity gate is in the wrong place. Runtime said: {e}"
        ),
        Ok(_) => panic!(
            "a tampered component instantiated. The hash is decorative and a \
             substituted artifact would execute"
        ),
    }
}

/// A projection through the component must equal the native one, coefficient for
/// coefficient. This is the equivalence that makes "one artifact embedded by
/// every language" mean something: if the component drifts from the native
/// implementation, every language binding drifts with it and nothing says so.
#[test]
fn projection_through_the_component_matches_the_native_api() {
    let (mut store, bindings) = component::load().expect("load");

    let secret = [0x5Au8; 32];
    let tau = b"sdk-execution-proof".to_vec();
    let randomness = [0xC3u8; 32];

    let via_component = bindings
        .aethel_core_identity()
        .call_plp_project_at_context(&mut store, &secret, &tau, &randomness)
        .expect("host call")
        .expect("plp-project-at-context returned err");

    let identity = aethel_core::plp::MasterIdentity::from_seed(&secret);
    let native = identity.project_at_context(&tau, &randomness);

    assert_eq!(via_component.tau, native.tau.to_vec(), "tau differs");
    assert_eq!(
        via_component.salt,
        native.salt.to_vec(),
        "salt differs between the embedded component and the native API"
    );
    assert_eq!(
        via_component.public_b,
        native.public_b.coeffs().to_vec(),
        "public_b differs between the embedded component and the native API"
    );
}

/// Positive control for the comparison above: the same native call under a
/// different context must NOT match. Otherwise an equality assertion between two
/// things that are always equal would pass no matter what the component did.
#[test]
fn the_projection_comparison_can_distinguish_contexts() {
    let (mut store, bindings) = component::load().expect("load");

    let secret = [0x5Au8; 32];
    let randomness = [0xC3u8; 32];

    let via_component = bindings
        .aethel_core_identity()
        .call_plp_project_at_context(&mut store, &secret, b"context-one", &randomness)
        .expect("host call")
        .expect("projection");

    let identity = aethel_core::plp::MasterIdentity::from_seed(&secret);
    let different = identity.project_at_context(b"context-two", &randomness);

    assert_ne!(
        via_component.public_b,
        different.public_b.coeffs().to_vec(),
        "two different contexts produced the same projection. The comparison in \
         the test above cannot detect a mismatch and proves nothing"
    );
}

/// A prove and verify round trip entirely inside the component.
#[test]
fn prove_and_verify_round_trip_inside_the_component() {
    let (mut store, bindings) = component::load().expect("load");
    let identity = bindings.aethel_core_identity();

    let secret = [0x11u8; 32];
    let tau = b"sdk-round-trip".to_vec();
    let randomness = [0x77u8; 32];

    let projection = identity
        .call_plp_project_at_context(&mut store, &secret, &tau, &randomness)
        .expect("host call")
        .expect("projection");

    let proof = identity
        .call_plp_prove_identity(&mut store, &secret, &tau, &randomness)
        .expect("host call")
        .expect("proof");

    let verified = identity
        .call_plp_verify(&mut store, &projection, &proof)
        .expect("host call")
        .expect("verify returned err");

    assert!(
        verified,
        "an honestly generated proof failed to verify through the embedded component"
    );
}

/// The typed error channel reaches the caller through the SDK.
///
/// Every export in aethel-core's old wasm-bindgen surface returned a sentinel:
/// an empty vector, `false`, `0`. That is how "no shares" and "the secret was 0"
/// became the same answer. The component's `result<T, identity-error>` is the
/// fix, and it is only a fix if it survives the trip through this crate.
#[test]
fn a_short_secret_returns_a_typed_error_not_a_sentinel() {
    let (mut store, bindings) = component::load().expect("load");

    let result = bindings
        .aethel_core_identity()
        .call_plp_project_at_context(&mut store, &[0u8; 31], b"ctx", &[0u8; 32])
        .expect("host call");

    match result {
        Err(IdentityError::InvalidInputLength) => {}
        Err(other) => panic!("expected invalid-input-length, got {other:?}"),
        Ok(_) => panic!("a 31-byte secret was accepted"),
    }
}

/// HTSS round trip through the component, including the below-threshold error.
#[test]
fn htss_round_trips_and_reports_threshold_not_met() {
    let (mut store, bindings) = component::load().expect("load");
    let sharing = bindings.aethel_core_secret_sharing();

    let secret = b"32-byte key material for HTSS !!".to_vec();
    assert_eq!(secret.len(), 32, "test setup");

    let (shares, merkle_root) = sharing
        .call_htss_split(&mut store, &secret)
        .expect("host call")
        .expect("split");
    assert_eq!(shares.len(), 5, "expected a 3-of-5 split");

    let recovered = sharing
        .call_htss_reconstruct(&mut store, &shares[..3], &merkle_root)
        .expect("host call")
        .expect("reconstruct");
    assert_eq!(
        recovered, secret,
        "key material did not survive the round trip through the embedded component"
    );

    // Two shares must be an error, not a wrong answer and not an empty vector.
    match sharing
        .call_htss_reconstruct(&mut store, &shares[..2], &merkle_root)
        .expect("host call")
    {
        Err(IdentityError::ThresholdNotMet) => {}
        Err(other) => panic!("expected threshold-not-met, got {other:?}"),
        Ok(_) => panic!("two shares of a 3-of-5 split reconstructed something"),
    }
}

/// The superseded single-relation `attestation` interface is absent from the
/// pinned component's world.
///
/// It used to export `saap-prove` / `saap-verify`, whose verify half denied
/// unconditionally because it had no sound way to check a proof: the only
/// public key that construction admitted was an exact linear image of the
/// secret, never safe to publish. aethel-core 0.1.5 removed it in favour of
/// `saap-verify-presentation`, anchored on the noisy projection `b_tau`, which
/// this SDK exercises through `disclosure`.
///
/// Checked against the vendored WIT rather than the bindings, because a
/// reappearing interface should fail here as an assertion rather than as a
/// compile error in a test that no longer describes the world.
#[test]
fn the_pinned_component_has_no_attestation_interface() {
    let wit = include_str!("../core/wit/aethel-core.wit");
    assert!(
        !wit.contains("interface attestation"),
        "the attestation interface reappeared in the vendored world. It was \
         removed in aethel-core 0.1.5 because its verify half could never be \
         sound; if it is genuinely back, that reasoning has to be revisited \
         before this test is deleted"
    );
    assert!(
        !wit.contains("export attestation"),
        "attestation is exported from the vendored world without its interface \
         definition being restored consistently"
    );
}
