//! `Verifier` must behave identically to the free functions it wraps.
//!
//! `identity.rs` and `disclosure.rs` prove the free-function contracts. This
//! file proves `Verifier::verify` and `Verifier::verify_presentation` agree
//! with `verify` and `verify_presentation` on the same inputs, and that one
//! `Verifier` can be reused across multiple verifications.

#![cfg(not(target_arch = "wasm32"))]

use aethel_sdk::{verify, verify_presentation, Identity, Verifier};

#[test]
fn a_held_verifier_agrees_with_the_free_function_for_signatures() {
    let mut identity = Identity::generate().expect("generate");
    let message = b"the message that was actually signed";
    let signature = identity.sign(message).expect("sign");

    let verifier = Verifier::new().expect("verifier");
    assert!(verifier
        .verify(identity.public_key(), message, &signature)
        .expect("verify"));
    assert_eq!(
        verifier.verify(identity.public_key(), message, &signature).expect("verify"),
        verify(identity.public_key(), message, &signature).expect("verify"),
    );
    assert!(!verifier
        .verify(identity.public_key(), b"a different message", &signature)
        .expect("verify"));
}

#[test]
fn a_held_verifier_agrees_with_the_free_function_for_presentations() {
    let mut identity = Identity::generate().expect("generate");
    let issuer_seed = b"the issuer's secret seed, 32 byte";
    let context = b"checkout-session";

    let credential =
        identity.issue_credential(issuer_seed, &[("tier", 3)]).expect("issue");
    let presentation = identity.present(&credential, context, &["tier"]).expect("present");

    let verifier = Verifier::new().expect("verifier");
    assert!(verifier
        .verify_presentation(issuer_seed, &presentation, context)
        .expect("verify"));
    assert_eq!(
        verifier.verify_presentation(issuer_seed, &presentation, context).expect("verify"),
        verify_presentation(issuer_seed, &presentation, context).expect("verify"),
    );
    assert!(!verifier
        .verify_presentation(issuer_seed, &presentation, b"a different context")
        .expect("verify"));
}

/// One `Verifier` must serve more than one verification, or owning the
/// runtime bought nothing over the free functions.
#[test]
fn one_verifier_serves_multiple_verifications() {
    let mut identity = Identity::generate().expect("generate");
    let message = b"first message";
    let signature = identity.sign(message).expect("sign");

    let verifier = Verifier::new().expect("verifier");
    for _ in 0..3 {
        assert!(verifier
            .verify(identity.public_key(), message, &signature)
            .expect("verify"));
    }
}
