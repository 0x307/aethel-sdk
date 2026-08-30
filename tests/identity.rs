//! The SDK surface: generate, sign, verify.
//!
//! `component_execution.rs` proves the component does these things. This file
//! proves the SDK surface over them does not lose the properties on the way
//! across, which is a separate claim: a wrapper that swallowed an error, or
//! verified against the wrong key, would leave every one of those tests passing.

#![cfg(not(target_arch = "wasm32"))]

use aethel_sdk::{identity::Error, verify, Identity};

const ENTROPY: &[u8; 32] = b"deterministic entropy for tests!";
const OTHER_ENTROPY: &[u8; 32] = b"a completely different entropy!!";

#[test]
fn generate_produces_an_identity_with_a_public_key() {
    let id = Identity::generate().expect("generate");
    assert!(!id.public_key().is_empty(), "generated identity has no public key");
}

/// Two calls to `generate` must differ, or the OS entropy is not reaching the
/// derivation and every identity this SDK makes would be the same one.
#[test]
fn two_generated_identities_are_different() {
    let a = Identity::generate().expect("generate");
    let b = Identity::generate().expect("generate");
    assert_ne!(
        a.public_key(),
        b.public_key(),
        "two calls to generate produced the same identity, so entropy is not reaching \
         the component"
    );
}

#[test]
fn generation_from_entropy_is_deterministic() {
    let a = Identity::from_entropy(ENTROPY).expect("generate");
    let b = Identity::from_entropy(ENTROPY).expect("generate");
    assert_eq!(a.public_key(), b.public_key());
}

/// Positive control for the test above: without this, an implementation that
/// ignored its entropy entirely would still look deterministic.
#[test]
fn different_entropy_produces_a_different_identity() {
    let a = Identity::from_entropy(ENTROPY).expect("generate");
    let b = Identity::from_entropy(OTHER_ENTROPY).expect("generate");
    assert_ne!(a.public_key(), b.public_key());
}

/// The entropy floor is enforced by the component and must surface here as a
/// typed error rather than a panic or a silently weak identity.
#[test]
fn short_entropy_is_rejected() {
    match Identity::from_entropy(b"too short") {
        Err(Error::Component(
            aethel_sdk::component::aethel::core::types::IdentityError::InvalidInputLength,
        )) => {}
        Err(other) => panic!("expected invalid-input-length, got {other:?}"),
        Ok(_) => panic!("9 bytes of entropy produced an identity"),
    }
}

#[test]
fn sign_and_verify_round_trip() {
    let mut id = Identity::from_entropy(ENTROPY).expect("generate");
    let message = b"the message that was actually signed";

    let signature = id.sign(message).expect("sign");
    assert!(
        verify(id.public_key(), message, &signature).expect("verify"),
        "an honestly produced signature failed to verify through the SDK"
    );
}

/// Positive control for the round trip. A `verify` that returned `true`
/// unconditionally would pass the test above and nothing else here.
#[test]
fn verification_rejects_a_tampered_message() {
    let mut id = Identity::from_entropy(ENTROPY).expect("generate");
    let signature = id.sign(b"transfer 10 to alice").expect("sign");

    assert!(
        !verify(id.public_key(), b"transfer 99 to alice", &signature).expect("verify"),
        "a signature verified against a message it was not made over"
    );
}

#[test]
fn verification_rejects_a_wrong_key_signature() {
    let mut signer = Identity::from_entropy(ENTROPY).expect("generate");
    let other = Identity::from_entropy(OTHER_ENTROPY).expect("generate");

    let message = b"signed by exactly one of these";
    let signature = signer.sign(message).expect("sign");

    assert!(
        !verify(other.public_key(), message, &signature).expect("verify"),
        "a signature verified under a key that did not produce it"
    );
}

#[test]
fn verification_rejects_a_tampered_signature() {
    let mut id = Identity::from_entropy(ENTROPY).expect("generate");
    let message = b"message";
    let mut signature = id.sign(message).expect("sign");
    signature[0] ^= 0x01;

    assert!(!verify(id.public_key(), message, &signature).expect("verify"));
}

#[test]
fn signing_is_deterministic() {
    let mut id = Identity::from_entropy(ENTROPY).expect("generate");
    let message = b"same message, twice";
    assert_eq!(id.sign(message).unwrap(), id.sign(message).unwrap());
}

/// Formatting an identity must not print key material.
///
/// The strong version of this claim is that there is no secret in the struct to
/// print: the key lives in the component instance. This asserts the observable
/// half, that the derived entropy does not appear in the output, and that the
/// formatting says where the secret actually is rather than being silent about
/// it.
#[test]
fn debug_formatting_does_not_leak() {
    let id = Identity::from_entropy(ENTROPY).expect("generate");
    let rendered = format!("{id:?}");

    assert!(
        !rendered.contains("deterministic entropy for tests!"),
        "Debug output contained the generation entropy verbatim: {rendered}"
    );
    assert!(
        rendered.contains("held in the component"),
        "Debug output does not say where the secret lives: {rendered}"
    );

    // The full public key is not secret, but printing it in full makes Debug
    // output unusable in logs. A fingerprint is the intent, so pin it.
    let full_key_hex: String = id.public_key().iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        !rendered.contains(&full_key_hex),
        "Debug output printed the entire public key"
    );
}

/// Positive control for the leak test: the assertion machinery must be able to
/// see the entropy string when it really is present. Otherwise
/// `debug_formatting_does_not_leak` proves only that `contains` was called.
#[test]
fn the_leak_check_can_detect_a_leak() {
    let leaky = format!("Identity {{ entropy: {} }}", String::from_utf8_lossy(ENTROPY));
    assert!(
        leaky.contains("deterministic entropy for tests!"),
        "the leak check cannot detect the entropy even when it is present"
    );
}

/// Two identities must not observe each other. Each owns its own component
/// instance, and signing with one must not be affected by the other existing.
#[test]
fn identities_are_isolated_from_each_other() {
    let mut a = Identity::from_entropy(ENTROPY).expect("generate");
    let mut b = Identity::from_entropy(OTHER_ENTROPY).expect("generate");

    let message = b"isolation check";
    let sig_a = a.sign(message).expect("sign");
    let sig_b = b.sign(message).expect("sign");

    assert_ne!(sig_a, sig_b, "two identities produced the same signature");
    assert!(verify(a.public_key(), message, &sig_a).expect("verify"));
    assert!(verify(b.public_key(), message, &sig_b).expect("verify"));
    assert!(!verify(a.public_key(), message, &sig_b).expect("verify"));
}
