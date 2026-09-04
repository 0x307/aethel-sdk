//! Selective disclosure through the SDK surface.
//!
//! `component_execution.rs` proves the component does this. These tests prove
//! the named-attribute surface over it does not lose the properties on the way
//! across: that disclosing by name discloses the right slots, that a name the
//! credential does not carry is refused rather than silently disclosing nothing,
//! and that verification still rejects what it should.

#![cfg(not(target_arch = "wasm32"))]

use aethel_sdk::{verify_presentation, Identity};

const ISSUER_SEED: &[u8] = b"issuer seed for the sdk tests!!!";

fn attributes() -> Vec<(&'static str, u64)> {
    vec![
        ("tier", 3),
        ("date_of_birth", 19_900_101),
        ("member_since", 2021),
        ("region_code", 44),
    ]
}

fn issued() -> (Identity, aethel_sdk::Credential) {
    let mut identity = Identity::generate().expect("generate");
    let credential = identity
        .issue_credential(ISSUER_SEED, &attributes())
        .expect("issue");
    (identity, credential)
}

/// The headline: prove you hold the credential and reveal only `tier`.
#[test]
fn a_presentation_discloses_only_the_named_attributes() {
    let (mut identity, credential) = issued();

    let presentation = identity
        .present(&credential, b"checkout-session", &["tier"])
        .expect("present");

    let disclosed = presentation.disclosed();
    assert_eq!(disclosed.get("tier"), Some(&3));
    assert_eq!(
        disclosed.len(),
        1,
        "more than the named attribute was disclosed"
    );
    assert!(
        !disclosed.contains_key("date_of_birth"),
        "an attribute that was not named came out anyway"
    );
}

/// And it verifies.
#[test]
fn a_presentation_verifies() {
    let (mut identity, credential) = issued();
    let presentation = identity
        .present(&credential, b"checkout-session", &["tier"])
        .expect("present");

    assert!(
        verify_presentation(ISSUER_SEED, &presentation, b"checkout-session").expect("verify"),
        "an honest presentation failed to verify through the SDK"
    );
}

/// Positive control for the test above. A `verify_presentation` that returned
/// `true` unconditionally would pass it and every other happy-path test here.
#[test]
fn verification_fails_under_a_different_issuer() {
    let (mut identity, credential) = issued();
    let presentation = identity
        .present(&credential, b"checkout-session", &["tier"])
        .expect("present");

    assert!(
        !verify_presentation(
            b"a completely different issuer!!!",
            &presentation,
            b"checkout-session"
        )
        .expect("verify"),
        "a presentation verified under an issuer that never issued it"
    );
}

/// A presentation must not certify its own context.
#[test]
fn verification_fails_under_a_different_context() {
    let (mut identity, credential) = issued();
    let presentation = identity
        .present(&credential, b"checkout-session", &["tier"])
        .expect("present");

    assert!(
        !verify_presentation(ISSUER_SEED, &presentation, b"some-other-session").expect("verify"),
        "a presentation made for one context verified under another"
    );
}

/// AC: disclosure is by name, and a name the credential does not carry is an
/// error. Silently disclosing nothing would produce a valid proof of a
/// statement the caller did not intend to make.
#[test]
fn an_unknown_attribute_name_is_refused() {
    let (mut identity, credential) = issued();

    match identity.present(&credential, b"checkout-session", &["salary"]) {
        Err(aethel_sdk::identity::Error::UnknownAttribute(name)) => {
            assert_eq!(name, "salary");
        }
        Err(other) => panic!("expected UnknownAttribute, got {other:?}"),
        Ok(_) => panic!("disclosing an attribute the credential does not carry succeeded"),
    }
}

/// Disclosing several named attributes discloses exactly those.
#[test]
fn several_attributes_can_be_disclosed_together() {
    let (mut identity, credential) = issued();
    let presentation = identity
        .present(&credential, b"kyc-session", &["tier", "region_code"])
        .expect("present");

    let disclosed = presentation.disclosed();
    assert_eq!(disclosed.get("tier"), Some(&3));
    assert_eq!(disclosed.get("region_code"), Some(&44));
    assert_eq!(disclosed.len(), 2);
    assert!(verify_presentation(ISSUER_SEED, &presentation, b"kyc-session").expect("verify"));
}

/// Disclosing nothing at all still proves credential possession and identity
/// linkage, which is the minimum useful statement.
#[test]
fn disclosing_nothing_still_verifies() {
    let (mut identity, credential) = issued();
    let presentation = identity
        .present(&credential, b"anonymous-session", &[])
        .expect("present");

    assert!(presentation.disclosed().is_empty());
    assert!(
        verify_presentation(ISSUER_SEED, &presentation, b"anonymous-session").expect("verify"),
        "a presentation disclosing nothing failed to verify"
    );
}

/// AC: an undisclosed attribute is not recoverable from the presentation.
///
/// Checks the observable consequence: the value does not appear in what the
/// presentation exposes, and it does not appear in the serialised responses.
#[test]
fn an_undisclosed_attribute_is_not_in_the_presentation() {
    let (mut identity, credential) = issued();
    let dob: u64 = 19_900_101;

    let presentation = identity
        .present(&credential, b"checkout-session", &["tier"])
        .expect("present");

    assert!(
        !presentation.disclosed().values().any(|v| *v == dob),
        "the hidden date of birth was disclosed"
    );

    // And it is not sitting in the raw response coefficients either.
    let mut raw = Vec::new();
    for c in presentation.projection().public_b.iter() {
        raw.extend_from_slice(&c.to_le_bytes());
    }
    assert!(
        !raw.windows(8).any(|w| w == dob.to_le_bytes()),
        "the hidden value appears in the projection"
    );
}

/// Positive control for the leak check above.
#[test]
fn the_leak_check_can_detect_a_leak() {
    let dob: u64 = 19_900_101;
    let mut planted = vec![0u8; 8];
    planted.extend_from_slice(&dob.to_le_bytes());
    assert!(
        planted.windows(8).any(|w| w == dob.to_le_bytes()),
        "the leak check cannot see the value even when present"
    );
}

/// Two presentations of the same credential must not be linkable by anything
/// they carry, and both must still verify.
#[test]
fn two_presentations_are_unlinkable_and_both_verify() {
    let (mut identity, credential) = issued();

    let first = identity
        .present(&credential, b"session-one", &["tier"])
        .expect("present");
    let second = identity
        .present(&credential, b"session-two", &["tier"])
        .expect("present");

    assert!(verify_presentation(ISSUER_SEED, &first, b"session-one").expect("verify"));
    assert!(verify_presentation(ISSUER_SEED, &second, b"session-two").expect("verify"));

    assert_eq!(first.disclosed(), second.disclosed(), "test setup");
    assert_ne!(
        format!("{:?}", first.projection().public_b),
        format!("{:?}", second.projection().public_b),
        "two presentations shared a projection, so they are linkable"
    );
}

/// More attributes than a credential has slots for is an error, not a
/// truncation. A truncated credential would issue and present cleanly while
/// omitting attributes the caller believed were in it.
#[test]
fn too_many_attributes_is_refused() {
    let mut identity = Identity::generate().expect("generate");
    let too_many: Vec<(&str, u64)> = (0..9)
        .map(|i| (["a", "b", "c", "d", "e", "f", "g", "h", "i"][i], i as u64))
        .collect();

    assert!(
        matches!(
            identity.issue_credential(ISSUER_SEED, &too_many),
            Err(aethel_sdk::identity::Error::TooManyAttributes(9))
        ),
        "nine attributes were accepted into eight slots"
    );
}

/// `Debug` on a credential must not print the attribute values: they are held
/// in the component and the SDK never sees them.
#[test]
fn credential_debug_does_not_print_values() {
    let (_identity, credential) = issued();
    let rendered = format!("{credential:?}");

    assert!(rendered.contains("tier"), "the schema should be visible");
    assert!(
        !rendered.contains("19900101"),
        "Debug printed an attribute value: {rendered}"
    );
    assert!(
        rendered.contains("held in the component"),
        "Debug does not say where the values live: {rendered}"
    );
}
