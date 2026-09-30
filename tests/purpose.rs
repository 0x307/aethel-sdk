//! Purpose-separated signing through the SDK (COR-18).
//!
//! A signature made under a purpose must verify under that purpose and nowhere
//! else. Each test that asserts a refusal sits next to the acceptance it is the
//! negative of, so a verifier that refused everything fails here.

#![cfg(not(target_arch = "wasm32"))]

use aethel_sdk::{
    identity::Error, public_key_from_multibase, verify, verify_typed_with_purpose,
    verify_with_purpose, Identity, Purpose,
};

const ENTROPY: &[u8; 32] = b"deterministic entropy for tests!";
const MESSAGE: &[u8] = b"one statement, many purposes";

fn registry() -> &'static [Purpose] {
    Purpose::registered().expect("the registry")
}

/// AC1. A signature under purpose A verifies under A, and fails under every
/// other registered purpose and under the empty context.
#[test]
fn a_purpose_signature_verifies_only_under_its_own_purpose() {
    let mut identity = Identity::from_entropy(ENTROPY).expect("identity");
    let public_key = identity.public_key().to_vec();
    assert!(registry().len() > 1, "a registry of one cannot show separation");

    for purpose in registry() {
        let signature = identity
            .sign_with_purpose(purpose, MESSAGE)
            .unwrap_or_else(|e| panic!("signing under {} failed: {e}", purpose.name()));

        for other in registry() {
            let verified = verify_with_purpose(&public_key, other, MESSAGE, &signature)
                .expect("verification");
            assert_eq!(
                verified,
                purpose == other,
                "a signature made under {} {} under {}",
                purpose.name(),
                if verified { "verified" } else { "failed to verify" },
                other.name()
            );
        }
        assert!(
            !verify(&public_key, MESSAGE, &signature).expect("verification"),
            "a signature made under {} verified under the empty context",
            purpose.name()
        );
    }
}

/// AC2. A signature made with plain `sign` fails under every registered purpose,
/// and still verifies under the empty context (the positive control).
#[test]
fn a_plain_signature_fails_under_every_purpose() {
    let mut identity = Identity::from_entropy(ENTROPY).expect("identity");
    let public_key = identity.public_key().to_vec();
    let plain = identity.sign(MESSAGE).expect("sign");

    assert!(verify(&public_key, MESSAGE, &plain).expect("verify"), "plain verify failed");
    for purpose in registry() {
        assert!(
            !verify_with_purpose(&public_key, purpose, MESSAGE, &plain).expect("verification"),
            "a plain signature verified under {}",
            purpose.name()
        );
    }
}

/// AC3. The SDK agrees with aethel-core's own native implementation, in both
/// directions, for every registered purpose.
#[test]
fn the_sdk_agrees_with_aethel_cores_native_purpose_api() {
    let mut sdk = Identity::from_entropy(ENTROPY).expect("identity");
    let native = aethel_core::signing::Identity::generate(ENTROPY).expect("native identity");
    assert_eq!(sdk.public_key(), native.public_key().as_slice(), "same entropy, different key");
    let public_key = sdk.public_key().to_vec();

    for purpose in registry() {
        // SDK signs, native verifies.
        let from_sdk = sdk.sign_with_purpose(purpose, MESSAGE).expect("sdk sign");
        assert!(
            aethel_core::signing::verify_with_purpose(
                &public_key,
                purpose.as_bytes(),
                MESSAGE,
                &from_sdk
            )
            .expect("native verify"),
            "native verification rejected the SDK's signature under {}",
            purpose.name()
        );
        // Native signs, SDK verifies.
        let from_native = native
            .sign_with_purpose(purpose.as_bytes(), MESSAGE)
            .expect("native sign");
        assert!(
            verify_with_purpose(&public_key, purpose, MESSAGE, &from_native).expect("sdk verify"),
            "the SDK rejected a native signature under {}",
            purpose.name()
        );
        assert_eq!(from_sdk, from_native, "signing is deterministic, so they must match");
    }
}

/// The registry the SDK reads from the component is aethel-core's registry: the
/// same names and bytes, in the same order. Any difference fails, and so would a
/// purpose added to core and not exported.
#[test]
fn the_sdk_registry_is_aethel_cores_registry() {
    let native = aethel_core::signing::purpose::ALL;
    assert_eq!(registry().len(), native.len(), "the registries differ in size");
    for (purpose, (name, bytes)) in registry().iter().zip(native) {
        assert_eq!(purpose.name(), *name);
        assert_eq!(purpose.as_bytes(), *bytes, "{name}");
    }
}

/// AC4. Only registered purposes exist. A name that is not registered is refused
/// with a typed error, and a registered one is found. There is no constructor
/// from bytes: the two `compile_fail` doctests on `Purpose` pin that.
#[test]
fn only_registered_purposes_can_be_named() {
    assert!(Purpose::from_name("AUTH_LOGIN_V1").is_ok(), "a registered purpose was not found");
    match Purpose::from_name("MADE_UP_V1") {
        Err(Error::UnknownPurpose(name)) => assert_eq!(name, "MADE_UP_V1"),
        other => panic!("an unregistered name was not refused: {other:?}"),
    }
    // A registered purpose's bytes are not a name.
    assert!(Purpose::from_name("aethel-auth/login/v1").is_err());
    assert!(Purpose::from_name("").is_err());
}

/// The typed forms carry the same separation, through a public key that crossed
/// a process boundary as a Multikey and a signature that crossed as JSON.
#[test]
fn typed_purpose_signatures_keep_the_separation_across_a_boundary() {
    let mut identity = Identity::from_entropy(ENTROPY).expect("identity");
    let login = Purpose::from_name("AUTH_LOGIN_V1").expect("login");
    let step_up = Purpose::from_name("AUTH_STEP_UP_V1").expect("step-up");

    let key = public_key_from_multibase(&identity.public_key_multibase()).expect("key");
    let json = identity
        .sign_typed_with_purpose(&login, MESSAGE)
        .expect("sign")
        .to_json()
        .expect("json");
    let received = aethel_sdk::Signature::from_json(&json).expect("decode");

    assert!(verify_typed_with_purpose(&key, &login, MESSAGE, &received).expect("verify"));
    assert!(!verify_typed_with_purpose(&key, &step_up, MESSAGE, &received).expect("verify"));
    assert!(!verify_typed_with_purpose(&key, &login, b"another statement", &received)
        .expect("verify"));
}
