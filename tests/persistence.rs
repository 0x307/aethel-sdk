//! An identity survives being written down.
//!
//! Without this an identity dies with the process that made it, which is not an
//! identity in any useful sense.

#![cfg(not(target_arch = "wasm32"))]

use aethel_sdk::{verify, Identity};

const KEY: &[u8] = b"a sealing key of thirty-two byte";
const OTHER_KEY: &[u8] = b"a different sealing key, 32 byte";

/// The fixture was sealed on a Windows machine and is opened wherever this test
/// runs, which in CI is Linux. That is the "written on one platform, loads on
/// another" criterion tested rather than assumed: if the blob were
/// platform-dependent this would fail on exactly one of the two.
const FIXTURE: &[u8] = include_bytes!("fixtures/sealed-identity.bin");
const FIXTURE_KEY: &[u8] = b"aethel-sdk sealing fixture key!!";
const FIXTURE_PUBLIC_KEY_PREFIX: &str =
    "604db5834fe60b750f0267c8e4fa76ef4be1884ac129f12cd83b854ceb20e271";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn an_identity_round_trips_through_a_sealed_blob() {
    let mut original = Identity::generate().expect("generate");
    let public_key = original.public_key().to_vec();

    let sealed = original.export_sealed(KEY).expect("seal");
    let reopened = Identity::open_sealed(&sealed, KEY).expect("open");

    assert_eq!(
        reopened.public_key(),
        public_key.as_slice(),
        "the reopened identity is a different one"
    );
}

/// The strong form: the reopened identity can sign, and the original's public
/// key verifies it. Comparing public keys alone would pass for an
/// implementation that restored the public half and lost the private one.
#[test]
fn a_reopened_identity_can_still_sign() {
    let mut original = Identity::generate().expect("generate");
    let public_key = original.public_key().to_vec();
    let sealed = original.export_sealed(KEY).expect("seal");

    let mut reopened = Identity::open_sealed(&sealed, KEY).expect("open");
    let message = b"signed after a round trip through disk";
    let signature = reopened.sign(message).expect("sign");

    assert!(
        verify(&public_key, message, &signature).expect("verify"),
        "a signature from the reopened identity did not verify under the original key"
    );
}

/// AC: an identity written on one platform loads on another.
#[test]
fn a_fixture_sealed_on_another_platform_opens_here() {
    let identity = Identity::open_sealed(FIXTURE, FIXTURE_KEY)
        .expect("the fixture sealed on another platform did not open");

    assert_eq!(
        &hex(identity.public_key())[..64],
        FIXTURE_PUBLIC_KEY_PREFIX,
        "the fixture opened but produced a different identity"
    );
}

/// Positive control for the fixture test. An `open_sealed` that ignored its
/// input would pass the test above, so the same call on a different blob must
/// produce a different identity.
#[test]
fn the_fixture_check_distinguishes_identities() {
    let from_fixture = Identity::open_sealed(FIXTURE, FIXTURE_KEY).expect("open");

    let mut other = Identity::generate().expect("generate");
    let other_sealed = other.export_sealed(KEY).expect("seal");
    let from_other = Identity::open_sealed(&other_sealed, KEY).expect("open");

    assert_ne!(
        from_fixture.public_key(),
        from_other.public_key(),
        "two different sealed blobs opened as the same identity"
    );
}

#[test]
fn the_wrong_key_does_not_open_it() {
    let mut identity = Identity::generate().expect("generate");
    let sealed = identity.export_sealed(KEY).expect("seal");

    assert!(
        Identity::open_sealed(&sealed, OTHER_KEY).is_err(),
        "a sealed identity opened under the wrong key"
    );
}

#[test]
fn a_tampered_blob_does_not_open() {
    let mut identity = Identity::generate().expect("generate");
    let sealed = identity.export_sealed(KEY).expect("seal");

    for index in [0usize, 5, sealed.len() - 1] {
        let mut tampered = sealed.clone();
        tampered[index] ^= 0x01;
        assert!(
            Identity::open_sealed(&tampered, KEY).is_err(),
            "a blob with byte {index} flipped still opened"
        );
    }
}

#[test]
fn a_truncated_blob_does_not_open() {
    let mut identity = Identity::generate().expect("generate");
    let sealed = identity.export_sealed(KEY).expect("seal");

    assert!(Identity::open_sealed(&sealed[..sealed.len() - 1], KEY).is_err());
    assert!(Identity::open_sealed(&[], KEY).is_err());
}

#[test]
fn a_short_key_is_refused() {
    let mut identity = Identity::generate().expect("generate");
    assert!(
        identity.export_sealed(b"too short").is_err(),
        "a key shorter than the minimum was accepted for sealing"
    );
}

/// The blob must not carry the identity in the clear. This is the byte string
/// a caller writes to disk, so it is the one that matters.
#[test]
fn the_sealed_blob_does_not_contain_the_public_key() {
    let mut identity = Identity::generate().expect("generate");
    let public_key = identity.public_key().to_vec();
    let sealed = identity.export_sealed(KEY).expect("seal");

    assert!(
        !sealed.windows(32).any(|w| w == &public_key[..32]),
        "the public key appears in the sealed blob, making it identifiable at rest"
    );
}

/// Positive control for the check above.
#[test]
fn the_at_rest_leak_check_can_detect_a_leak() {
    let identity = Identity::generate().expect("generate");
    let public_key = identity.public_key().to_vec();

    let mut leaky = vec![0u8; 8];
    leaky.extend_from_slice(&public_key);

    assert!(
        leaky.windows(32).any(|w| w == &public_key[..32]),
        "the leak check cannot see the public key even when it is stored in the clear"
    );
}

/// A reopened identity is usable for everything, not only signing.
#[test]
fn a_reopened_identity_can_issue_and_present() {
    let mut original = Identity::generate().expect("generate");
    let sealed = original.export_sealed(KEY).expect("seal");
    let mut reopened = Identity::open_sealed(&sealed, KEY).expect("open");

    let credential = reopened
        .issue_credential(b"issuer seed for the sdk tests!!!", &[("tier", 3)])
        .expect("issue");
    let presentation = reopened
        .present(&credential, b"after-reload", &["tier"])
        .expect("present");

    assert_eq!(presentation.disclosed().get("tier"), Some(&3));
    assert!(
        aethel_sdk::verify_presentation(
            b"issuer seed for the sdk tests!!!",
            &presentation,
            b"after-reload"
        )
        .expect("verify"),
        "a credential issued by a reopened identity did not verify"
    );
}
