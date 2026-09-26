//! The public key's W3C Multikey encoding.
//!
//! `Identity::public_key_multibase` delegates to `pqc-sig`, so comparing it to
//! `pqc-sig` would test shared code, not independent conformance. The fixed
//! fixture below protects the historical SDK wire output. The `multibase`
//! assertion remains independent coverage for the Multibase layer.

#![cfg(not(target_arch = "wasm32"))]

use aethel_sdk::{public_key_from_multibase, verify_typed, Identity};
use pqc_sig::{SigAlgorithm, SigPublicKey};

const ENTROPY: &[u8; 32] = b"deterministic entropy for tests!";
const HISTORICAL_ML_DSA_65_MULTIKEY: &str = include_str!("fixtures/historical-ml-dsa-65.multikey");

/// The registered multicodec code for ML-DSA-65, `0x1211`, as unsigned LEB128.
/// Written out rather than computed, so a broken varint encoder cannot agree
/// with itself.
const ML_DSA_65_PREFIX: [u8; 2] = [0x91, 0x24];

#[test]
fn the_multikey_decodes_under_a_third_party_multiformats_implementation() {
    let identity = Identity::from_entropy(ENTROPY).expect("identity");
    let encoded = identity.public_key_multibase();

    // multibase is a separate implementation of the spec, by other authors.
    let (base, decoded) = multibase::decode(&encoded).expect("third-party decode");

    assert_eq!(
        base,
        multibase::Base::Base58Btc,
        "Multikey requires base58btc, and the 'z' prefix is what says so"
    );
    assert_eq!(
        &decoded[..2],
        &ML_DSA_65_PREFIX,
        "the multicodec prefix is not ML-DSA-65's registered code"
    );
    assert_eq!(
        &decoded[2..],
        identity.public_key(),
        "the encoded key bytes are not the identity's public key"
    );
}

#[test]
fn the_multikey_remains_byte_identical_to_the_historical_sdk_fixture() {
    let identity = Identity::from_entropy(ENTROPY).expect("identity");
    assert_eq!(
        identity.public_key_multibase(),
        HISTORICAL_ML_DSA_65_MULTIKEY.trim_end()
    );
}

#[test]
fn decoded_multikey_verifies_a_real_aethel_signature() {
    let mut identity = Identity::from_entropy(ENTROPY).expect("identity");
    let decoded = public_key_from_multibase(&identity.public_key_multibase()).expect("decode");
    let message = b"cross-process public verification";
    let signature = identity.sign_typed(message).expect("sign");

    assert!(verify_typed(&decoded, message, &signature).expect("verify"));
}

#[test]
fn a_multikey_for_a_different_algorithm_does_not_decode_as_ml_dsa_65() {
    // The positive control above only shows the decoder accepts our string. It
    // would accept it just as happily if it ignored the code entirely. This is
    // the other half: a key announcing ML-DSA-44 is refused when ML-DSA-65 is
    // asked for, so the code is genuinely being read.
    let identity = Identity::from_entropy(ENTROPY).expect("identity");
    let mismatched =
        SigPublicKey::new(SigAlgorithm::MlDsa44, identity.public_key().to_vec()).to_multibase();

    assert!(public_key_from_multibase(&mismatched.expect("encode")).is_err());
}

#[test]
fn a_multikey_with_an_invalid_public_key_length_is_rejected() {
    let malformed = SigPublicKey::new(SigAlgorithm::MlDsa65, vec![0; 8])
        .to_multibase()
        .expect("encode");
    assert!(public_key_from_multibase(&malformed).is_err());
}

#[test]
fn invalid_multibase_is_rejected() {
    assert!(public_key_from_multibase("not-a-multikey").is_err());
}

#[test]
fn distinct_identities_produce_distinct_multikeys() {
    let first = Identity::from_entropy(ENTROPY).expect("first identity");
    let second = Identity::from_entropy(b"a different 32 bytes of entropy!").expect("second");

    assert_ne!(first.public_key_multibase(), second.public_key_multibase());
}

#[test]
fn the_encoding_is_stable_for_one_identity() {
    // Generation is deterministic in its entropy, so the Multikey is too. A
    // caller publishing this in a DID document needs it not to move.
    let first = Identity::from_entropy(ENTROPY).expect("identity");
    let second = Identity::from_entropy(ENTROPY).expect("identity again");

    assert_eq!(first.public_key_multibase(), second.public_key_multibase());
    assert!(first.public_key_multibase().starts_with('z'));
}
