//! The public key's W3C Multikey encoding, checked by decoders that share no
//! code with the encoder.
//!
//! The encoder is eight lines of varint plus a base58btc call. That is small
//! enough to look obviously right and still be wrong in a way that produces a
//! well-formed string: a bad multicodec code yields a perfectly valid Multikey
//! describing a different algorithm. So nothing here re-derives the expected
//! value the way the encoder does. Each test decodes with something else.

#![cfg(not(target_arch = "wasm32"))]

use aethel_sdk::Identity;
use pqc_sig::types::{SigAlgorithm, SigPublicKey};

const ENTROPY: &[u8; 32] = b"deterministic entropy for tests!";

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
fn the_multikey_decodes_under_pqc_sigs_independent_implementation() {
    let identity = Identity::from_entropy(ENTROPY).expect("identity");
    let encoded = identity.public_key_multibase();

    // pqc-sig is a separate codebase with its own varint and its own
    // multicodec table. It checks the embedded code against the algorithm it
    // was asked for, so a wrong code fails here rather than round-tripping.
    let decoded = SigPublicKey::from_multibase(SigAlgorithm::MlDsa65, &encoded)
        .expect("independent decode as ML-DSA-65");

    assert_eq!(decoded.as_bytes(), identity.public_key());
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

    assert!(
        SigPublicKey::from_multibase(SigAlgorithm::MlDsa65, &mismatched.expect("encode")).is_err(),
        "the multicodec code is not being checked"
    );
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
