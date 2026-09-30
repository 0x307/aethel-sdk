//! Deciding whom to trust. Referenced from docs/AGENT-IDENTITY.md.
//!
//! A verifier keeps its own allowlist of Multikey strings. A signature counts
//! only if it is valid AND its key is on that list. The list is the verifier's
//! decision; nothing here asks a registry run by anyone else.
//!
//! The run fails (non-zero exit) if the untrusted signer is accepted or the
//! trusted one is refused, so the positive and negative cases sit side by side.

use aethel_sdk::{public_key_from_multibase, verify_typed, Identity, Signature};

/// What a verifier does with a public key and signature received from outside.
fn accept(
    allowlist: &[String],
    multikey: &str,
    message: &[u8],
    signature_json: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    if !allowlist.iter().any(|trusted| trusted == multikey) {
        return Ok(false);
    }
    let key = public_key_from_multibase(multikey)?;
    let signature = Signature::from_json(signature_json)?;
    Ok(verify_typed(&key, message, &signature)?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut trusted = Identity::generate()?;
    let mut stranger = Identity::generate()?;

    // The verifier has only ever been told about the first agent's key.
    let allowlist = vec![trusted.public_key_multibase()];

    let message = b"agent 7 finished task 42 for customer A";

    // Each agent signs the same statement and publishes its key and signature.
    let from_trusted = (
        trusted.public_key_multibase(),
        trusted.sign_typed(message)?.to_json()?,
    );
    let from_stranger = (
        stranger.public_key_multibase(),
        stranger.sign_typed(message)?.to_json()?,
    );

    // Positive control: the trusted signer is accepted.
    assert!(
        accept(&allowlist, &from_trusted.0, message, &from_trusted.1)?,
        "the trusted signer was refused"
    );

    // Negative control: a valid signature from a key that is not on the list is refused.
    assert!(
        !accept(&allowlist, &from_stranger.0, message, &from_stranger.1)?,
        "an untrusted signer was accepted"
    );

    // A trusted key does not vouch for a different statement.
    assert!(
        !accept(&allowlist, &from_trusted.0, b"a different statement", &from_trusted.1)?,
        "a signature was accepted for a message it did not sign"
    );

    println!("ok: trusted signer accepted, untrusted signer refused");
    Ok(())
}
