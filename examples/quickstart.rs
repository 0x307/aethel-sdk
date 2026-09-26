//! The README quickstart, kept as an example so it is compiled and run rather
//! than believed. If this stops working, CI notices before a reader does.

use aethel_sdk::{public_key_from_multibase, verify, verify_typed, Identity, Signature};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Entropy comes from the OS. The signing key is derived from it inside the
    // embedded component and never enters this process.
    let mut identity = Identity::generate()?;

    // PROCESS A — signer: make transport-safe public verification material and
    // an algorithm-labelled signature. The identity's private material remains
    // inside the embedded component.
    let message = b"the message that was actually signed";
    let multikey = identity.public_key_multibase();
    let signature_json = identity.sign_typed(message)?.to_json()?;

    // PROCESS B — verifier: this process needs only the received Multikey,
    // JSON signature, and original message. It does not have the identity or
    // the sealing key.
    let received_key = public_key_from_multibase(&multikey)?;
    let received_signature = Signature::from_json(&signature_json)?;
    assert!(verify_typed(&received_key, message, &received_signature)?);
    assert!(!verify_typed(
        &received_key,
        b"something else",
        &received_signature
    )?);

    // The established byte-slice APIs remain available for existing callers.
    let bytes_signature = identity.sign(message)?;
    assert!(verify(identity.public_key(), message, &bytes_signature)?);

    // Persist it. `key` must be high-entropy key material, NOT a password.
    let key = b"a sealing key of thirty-two byte";
    let sealed = identity.export_sealed(key)?;
    let mut identity = Identity::open_sealed(&sealed, key)?;

    // Project the identity into a context. Each call uses fresh secret
    // randomness, so two projections at the same context are independent, and
    // neither exposes the master secret.
    let first = identity.project_at(b"checkout-session")?;
    let second = identity.project_at(b"checkout-session")?;
    assert_ne!(first.salt(), second.salt());

    println!("ok: typed signed, verified, sealed, reopened and projected {multikey:.16}...");
    Ok(())
}
