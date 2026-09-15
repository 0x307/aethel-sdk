//! The README quickstart, kept as an example so it is compiled and run rather
//! than believed. If this stops working, CI notices before a reader does.

use aethel_sdk::{verify, Identity};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Entropy comes from the OS. The signing key is derived from it inside the
    // embedded component and never enters this process.
    let mut identity = Identity::generate()?;

    // Sign and verify.
    let message = b"the message that was actually signed";
    let signature = identity.sign(message)?;
    assert!(verify(identity.public_key(), message, &signature)?);
    assert!(!verify(
        identity.public_key(),
        b"something else",
        &signature
    )?);

    // The interoperable form of the public key: base58btc over the multicodec
    // code for ML-DSA-65. This is what goes in a DID document.
    let multikey = identity.public_key_multibase();
    assert!(multikey.starts_with('z'));

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

    println!("ok: signed, verified, sealed, reopened and projected {multikey:.16}...");
    Ok(())
}
