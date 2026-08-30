//! The README quickstart, kept as an example so it is compiled and run rather
//! than believed. If this stops working, CI notices before a reader does.

use aethel_sdk::{verify, verify_presentation, Identity};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Entropy comes from the OS. The signing key is derived from it inside the
    // embedded component and never enters this process.
    let mut identity = Identity::generate()?;

    // Sign and verify.
    let message = b"the message that was actually signed";
    let signature = identity.sign(message)?;
    assert!(verify(identity.public_key(), message, &signature)?);
    assert!(!verify(identity.public_key(), b"something else", &signature)?);

    // Persist it. `key` must be high-entropy key material, NOT a password.
    let key = b"a sealing key of thirty-two byte";
    let sealed = identity.export_sealed(key)?;
    let mut identity = Identity::open_sealed(&sealed, key)?;

    // Issue a credential over named attributes, and disclose only one of them.
    let credential = identity.issue_credential(
        b"the issuer's secret seed, 32 byte",
        &[("tier", 3), ("date_of_birth", 19_900_101)],
    )?;
    let presentation = identity.present(&credential, b"checkout-session", &["tier"])?;

    // The verifier learns the tier and nothing about the date of birth.
    assert_eq!(presentation.disclosed().get("tier"), Some(&3));
    assert!(presentation.disclosed().get("date_of_birth").is_none());
    assert!(verify_presentation(
        b"the issuer's secret seed, 32 byte",
        &presentation,
        b"checkout-session",
    )?);

    Ok(())
}