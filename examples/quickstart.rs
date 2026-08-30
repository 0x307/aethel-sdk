//! The README quickstart, kept as an example so it is compiled and run rather
//! than believed. If this stops working, CI notices before a reader does.

use aethel_sdk::{verify, Identity};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Entropy comes from the OS. The signing key is derived from it inside the
    // embedded component and never enters this process.
    let mut identity = Identity::generate()?;

    let message = b"the message that was actually signed";
    let signature = identity.sign(message)?;

    assert!(verify(identity.public_key(), message, &signature)?);

    // A different message does not verify against that signature.
    assert!(!verify(identity.public_key(), b"something else", &signature)?);

    println!("public key: {} bytes", identity.public_key().len());
    Ok(())
}
