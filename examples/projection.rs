//! Run with: cargo run --example projection

use aethel_sdk::Identity;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut identity = Identity::generate()?;
    let context = b"checkout-session";

    // The SDK samples fresh secret randomness for every call.
    let first = identity.project_at(context)?;
    let second = identity.project_at(context)?;

    // A projection carries public context-bound material, not the identity
    // master secret or the randomness used to produce it.
    println!("projection salt: {:02x?}", first.salt());
    println!("public coefficients: {}", first.public_b().len());
    println!(
        "fresh projections at one context differ: {}",
        first.to_bytes() != second.to_bytes()
    );

    Ok(())
}
