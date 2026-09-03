//! Regenerate the cross-platform sealing fixture.
//!
//! `tests/persistence.rs` opens a sealed identity that was written on a
//! different machine and operating system from the one running the test. The
//! blob it opens is produced by this example and committed.
//!
//! Run it only when the seal format changes on purpose. The fixture was
//! regenerated for aethel-core 0.3.1: core commit ffdb8ba bumped the sealed
//! identity format from v1 to v2 and binds the identity type into the nonce
//! derivation and AEAD associated data, so the v1 fixture is deliberately
//! rejected as an unknown format.
//!
//! ```bash
//! cargo run --example seal_fixture
//! ```
//!
//! Sealing is deterministic, so re-running it on the same input reproduces the
//! same bytes. If this produces a different blob and you did not change the
//! format, something is wrong.

use aethel_sdk::Identity;

const FIXTURE_ENTROPY: &[u8] = b"aethel-sdk sealing fixture entrpy";
const FIXTURE_KEY: &[u8] = b"aethel-sdk sealing fixture key!!";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut identity = Identity::from_entropy(FIXTURE_ENTROPY)?;
    let sealed = identity.export_sealed(FIXTURE_KEY)?;

    std::fs::write("tests/fixtures/sealed-identity.bin", &sealed)?;

    let public_key_hex: String = identity
        .public_key()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    println!("wrote tests/fixtures/sealed-identity.bin ({} bytes)", sealed.len());
    println!("public key sha-prefix: {}", &public_key_hex[..64]);
    Ok(())
}
