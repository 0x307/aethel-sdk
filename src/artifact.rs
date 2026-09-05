//! The embedded `aethel:core` component, and the claim the package makes about it.
//!
//! This crate ships a compiled WebAssembly component inside a source package.
//! That is only defensible if anyone can rebuild it and get the same bytes, so
//! three things are checked in together and are meant to be read as one unit:
//!
//! - `core/aethel_core.component.wasm` — the artifact, embedded at compile time
//! - `core/component.sha256` — the hash the package *claims* those bytes have
//! - `core/pin.toml` — the aethel-core revision and toolchain that produced them
//!
//! `scripts/sync-core.sh` regenerates all three from the pinned revision. None
//! of them is edited by hand.
//!
//! # No crypto lives here
//!
//! Nothing in this crate implements a cryptographic operation. The SHA-256 below
//! is a digest over the embedded file, used to detect a substituted artifact. The
//! identity primitives are entirely inside the component, which is the L1
//! boundary the initiative is built on: one artifact, embedded by every language.
//!
//! # The hash is platform-specific
//!
//! rustc embeds platform paths and links a different std, so the same aethel-core
//! revision built on Windows or macOS produces different bytes. The canonical
//! platform is recorded in `core/pin.toml`, and `scripts/sync-core.sh` reproduces
//! it in a container so the canonical bytes can be built from any host.

use sha2::{Digest, Sha256};

/// The compiled `aethel:core` component, embedded in the binary.
///
/// This is the artifact, not a path to one and not something fetched at install
/// time. A consumer of this crate has the component in memory the moment the
/// crate is linked.
pub const COMPONENT: &[u8] = include_bytes!("../core/aethel_core.component.wasm");

/// Raw contents of `core/component.sha256`, in `sha256sum` format.
const DECLARED: &str = include_str!("../core/component.sha256");

/// Raw contents of `core/pin.toml`.
const PIN: &str = include_str!("../core/pin.toml");

/// The SHA-256 the package declares for [`COMPONENT`], as lowercase hex.
pub fn declared_sha256() -> &'static str {
    DECLARED
        .split_whitespace()
        .next()
        .expect("core/component.sha256 is empty; run scripts/sync-core.sh")
}

/// The aethel-core revision [`COMPONENT`] was built from.
pub fn core_revision() -> &'static str {
    pin_value("rev").expect("core/pin.toml has no rev; run scripts/sync-core.sh")
}

/// The canonical platform the declared hash was produced on.
pub fn canonical_platform() -> &'static str {
    pin_value("platform").unwrap_or("unknown")
}

fn pin_value(key: &str) -> Option<&'static str> {
    PIN.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| {
            let (name, rest) = line.split_once('=')?;
            if name.trim() != key {
                return None;
            }
            rest.trim().strip_prefix('"')?.split('"').next()
        })
}

/// An artifact whose bytes are not the bytes the package declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityError {
    /// The hash the package declares, from `core/component.sha256`.
    pub declared: String,
    /// The hash the bytes actually have.
    pub actual: String,
}

impl core::fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "aethel-core component hash mismatch: declared {}, got {}. \
             The embedded artifact is not the one this package claims to ship.",
            self.declared, self.actual
        )
    }
}

impl std::error::Error for IntegrityError {}

/// SHA-256 of `bytes`, as lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Check `bytes` against the hash the package declares.
///
/// Kept generic over the bytes rather than hard-wired to [`COMPONENT`] so that
/// the check itself can be tested against an artifact that is known to be wrong.
/// A check that has never been shown to fail is not known to work.
pub fn verify(bytes: &[u8]) -> Result<(), IntegrityError> {
    let declared = declared_sha256();
    let actual = sha256_hex(bytes);
    if actual == declared {
        Ok(())
    } else {
        Err(IntegrityError {
            declared: declared.to_string(),
            actual,
        })
    }
}

/// Check the embedded artifact against the hash the package declares.
pub fn verify_embedded() -> Result<(), IntegrityError> {
    verify(COMPONENT)
}
