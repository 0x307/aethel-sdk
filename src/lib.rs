//! `aethel-sdk`: a Rust surface over aethel-core's post-quantum identity primitives.
//!
//! # What runs today
//!
//! The compiled `aethel:core` component is embedded in this crate, its integrity
//! is checked against a hash the package declares ([`artifact`]), and it loads
//! and executes in an embedded runtime ([`component`]).
//!
//! It is the L1 boundary from the initiative charter: one WebAssembly artifact,
//! embedded by every language, carrying every cryptographic operation. Nothing
//! in this crate implements crypto, and nothing in this crate is allowed to.
//!
//! On top of that, the following work end to end and are exercised by
//! `examples/quickstart.rs`, which runs in CI:
//!
//! - [`Identity::generate`] and [`Identity::from_entropy`], keys derived inside
//!   the component and never present in this process
//! - [`Identity::sign`] and [`verify`], ML-DSA-65
//! - [`Identity::export_sealed`] and [`Identity::open_sealed`], so an identity
//!   survives the process
//! - [`Identity::public_key_multibase`], the public key as a W3C Multikey
//! - [`Identity::project_at`], fresh, context-bound PLP projections
//! - [`Identity::issue_credential`], BDLOP issuance over named attributes
//! - [`Identity::present`] and [`verify_presentation`], SAAP selective
//!   disclosure: the verifier learns the disclosed attributes and nothing about
//!   the hidden ones
//!
//! # What is not on this surface
//!
//! Callable through the component but not wrapped here: standalone PLP proof
//! (`prove`, `plp-verify`) and HTSS threshold split and reconstruct.
//! `ROADMAP.md` has the sequence.
//!
//! # What is not built anywhere
//!
//! - **Predicate proofs over hidden values.** "Age over 21 without revealing
//!   age" does not work. Selective disclosure reveals the exact value of a
//!   disclosed attribute; it cannot prove a bound on an undisclosed one. This is
//!   RFC 5.6 relation 3, deliberately deferred, with three `identity-error`
//!   variants reserved upstream for it.
//! - **Revocation and key rotation.** There is no revocation list, no expiry, no
//!   epoch on a credential or presentation, and no way to bind an identity to a
//!   successor.
//! - **Issuance orchestration.** `issue_credential` is one local call and needs
//!   the issuer seed in this process. There is no two-party issuer/holder
//!   protocol.
//!
//! # A correction
//!
//! Earlier versions of this comment said the ergonomic surface was "designed and
//! none of them is callable from this crate yet", and that "SAAP selective
//! disclosure does not work in the embedded component" because `saap-verify`
//! denied unconditionally. Both were true once and neither is true now. The
//! quickstart in this repository exercises exactly those paths and passes.

pub mod artifact;

#[cfg(not(target_arch = "wasm32"))]
pub mod component;

#[cfg(not(target_arch = "wasm32"))]
pub mod identity;

#[cfg(not(target_arch = "wasm32"))]
pub mod disclosure;

#[cfg(not(target_arch = "wasm32"))]
pub mod verifier;

#[cfg(not(target_arch = "wasm32"))]
pub use disclosure::{verify_presentation, Credential, Presentation};

#[cfg(not(target_arch = "wasm32"))]
pub use identity::{verify, Identity, Projection};

#[cfg(not(target_arch = "wasm32"))]
pub use verifier::Verifier;
