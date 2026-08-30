//! `aethel-sdk`: a Rust surface over aethel-core's post-quantum identity primitives.
//!
//! # What runs today
//!
//! The compiled `aethel:core` component is embedded in this crate, its integrity
//! is checked against a hash the package declares ([`artifact`]), and it loads
//! and executes in an embedded runtime ([`component`]).
//!
//! That is the whole of what this crate does today. It is the L1 boundary from
//! the initiative charter: one WebAssembly artifact, embedded by every language,
//! carrying every cryptographic operation. Nothing in this crate implements
//! crypto, and nothing in this crate is allowed to.
//!
//! # What is designed but not built
//!
//! The ergonomic surface. Generating an identity, signing and verifying,
//! projecting into a context, selectively disclosing attributes, and recovering
//! through threshold shares are all designed and none of them is callable from
//! this crate yet. `ROADMAP.md` has the sequence.
//!
//! One caveat that outlives this crate's own progress: **SAAP selective
//! disclosure does not work in the embedded component.** `saap-verify` denies
//! unconditionally, because the corrected verifier needs a public key that the
//! current WIT signature has no parameter to carry. This is deliberate and
//! documented upstream. Do not read a future `disclose` method as evidence that
//! it started working.

pub mod artifact;

#[cfg(not(target_arch = "wasm32"))]
pub mod component;

#[cfg(not(target_arch = "wasm32"))]
pub mod identity;

#[cfg(not(target_arch = "wasm32"))]
pub use identity::{verify, Identity};
