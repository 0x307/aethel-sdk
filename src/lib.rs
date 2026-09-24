//! `aethel-sdk`: a Rust surface over aethel-core's post-quantum identity primitives.
//!
//! ```
//! use aethel_sdk::{verify, Identity};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // The signing key is derived inside the embedded component from OS entropy
//! // and never enters this process.
//! let mut identity = Identity::generate()?;
//!
//! let message = b"the message that was actually signed";
//! let signature = identity.sign(message)?;
//!
//! // Ok(false) is "this signature does not verify". An Err means the input
//! // could not be processed at all. They are different answers: treating an
//! // error as "invalid" is what makes malformed input look like a failed check.
//! assert!(verify(identity.public_key(), message, &signature)?);
//! assert!(!verify(identity.public_key(), b"something else", &signature)?);
//!
//! // The interoperable form of the public key, for a DID document.
//! println!("{}", identity.public_key_multibase());
//! # Ok(())
//! # }
//! ```
//!
//! # Read this before the feature list
//!
//! This crate is **identity-only** by default: post-quantum signing, sealed
//! persistence, threshold recovery, and context-bound projections that are
//! unlinkable across contexts.
//!
//! **Credentials are off by default, behind the `experimental-credentials`
//! feature, and should not be relied on.** `aethel-core`'s `SECURITY.md`
//! records that the credential commitment does not hide what it commits to: a
//! presentation reveals every attribute it carries, disclosed or not, and two
//! presentations of one credential are linkable. Disclosed attributes are also
//! self-asserted, and a presentation cannot leave the process that made it.
//! Fixing that is a separate line of work, and until it lands the feature
//! exists so the work can continue in public, not for production use.
//!
//! Fuller worked examples are in `examples/` in the published package:
//! `quickstart.rs` (generate, sign, verify, persist, project) and
//! `projection.rs`. Run them with `cargo run --example quickstart` from a
//! checkout of the repository.
//!
//! # Before you add this crate
//!
//! This crate embeds a WebAssembly runtime. `cargo add aethel-sdk` pulls
//! wasmtime and Cranelift, roughly 120 crates, and a cold debug build takes
//! **several minutes** and produces a target directory over a gigabyte. That is
//! a one-time cost and it is not a hung build. Separately, the first
//! verification in a process pays a ~230 ms component compile; [`Verifier`]
//! exists so you can pay that at startup rather than on a caller's request.
//!
//! Host platforms only. wasmtime needs mmap and cannot itself be compiled to
//! `wasm32-unknown-unknown`, so this crate is scoped away from that target: it
//! will not build for a browser. The identity operations still all happen inside
//! WebAssembly; it is the runtime executing them that has to be native.
//!
//! # What you are responsible for
//!
//! Each of these can be got wrong while every call returns `Ok`:
//!
//! - **The sealing key is a single point of failure.** Lose it and the identity
//!   is gone, including from a full set of recovery shares. It must be
//!   high-entropy key material, never a password.
//! - **Keep the HTSS Merkle root apart from the shares.** A store that holds
//!   both can substitute an entire recovery set.
//! - **Projection randomness must be fresh and secret**, and never derived from
//!   the context. [`Identity::project_at`] does this for you.
//! - **Entropy quality is yours.** Generation is deterministic in its entropy,
//!   so weak entropy means a predictable identity, and the component cannot
//!   tell the difference.
//!
//! Out of scope, stated plainly: there has been **no third-party audit**; side
//! channels above L1 (wasmtime, your allocator, your application) are not
//! covered; physical and hardware attacks are not covered; and the security of
//! the constructions rests on `aethel-core`'s stated assumptions rather than on
//! anything this crate's tests can prove.
//!
//! [`SECURITY-MODEL.md`](https://github.com/0x307/aethel-sdk/blob/main/SECURITY-MODEL.md)
//! is the long form of this section, with how each claim is checked. It ships
//! in this package, so it is in the crate you installed even when you are
//! reading these docs online.
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
//! On top of that, the following work end to end, and every one of them is
//! exercised by the test suite and by `examples/quickstart.rs`, which runs in
//! CI:
//!
//! - [`Identity::generate`] and [`Identity::from_entropy`], keys derived inside
//!   the component and never present in this process
//! - [`Identity::sign`], and the free function [`identity::verify`] (there is
//!   no `Identity::verify`: verification needs only public material). ML-DSA-65
//! - [`Identity::export_sealed`] and [`Identity::open_sealed`], so an identity
//!   survives the process
//! - [`Identity::split_for_recovery`] and [`Identity::recover_from_shares`],
//!   authenticated 3-of-5 recovery over the canonical sealed identity
//! - [`Identity::public_key_multibase`], the public key as a W3C Multikey
//! - [`Identity::project_at`], fresh, context-bound PLP projections
//!
//! With the `experimental-credentials` feature, `Identity::issue_credential`,
//! `Identity::present` and `verify_presentation` are compiled in as well. They
//! run, and their tests pass in CI, but they are not safe to rely on: see the
//! top of this page.
//!
//! # What is not on this surface
//!
//! Callable through the component but not wrapped here: standalone PLP proof
//! (`prove`, `plp-verify`).
//! `ROADMAP.md` has the sequence.
//!
//! # What is not built anywhere
//!
//! - **Key rotation.** There is no way to bind an identity to a successor.
//! - **Everything credential-shaped beyond the experimental feature**: a
//!   commitment that hides, issuer-authenticated issuance, two-party issuance,
//!   revocation and expiry, and a way to prove a threshold over a hidden value.
//!   That is the credential line of work, and the expected `1.0` is identity
//!   plus credentials once it lands.
//!
//! # A correction
//!
//! Earlier versions of this comment said the ergonomic surface was "designed and
//! none of them is callable from this crate yet", and that "SAAP selective
//! disclosure does not work in the embedded component" because `saap-verify`
//! denied unconditionally. Both were true once and neither is true now. The
//! credential tests, run in CI with `--features experimental-credentials`,
//! exercise those paths and pass. Passing is not the same as sound, which is why
//! the feature is off by default.
//!
//! ---
//!
//! ## The 0x307 crate family
//!
//! `aethel-sdk` is one of six open-source crates from [0x307](https://0x307.com/crates), held to one
//! audit and stability standard.
//!
//! | Crate | Tier | What it does |
//! |---|---|---|
//! | [pqc-sig](https://crates.io/crates/pqc-sig) | Production | ML-DSA, SLH-DSA and FN-DSA signatures (FIPS 204/205/206) |
//! | [pqc-kem](https://crates.io/crates/pqc-kem) | Production | ML-KEM (FIPS 203), the X25519 + ML-KEM-768 hybrid, X-Wing, and sealed boxes |
//! | [aethel-core](https://crates.io/crates/aethel-core) | Production | Post-quantum anonymous identity: a separate identifier per context, context-bound ML-DSA signing |
//! | [aethel-sdk](https://crates.io/crates/aethel-sdk) (this crate) | Preview | The SDK over aethel-core, and the place to start |
//! | [aethel-vault](https://crates.io/crates/aethel-vault) | Preview | Agent-held wallet: policy-gated x402 / EIP-3009 signing with ML-DSA-65 spend records |
//! | [pqc-privacy](https://crates.io/crates/pqc-privacy) | Lab | Research bundle, kept off every identity and payment path |
//!
//! **Production** crates are thin, standards-bound libraries meant to be depended on today. **Preview** crates work and are published, with APIs still settling. **Lab** crates are research, never on an identity or payment path.
//!
//! **Runnable examples:** [0x307/examples](https://github.com/0x307/examples), one program per
//! crate, pinned to the published versions.
//!
//! **Audit status:** None of these crates has been independently audited, and none holds a CMVP / FIPS 140-3 validation. "FIPS 203/204/205/206" means the algorithms follow those standards, not that the code is certified. Known issues for this crate are in
//! [SECURITY.md](https://github.com/0x307/aethel-sdk/blob/main/SECURITY.md). Versioning and yanks:
//! [STABILITY.md](https://github.com/0x307/aethel-sdk/blob/main/STABILITY.md).
//!

pub mod artifact;

#[cfg(not(target_arch = "wasm32"))]
pub mod component;

#[cfg(not(target_arch = "wasm32"))]
pub mod identity;

/// Credentials. Off by default: see the crate docs for why.
#[cfg(all(not(target_arch = "wasm32"), feature = "experimental-credentials"))]
pub mod disclosure;

#[cfg(not(target_arch = "wasm32"))]
pub mod verifier;

#[cfg(all(not(target_arch = "wasm32"), feature = "experimental-credentials"))]
pub use disclosure::{
    verify_presentation, Credential, IssuerPublicParameters, Presentation, MAX_ATTRIBUTES,
    MIN_ISSUER_SEED_BYTES,
};

#[cfg(not(target_arch = "wasm32"))]
pub use identity::{verify, Identity, Projection, RecoveryShare, RecoveryShareSet};

#[cfg(not(target_arch = "wasm32"))]
pub use verifier::Verifier;

/// The credential API must not be reachable without its feature.
///
/// This module is compiled only when the feature is off, so its doctest runs in
/// exactly the configuration it checks. Pinned to E0432 (unresolved import), so
/// the doctest cannot pass by failing for some unrelated reason.
///
/// ```compile_fail,E0432
/// use aethel_sdk::Credential;
/// fn main() {}
/// ```
#[cfg(all(not(target_arch = "wasm32"), not(feature = "experimental-credentials")))]
mod credentials_are_gated {}
