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
//! Two limits decide whether this crate is usable for what you have in mind,
//! and both are easy to miss because everything else here works.
//!
//! **Disclosed attributes are self-asserted.** A verified presentation proves
//! the disclosed values open under an issuer's public parameters. It does not
//! prove an issuer authorised them. Those parameters are published, and a
//! holder must hold them to present at all, so anyone can build a credential
//! over their own identity with attributes of their choosing and it will
//! verify. If you need "the issuer said this" rather than "the holder says this
//! and the shape is right", this is not that yet. See
//! [`verify_presentation`] and `docs/ISSUER-AUTHENTICATION.md` in `aethel-core`.
//!
//! **A presentation cannot leave the process that made it.** [`Presentation`]
//! has no serialised form, so holder and verifier are the same process today.
//!
//! Neither is a limit of the underlying cryptography. Both are places the
//! surface is unfinished, and they are stated here rather than on the type
//! pages because they determine whether the feature list below is worth
//! reading. What does work stands on its own: post-quantum signing, sealed
//! persistence, threshold recovery, and context-bound projections that are
//! unlinkable across contexts.
//!
//! Fuller worked examples are in `examples/` in the published package:
//! `quickstart.rs` (generate, sign, verify, persist, disclose), `projection.rs`,
//! and `bench_verify.rs`. Run them with `cargo run --example quickstart` from a
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
//! - **Disclosed attributes are self-asserted**, as above.
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
//! - [`Identity::issue_credential`], BDLOP issuance over named attributes
//! - [`Identity::present`] and [`verify_presentation`], SAAP selective
//!   disclosure: the verifier learns the disclosed attributes and nothing about
//!   the hidden ones
//!
//! # What is not on this surface
//!
//! Callable through the component but not wrapped here: standalone PLP proof
//! (`prove`, `plp-verify`).
//! `ROADMAP.md` has the sequence.
//!
//! # What is not built anywhere
//!
//! - **Issuer-authenticated issuance.** Verification no longer needs the issuer
//!   seed: [`verify_presentation`] takes [`IssuerPublicParameters`], so a
//!   verifier holds no secret and a compromised verifier cannot issue against
//!   anyone else's identity. What that does *not* buy is unforgeable attributes.
//!   The relation checks that a presentation opens under the issuer's
//!   parameters, not that an issuer authorised the values, and a holder must
//!   hold those parameters to present at all. So a holder can self-assert:
//!   construct a credential over their own identity with attributes of their
//!   choosing, and it verifies. Deployments where holders are not trusted to
//!   state their own attributes need the issuer's signature over the credential,
//!   which is not shipped. See `docs/ISSUER-AUTHENTICATION.md` in `aethel-core`.
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
pub use disclosure::{
    verify_presentation, Credential, IssuerPublicParameters, Presentation, MAX_ATTRIBUTES,
    MIN_ISSUER_SEED_BYTES,
};

#[cfg(not(target_arch = "wasm32"))]
pub use identity::{verify, Identity, Projection, RecoveryShare, RecoveryShareSet};

#[cfg(not(target_arch = "wasm32"))]
pub use verifier::Verifier;
