//! Generating an identity, signing with it, and verifying signatures.
//!
//! This is the ergonomic surface, and it is deliberately thin. Every
//! cryptographic operation happens inside the embedded component: this module
//! sources entropy, converts types, and calls across. If you find yourself
//! adding an algorithm here, it belongs in `aethel-core` instead. That is the
//! charter's L1 rule, and it is what makes "one artifact, embedded by every
//! language" true rather than aspirational.
//!
//! # Where the secret lives
//!
//! Nowhere in this crate. [`Identity`] holds a resource handle into the
//! component instance, not key material. The ML-DSA-65 signing key and the PLP
//! master seed are derived inside the component from entropy this crate
//! supplies, and the only key material that ever crosses back is the public key.
//!
//! That is worth stating precisely, because it is stronger than "we are careful
//! not to log the secret": there is no secret in this address space to log. The
//! entropy passed *in* is not the key either, it is stretched and domain
//! separated inside the component, and this crate zeroizes its copy regardless.
//!
//! # One instance per identity
//!
//! Each [`Identity`] owns its own component instance. That costs memory but
//! keeps the model obvious: dropping an identity drops the instance holding its
//! secret, and two identities cannot observe each other.

use zeroize::Zeroize;

use crate::component::{self, aethel::core::types::IdentityError, AethelCore, LoadError};
use wasmtime::component::ResourceAny;
use wasmtime::Store;

/// Minimum entropy accepted by the component's key derivation.
pub const MIN_ENTROPY_BYTES: usize = 32;

/// Anything that can go wrong generating or using an identity.
#[derive(Debug)]
pub enum Error {
    /// The embedded component could not be loaded. Includes the integrity
    /// failure case, where the artifact is not the one the package declares.
    Load(LoadError),
    /// The component rejected the call, with its declared reason.
    Component(IdentityError),
    /// A call into the component trapped or otherwise failed at the host
    /// boundary. Distinct from `Component`, which is the operation answering.
    Host(wasmtime::Error),
    /// The operating system would not supply entropy.
    Entropy(getrandom::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Load(e) => write!(f, "{e}"),
            Error::Component(e) => write!(f, "aethel-core rejected the call: {e:?}"),
            Error::Host(e) => write!(f, "the call into the component failed: {e}"),
            Error::Entropy(e) => write!(f, "could not source entropy: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<LoadError> for Error {
    fn from(e: LoadError) -> Self {
        Error::Load(e)
    }
}

impl From<IdentityError> for Error {
    fn from(e: IdentityError) -> Self {
        Error::Component(e)
    }
}

impl From<wasmtime::Error> for Error {
    fn from(e: wasmtime::Error) -> Self {
        Error::Host(e)
    }
}

/// A post-quantum identity.
///
/// Created by [`Identity::generate`]. The secret key material lives inside the
/// component instance this owns, never in this struct.
pub struct Identity {
    store: Store<()>,
    bindings: AethelCore,
    handle: ResourceAny,
    public_key: Vec<u8>,
}

/// Prints the public key fingerprint and nothing else.
///
/// There is no secret in this struct to redact, but formatting it should still
/// be explicit about that rather than deriving `Debug` and letting a future
/// field decide the question by accident.
impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let fingerprint: String = self
            .public_key
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect();
        f.debug_struct("Identity")
            .field("public_key", &format_args!("{fingerprint}..."))
            .field("secret", &format_args!("<held in the component, never here>"))
            .finish()
    }
}

impl Identity {
    /// Generate a new identity, sourcing entropy from the operating system.
    ///
    /// The entropy is passed to the component, which derives the signing key and
    /// the PLP master seed from it. Reading the OS CSPRNG is not a cryptographic
    /// operation this crate implements, and it has to happen here: the component
    /// has no WASI and therefore no ambient randomness of its own.
    pub fn generate() -> Result<Self, Error> {
        let mut entropy = [0u8; MIN_ENTROPY_BYTES];
        getrandom::getrandom(&mut entropy).map_err(Error::Entropy)?;
        let identity = Self::from_entropy(&entropy);
        // The component has already stretched this into key material. Wipe our
        // copy either way: it is the input that determines the identity.
        entropy.zeroize();
        identity
    }

    /// Generate an identity from caller-supplied entropy.
    ///
    /// Deterministic: the same entropy always produces the same identity. That
    /// makes tests reproducible, and it makes this the wrong function to reach
    /// for in production unless you are certain about where the bytes came from.
    /// Requires at least [`MIN_ENTROPY_BYTES`].
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, Error> {
        let (mut store, bindings) = component::load()?;

        let handle = bindings
            .aethel_core_identity()
            .master_identity()
            .call_generate(&mut store, entropy)??;

        let public_key = bindings
            .aethel_core_identity()
            .master_identity()
            .call_public_key(&mut store, handle)?;

        Ok(Self { store, bindings, handle, public_key })
    }

    /// The ML-DSA-65 public key. Safe to publish.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Sign a message.
    ///
    /// Deterministic, per FIPS 204: signing the same message twice produces the
    /// same signature.
    pub fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let signature = self
            .bindings
            .aethel_core_identity()
            .master_identity()
            .call_sign(&mut self.store, self.handle, message)??;
        Ok(signature)
    }
}

/// Verify a signature against a public key.
///
/// A free function, because verification needs only public material. Returns
/// `Ok(false)` for a well-formed signature that does not verify, and an error
/// only when the input could not be processed at all. Those are different
/// answers and collapsing them is how "invalid signature" and "malformed input"
/// become indistinguishable.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, Error> {
    let (mut store, bindings) = component::load()?;
    let verified = bindings
        .aethel_core_identity()
        .call_verify_signature(&mut store, public_key, message, signature)??;
    Ok(verified)
}
