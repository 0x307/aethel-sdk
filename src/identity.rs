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

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::component::exports::aethel::core::identity::EphemeralProjection;
use crate::component::{
    self, aethel::core::types::IdentityError, exports::aethel::core::secret_sharing::HtssShare,
    AethelCore, LoadError,
};
use wasmtime::component::ResourceAny;
use wasmtime::Store;

/// Minimum entropy accepted by the component's key derivation.
pub const MIN_ENTROPY_BYTES: usize = 32;
/// Minimum bytes of secret randomness required for one PLP projection.
pub const MIN_PROJECTION_RANDOMNESS_BYTES: usize = 32;

/// The multicodec code for an ML-DSA-65 public key, registered upstream.
///
/// Named rather than inlined because the byte sequence it encodes is what a
/// decoder keys on: get it wrong and the output is still a well-formed
/// base58btc string, just one that describes a different algorithm.
pub const ML_DSA_65_MULTICODEC: u32 = 0x1211;

/// Encode `public_key` as a W3C Multikey. See
/// [`Identity::public_key_multibase`].
fn multikey(public_key: &[u8]) -> String {
    let mut prefixed = unsigned_varint(ML_DSA_65_MULTICODEC);
    prefixed.extend_from_slice(public_key);
    format!("z{}", bs58::encode(&prefixed).into_string())
}

/// Unsigned LEB128, the multiformats varint. Seven bits of payload per byte,
/// low group first, high bit set on every byte but the last.
fn unsigned_varint(mut value: u32) -> Vec<u8> {
    let mut out = Vec::new();
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
    out
}

/// A public, context-bound PLP projection.
///
/// A projection contains only its padded context tag, public per-projection
/// salt, and public projection coefficients. The identity's PLP master seed
/// stays inside the component and is not represented here.
///
/// Under aethel-core's stated M-LWE security assumptions, the master secret is
/// not derivable from any number of projections made with fresh, secret
/// randomness. That randomness derives the public salt, which in turn derives
/// this projection's context matrix; fresh salts keep same-context projections
/// from sharing the matrix needed for the historical averaging attack. This is
/// a cryptographic property of aethel-core's construction, not one SDK unit
/// tests can prove.
pub struct Projection {
    inner: EphemeralProjection,
}

impl Projection {
    fn from_component(inner: EphemeralProjection) -> Self {
        Self { inner }
    }

    /// The core's padded 32-byte context tag (τ).
    pub fn tau(&self) -> &[u8] {
        &self.inner.tau
    }

    /// The public 32-byte salt that selects this projection's context matrix.
    pub fn salt(&self) -> &[u8] {
        &self.inner.salt
    }

    /// The public projection coefficients (b_τ).
    pub fn public_b(&self) -> &[u32] {
        &self.inner.public_b
    }

    /// Canonical core projection encoding: padded τ, salt, then `public_b`
    /// coefficients as little-endian `u32`s.
    ///
    /// This encoding intentionally excludes the context matrix: core derives
    /// that matrix from τ and salt during verification.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64 + self.inner.public_b.len() * 4);
        bytes.extend_from_slice(&self.inner.tau);
        bytes.extend_from_slice(&self.inner.salt);
        for coefficient in &self.inner.public_b {
            bytes.extend_from_slice(&coefficient.to_le_bytes());
        }
        bytes
    }
}

impl core::fmt::Debug for Projection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Projection")
            .field("tau", &self.tau())
            .field("salt", &self.salt())
            .field("public_b_coefficients", &self.public_b().len())
            .finish()
    }
}

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
    /// A disclosure named an attribute the credential does not carry.
    ///
    /// An error rather than a silent no-op: disclosing nothing when the caller
    /// asked to disclose something produces a perfectly valid proof of the
    /// wrong statement.
    UnknownAttribute(String),
    /// More attributes than a credential has slots for.
    TooManyAttributes(usize),
    /// Recovery material was not a complete, well-formed transport encoding.
    ///
    /// This does not reveal which sensitive share bytes were malformed.
    InvalidRecoveryMaterial(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Load(e) => write!(f, "{e}"),
            Error::Component(e) => write!(f, "aethel-core rejected the call: {e:?}"),
            Error::Host(e) => write!(f, "the call into the component failed: {e}"),
            Error::Entropy(e) => write!(f, "could not source entropy: {e}"),
            Error::UnknownAttribute(name) => write!(
                f,
                "this credential has no attribute named {name:?}, so it cannot be disclosed"
            ),
            Error::TooManyAttributes(n) => write!(
                f,
                "a credential carries at most 8 attributes, {n} were supplied"
            ),
            Error::InvalidRecoveryMaterial(reason) => {
                write!(f, "invalid recovery material: {reason}")
            }
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
    // pub(crate) so the disclosure module can drive the same component instance.
    // A credential handle is only meaningful inside the instance that issued it,
    // so there is one owner of the store and everything else borrows it.
    pub(crate) store: Store<()>,
    pub(crate) bindings: AethelCore,
    pub(crate) handle: ResourceAny,
    public_key: Vec<u8>,
}

const HTSS_TOTAL_SHARES: usize = 5;

/// One authenticated HTSS recovery share.
///
/// The legacy transport encoding carries a claimed 32-byte Merkle root so a
/// share can be transported independently. That root is untrusted metadata:
/// [`Identity::recover_from_shares`] authenticates shares only against its
/// separate `expected_root` argument. This remains recovery-sensitive material;
/// transport encryption and access control are still required.
pub struct RecoveryShare {
    index: u8,
    value: Vec<u8>,
    path: Vec<u8>,
    merkle_root: [u8; 32],
}

impl RecoveryShare {
    /// Encode this share and its claimed Merkle root for transport or storage.
    ///
    /// The bytes contain recovery-sensitive material. They are portable, not
    /// safe to publish.
    pub fn to_bytes(&self) -> Vec<u8> {
        RecoveryShareSet {
            shares: vec![self.clone()],
            merkle_root: self.merkle_root,
        }
        .to_bytes()
    }

    /// Decode one share previously produced by [`RecoveryShare::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut set = RecoveryShareSet::from_bytes(bytes)?;
        if set.shares.len() != 1 {
            return Err(Error::InvalidRecoveryMaterial(
                "a single-share encoding must contain exactly one share",
            ));
        }
        Ok(set.shares.remove(0))
    }
}

impl Clone for RecoveryShare {
    fn clone(&self) -> Self {
        Self {
            index: self.index,
            value: self.value.clone(),
            path: self.path.clone(),
            merkle_root: self.merkle_root,
        }
    }
}

impl core::fmt::Debug for RecoveryShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoveryShare")
            .field("index", &self.index)
            .field("value", &"<redacted>")
            .field("path", &"<redacted>")
            .field("merkle_root", &"<redacted>")
            .finish()
    }
}

/// A 3-of-5 HTSS recovery set for an identity.
///
/// The legacy encoding keeps shares and their Merkle root together for
/// compatibility. Its root is informational and untrusted at recovery time:
/// retain [`Self::merkle_root`] separately in trusted storage before accepting
/// serialized shares. A store that can replace both can substitute an entire
/// recovery set.
pub struct RecoveryShareSet {
    shares: Vec<RecoveryShare>,
    merkle_root: [u8; 32],
}

impl RecoveryShareSet {
    /// The five authenticated shares. Distribute each share separately.
    pub fn shares(&self) -> &[RecoveryShare] {
        &self.shares
    }

    /// The 32-byte Merkle root emitted by the component for this share set.
    ///
    /// Save this separately in a trusted location. A root decoded from recovery
    /// material is an untrusted claim, not a recovery authority.
    pub fn merkle_root(&self) -> &[u8; 32] {
        &self.merkle_root
    }

    /// Encode all shares and a claimed Merkle root in the legacy versioned
    /// binary format suitable for transport or storage.
    ///
    /// These bytes are recovery-sensitive material and must be protected like
    /// the identity itself. Transport-safe does not mean safe to publish.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            4 + 1
                + 1
                + 32
                + self
                    .shares
                    .iter()
                    .map(|share| 1 + 4 + share.value.len() + 4 + share.path.len())
                    .sum::<usize>(),
        );
        bytes.extend_from_slice(b"ATHR");
        bytes.push(1);
        bytes.push(self.shares.len() as u8);
        bytes.extend_from_slice(&self.merkle_root);
        for share in &self.shares {
            bytes.push(share.index);
            write_recovery_bytes(&mut bytes, &share.value);
            write_recovery_bytes(&mut bytes, &share.path);
        }
        bytes
    }

    /// Decode recovery material produced by [`RecoveryShareSet::to_bytes`].
    ///
    /// The decoded root is an untrusted claim. Supply a separately retained
    /// trusted root to [`Identity::recover_from_shares`] for authentication.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        const HEADER_BYTES: usize = 4 + 1 + 1 + 32;
        if bytes.len() < HEADER_BYTES || &bytes[..4] != b"ATHR" || bytes[4] != 1 {
            return Err(Error::InvalidRecoveryMaterial("unknown encoding"));
        }
        let count = bytes[5] as usize;
        if count == 0 || count > 5 {
            return Err(Error::InvalidRecoveryMaterial("invalid share count"));
        }
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&bytes[6..HEADER_BYTES]);
        let mut offset = HEADER_BYTES;
        let mut shares = Vec::with_capacity(count);
        for _ in 0..count {
            let index = *bytes
                .get(offset)
                .ok_or(Error::InvalidRecoveryMaterial("truncated share index"))?;
            offset += 1;
            let value = read_recovery_bytes(bytes, &mut offset)?;
            let path = read_recovery_bytes(bytes, &mut offset)?;
            shares.push(RecoveryShare {
                index,
                value,
                path,
                merkle_root,
            });
        }
        if offset != bytes.len() {
            return Err(Error::InvalidRecoveryMaterial("trailing bytes"));
        }
        Ok(Self {
            shares,
            merkle_root,
        })
    }
}

impl core::fmt::Debug for RecoveryShareSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoveryShareSet")
            .field("share_count", &self.shares.len())
            .field("shares", &"<redacted>")
            .field("merkle_root", &"<redacted>")
            .finish()
    }
}

fn write_recovery_bytes(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_le_bytes());
    output.extend_from_slice(value);
}

fn read_recovery_bytes(input: &[u8], offset: &mut usize) -> Result<Vec<u8>, Error> {
    let length_bytes = input
        .get(*offset..*offset + 4)
        .ok_or(Error::InvalidRecoveryMaterial("truncated length"))?;
    let length = u32::from_le_bytes(
        length_bytes
            .try_into()
            .map_err(|_| Error::InvalidRecoveryMaterial("invalid length"))?,
    ) as usize;
    *offset += 4;
    let end = offset
        .checked_add(length)
        .ok_or(Error::InvalidRecoveryMaterial("invalid share length"))?;
    let value = input
        .get(*offset..end)
        .ok_or(Error::InvalidRecoveryMaterial("truncated share data"))?
        .to_vec();
    *offset = end;
    Ok(value)
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
            .field(
                "secret",
                &format_args!("<held in the component, never here>"),
            )
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

        Ok(Self {
            store,
            bindings,
            handle,
            public_key,
        })
    }

    /// The ML-DSA-65 public key. Safe to publish.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// The public key as a [W3C Multikey][mk]: base58btc, `z`-prefixed, over
    /// the multicodec code for ML-DSA-65 followed by the key bytes.
    ///
    /// This is the interoperable form. `public_key()` returns raw bytes, which
    /// say nothing about which algorithm produced them; a Multikey names the
    /// algorithm in-band, so a verifier that has never seen this SDK can decode
    /// it and know what it is holding.
    ///
    /// The code is `0x1211`, which is registered upstream in the
    /// [multicodec table][mc] for ML-DSA-65, so nothing here is private-use.
    ///
    /// [mk]: https://www.w3.org/TR/controller-document/#multikey
    /// [mc]: https://github.com/multiformats/multicodec
    pub fn public_key_multibase(&self) -> String {
        multikey(&self.public_key)
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

    /// Split this identity's canonical sealed representation into authenticated
    /// 3-of-5 recovery shares.
    ///
    /// The current embedded aethel-core HTSS policy is fixed at 3-of-5. The
    /// raw signing key and PLP master seed never leave the component; instead,
    /// HTSS protects the sealed identity blob that [`Identity::open_sealed`]
    /// canonically imports. `sealing_key` must meet the same requirements as
    /// [`Identity::export_sealed`], and is required again during recovery.
    pub fn split_for_recovery(&mut self, sealing_key: &[u8]) -> Result<RecoveryShareSet, Error> {
        let mut sealed = self.export_sealed(sealing_key)?;
        let split = {
            let sharing = self.bindings.aethel_core_secret_sharing();
            sharing.call_htss_split(&mut self.store, &sealed)?
        };
        sealed.zeroize();
        let (shares, merkle_root) = split?;
        let merkle_root: [u8; 32] = merkle_root
            .try_into()
            .map_err(|_| Error::InvalidRecoveryMaterial("component returned non-32-byte root"))?;
        let shares = shares
            .into_iter()
            .map(|share| RecoveryShare {
                index: share.index,
                value: share.value,
                path: share.path,
                merkle_root,
            })
            .collect();
        Ok(RecoveryShareSet {
            shares,
            merkle_root,
        })
    }

    /// Recover an identity from any three valid shares of one recovery set.
    ///
    /// `expected_root` is trusted authentication metadata retained separately
    /// from the untrusted shares, such as in a keychain or an authenticated
    /// recovery record. It must not be sourced from the share bundle supplied
    /// to this method. The component verifies every inclusion path against it
    /// before reconstructing the sealed identity blob, which is then restored
    /// through the canonical [`Identity::open_sealed`] path.
    pub fn recover_from_shares(
        shares: &[RecoveryShare],
        expected_root: &[u8; 32],
        sealing_key: &[u8],
    ) -> Result<Self, Error> {
        if shares.is_empty() {
            return Err(Error::InvalidRecoveryMaterial("no shares supplied"));
        }
        if shares.len() > HTSS_TOTAL_SHARES {
            return Err(Error::Component(IdentityError::InvalidShareSet));
        }
        if shares
            .iter()
            .any(|share| !bool::from(share.merkle_root.ct_eq(expected_root)))
        {
            return Err(Error::InvalidRecoveryMaterial(
                "shares belong to different recovery sets",
            ));
        }
        let component_shares: Vec<HtssShare> = shares
            .iter()
            .map(|share| HtssShare {
                index: share.index,
                value: share.value.clone(),
                path: share.path.clone(),
            })
            .collect();
        let (mut store, bindings) = component::load()?;
        let mut sealed = bindings
            .aethel_core_secret_sharing()
            .call_htss_reconstruct(&mut store, &component_shares, expected_root)??;
        let identity = Self::open_sealed(&sealed, sealing_key);
        sealed.zeroize();
        identity
    }

    /// Project this identity into `context` with fresh OS-supplied randomness.
    ///
    /// This is the preferred API. Each call samples new secret randomness, so
    /// even two projections at the same context have different salts and
    /// independent context matrices. No master secret leaves the component.
    pub fn project_at(&mut self, context: &[u8]) -> Result<Projection, Error> {
        let mut randomness = [0u8; MIN_PROJECTION_RANDOMNESS_BYTES];
        getrandom::getrandom(&mut randomness).map_err(Error::Entropy)?;
        let projection = self.project_at_with_randomness(context, &randomness);
        randomness.zeroize();
        projection
    }

    /// Project this identity into `context` using caller-provided randomness.
    ///
    /// `randomness` must contain at least
    /// [`MIN_PROJECTION_RANDOMNESS_BYTES`] bytes. In normal use it must be
    /// freshly sampled secret entropy for every projection; derive it
    /// neither from the context nor from identity data. Core derives both the
    /// public salt and the projection error from it.
    ///
    /// Reusing the same randomness at the same context reproduces the same
    /// projection byte-for-byte. That reuse creates no new independent sample,
    /// but using fresh randomness through [`Identity::project_at`] is the safe
    /// default and prevents the shared-matrix averaging attack this construction
    /// is designed to avoid.
    ///
    /// Under aethel-core's stated M-LWE security assumptions, fresh, secret
    /// randomness makes the master secret non-derivable from any number of
    /// projections. The salt it derives gives each projection its own context
    /// matrix, including at a repeated context, so the historical averaging
    /// attack has no shared matrix to use. This is a property of the underlying
    /// cryptographic construction, not a claim SDK unit tests can establish.
    pub fn project_at_with_randomness(
        &mut self,
        context: &[u8],
        randomness: &[u8],
    ) -> Result<Projection, Error> {
        let projection = self
            .bindings
            .aethel_core_identity()
            .master_identity()
            .call_project_at_context(&mut self.store, self.handle, context, randomness)??;
        Ok(Projection::from_component(projection))
    }
}

/// Minimum sealing key length. See [`Identity::export_sealed`].
pub const MIN_SEAL_KEY_BYTES: usize = 32;

impl Identity {
    /// Seal this identity so it can be stored and loaded again.
    ///
    /// # This takes a key, not a password
    ///
    /// `key` must be at least [`MIN_SEAL_KEY_BYTES`] of **high-entropy** key
    /// material: a key from an OS keychain, an HSM, or a random value you store.
    /// The component stretches it with SHAKE-256, which is fast by design.
    ///
    /// **Do not pass a human-chosen password.** A password needs a deliberately
    /// slow, memory-hard KDF (Argon2id or scrypt) to survive offline guessing,
    /// and neither this crate nor the component provides one. A password here
    /// produces a file that looks encrypted and falls to a wordlist. Run a real
    /// password KDF first and pass its output.
    ///
    /// # What you get
    ///
    /// A byte string safe to write to disk, and exactly as sensitive as the
    /// identity: whoever can open it holds the identity. Sealing is
    /// deterministic, so the same identity under the same key produces identical
    /// bytes and a stored file does not churn.
    pub fn export_sealed(&mut self, key: &[u8]) -> Result<Vec<u8>, Error> {
        let sealed = self
            .bindings
            .aethel_core_identity()
            .master_identity()
            .call_export_sealed(&mut self.store, self.handle, key)??;
        Ok(sealed)
    }

    /// Open a sealed identity.
    ///
    /// Returns an error for a blob that is malformed, truncated, of an unknown
    /// version, or sealed under a different key. Those are deliberately
    /// indistinguishable: a decryption failure must not tell an attacker which
    /// part they got wrong.
    pub fn open_sealed(sealed: &[u8], key: &[u8]) -> Result<Self, Error> {
        let (mut store, bindings) = component::load()?;

        let handle = bindings
            .aethel_core_identity()
            .master_identity()
            .call_import_sealed(&mut store, sealed, key)??;

        let public_key = bindings
            .aethel_core_identity()
            .master_identity()
            .call_public_key(&mut store, handle)?;

        Ok(Self {
            store,
            bindings,
            handle,
            public_key,
        })
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
