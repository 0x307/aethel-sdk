//! Owning the compiled component for the lifetime of a verifier.
//!
//! [`verify`](crate::verify) and [`verify_presentation`](crate::verify_presentation)
//! already share one process-wide compile through [`component::shared`], so
//! [`Verifier`] is not here to make verification cheaper: it makes the timing
//! of that cost a choice. The free functions pay the 230 ms first-use compile
//! whenever the first verification happens to land. `Verifier::new` pays it at
//! construction, so a caller can pay it at startup instead of on a request.
//!
//! Mirrors [`Identity`](crate::Identity), which owns its `Store` for its whole
//! life for the same reason: a long-lived thing should own the resource it
//! keeps using rather than reacquiring it every call.
//!
//! # Which one to reach for
//!
//! - The free functions are the convenient path: a script, a test, a one-off
//!   verification. `component::shared()` amortises the compile for you and
//!   there is nothing to hold.
//! - `Verifier` is the request-path shape. Anything verifying more than
//!   occasionally should hold one, constructed once, so the 230 ms compile is
//!   paid at startup rather than on a caller's first request. SAGP, a gateway
//!   that verifies on the request path, holds one `Verifier` built at startup
//!   for exactly this reason.
//!
//! Per-verification cost is identical either way: both paths instantiate the
//! same compiled [`component::Runtime`] and run the same call into the
//! component.

use crate::component;
use crate::disclosure::Presentation;
use crate::identity::Error;

/// A verifier that owns its compiled runtime.
///
/// Construct once, hold it for as long as verification is needed, and call
/// [`Verifier::verify`] or [`Verifier::verify_presentation`] as many times as
/// you like. Each call instantiates a fresh `Store` against the runtime this
/// struct already compiled; nothing about that per-call step differs from
/// what the free functions do.
pub struct Verifier {
    runtime: component::Runtime,
}

impl Verifier {
    /// Compile the embedded component and hold it.
    ///
    /// ```
    /// use aethel_sdk::{Identity, Verifier};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // Once, at startup: this is where the ~230 ms compile is paid.
    /// let verifier = Verifier::new()?;
    ///
    /// let mut identity = Identity::generate()?;
    /// let signature = identity.sign(b"a message")?;
    ///
    /// // Per request, as often as you like. Same contract as the free
    /// // function: Ok(false) is "did not verify", Err is "could not check".
    /// assert!(verifier.verify(identity.public_key(), b"a message", &signature)?);
    /// assert!(!verifier.verify(identity.public_key(), b"other", &signature)?);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// This is where the 230 ms first-use compile happens for this verifier.
    /// Call it once, at startup, rather than lazily on the first request.
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            runtime: component::Runtime::new()?,
        })
    }

    /// Verify a signature against a public key.
    ///
    /// Same contract as the free function [`crate::verify`]: `Ok(false)` for a
    /// well-formed signature that does not verify, and an error only when the
    /// input could not be processed at all.
    pub fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Error> {
        let (mut store, bindings) = self.runtime.instantiate()?;
        let verified = bindings
            .aethel_core_identity()
            .call_verify_signature(&mut store, public_key, message, signature)??;
        Ok(verified)
    }

    /// Verify a presentation.
    ///
    /// Same contract as the free function [`crate::verify_presentation`]:
    /// `expected_context` must match the context the presentation was made
    /// for, and the result is `Ok(false)` for a well-formed presentation that
    /// does not verify.
    /// Takes [`crate::IssuerPublicParameters`], not the issuer seed: a verifier
    /// needs no secret. This is the shape a request-path verifier wants, since
    /// the parameters are derived once and held.
    pub fn verify_presentation(
        &self,
        issuer: &crate::disclosure::IssuerPublicParameters,
        presentation: &Presentation,
        expected_context: &[u8],
    ) -> Result<bool, Error> {
        let (mut store, bindings) = self.runtime.instantiate()?;
        let resource = bindings
            .aethel_core_identity()
            .issuer_public_parameters()
            .call_deserialize(&mut store, issuer.as_bytes())??;
        let verified = bindings
            .aethel_core_identity()
            .call_saap_verify_presentation(
                &mut store,
                resource,
                &presentation.inner,
                presentation.projection.as_component(),
                expected_context,
            )??;
        Ok(verified)
    }
}
