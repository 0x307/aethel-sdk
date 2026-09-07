//! Selective disclosure: prove you hold a credential, reveal only what you choose.
//!
//! # Attributes are named, never a bitmask
//!
//! A credential is issued over named attributes, and a presentation discloses
//! them by name. No bitmask appears anywhere in this API. That is deliberate:
//! the underlying world uses `flags`, and P3-01 called out raw bitmasks on the
//! wire specifically, but the reason it matters here is simpler. `disclose(&[
//! "tier"])` is a thing you can read and get right; `disclose(0b0000_1000)` is a
//! thing you get wrong once and never notice, because disclosing the wrong
//! attribute produces a perfectly valid proof.
//!
//! A name that is not in the credential's schema is an error, not a silent
//! no-op, for the same reason.
//!
//! # What this can and cannot prove
//!
//! It can prove: *"I hold a credential issued by X, one of whose attributes is
//! `tier = 3`"*, while revealing nothing about the other attributes. The
//! verifier learns the disclosed values, learns that the credential was issued
//! by the issuer they named, and learns that the holder is the identity whose
//! projection they are checking against.
//!
//! **It cannot prove a predicate over a hidden value.** "Age is at least 21,
//! without revealing the age" is the case people usually want, and it is not
//! implemented: relation 3 of the protocol is scoped out upstream. If you need
//! that today, you disclose the value.
//!
//! # No crypto here
//!
//! Every operation is a call into the embedded component. The commitment
//! randomness and attribute values live inside it, exactly as the identity's
//! secret does.

use alloc_shim::BTreeMap;

use crate::component::exports::aethel::core::identity::{
    DisclosureAttributes, SaapPresentation as WitPresentation,
};
use crate::identity::{Error, Identity};
use wasmtime::component::ResourceAny;

mod alloc_shim {
    pub use std::collections::BTreeMap;
}

/// Attribute slots a credential can carry.
pub const MAX_ATTRIBUTES: usize = 8;

/// Bytes of randomness the component requires for each of its inputs.
const RANDOMNESS_BYTES: usize = 32;

fn fresh_randomness() -> Result<[u8; RANDOMNESS_BYTES], Error> {
    let mut bytes = [0u8; RANDOMNESS_BYTES];
    getrandom::getrandom(&mut bytes).map_err(Error::Entropy)?;
    Ok(bytes)
}

/// A credential issued over an identity.
///
/// Holds a handle into the identity's component instance, not the credential
/// itself: the commitment randomness and attribute values stay inside the
/// component. Issue once, present many times.
pub struct Credential {
    pub(crate) handle: ResourceAny,
    /// All `MAX_ATTRIBUTES` slot names, padded. Internal: the padding exists so
    /// a disclose-by-name lookup cannot match an unused slot by accident, and
    /// it is not something a caller should ever see.
    pub(crate) schema: Vec<String>,
    /// How many of `schema` the caller actually issued over.
    pub(crate) issued: usize,
}

impl core::fmt::Debug for Credential {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Credential")
            .field("attributes", &self.attribute_names())
            .field(
                "values",
                &format_args!("<held in the component, never here>"),
            )
            .finish()
    }
}

impl Credential {
    /// The attribute names this credential was issued over, in slot order.
    /// Exactly the names that were issued over, in slot order.
    ///
    /// A credential always occupies `MAX_ATTRIBUTES` slots internally, and the
    /// unused ones carry placeholder names so that disclosing by name cannot
    /// match one by accident. Those placeholders are an implementation detail
    /// and are not returned here: issuing over three attributes gives three
    /// names back.
    pub fn attribute_names(&self) -> &[String] {
        &self.schema[..self.issued]
    }

    fn mask_for(&self, disclose: &[&str]) -> Result<DisclosureAttributes, Error> {
        let mut mask = DisclosureAttributes::empty();
        for name in disclose {
            // Only the issued prefix is searchable. The padding names exist so
            // that an unissued slot has *a* name and cannot be matched
            // positionally by accident; they were never meant to be a disclosable
            // surface of their own, and searching the full schema made them one.
            let slot = self.schema[..self.issued]
                .iter()
                .position(|n| n == name)
                .ok_or_else(|| Error::UnknownAttribute((*name).to_string()))?;
            mask |= slot_flag(slot);
        }
        Ok(mask)
    }
}

/// Map a slot index to its named flag.
///
/// Spelled out rather than computed as `1 << slot`, because the whole point of
/// the world declaring named flags instead of an integer is that the mapping is
/// explicit somewhere a reader can check it.
fn slot_flag(slot: usize) -> DisclosureAttributes {
    match slot {
        0 => DisclosureAttributes::ATTRIBUTE0,
        1 => DisclosureAttributes::ATTRIBUTE1,
        2 => DisclosureAttributes::ATTRIBUTE2,
        3 => DisclosureAttributes::ATTRIBUTE3,
        4 => DisclosureAttributes::ATTRIBUTE4,
        5 => DisclosureAttributes::ATTRIBUTE5,
        6 => DisclosureAttributes::ATTRIBUTE6,
        _ => DisclosureAttributes::ATTRIBUTE7,
    }
}

/// A presentation: what the holder sends and the verifier checks.
///
/// Carries the disclosed values, the blinded commitment and the responses.
/// Nothing in it is key material, and nothing in it identifies the credential
/// across presentations.
/// What the holder produces and the verifier checks.
///
/// **This type has no serialised form yet.** It is described as what the holder
/// sends, and in a deployment it would have to travel between processes, but
/// there is no `to_bytes`/`from_bytes` on it the way there is on
/// [`crate::Projection`], [`crate::RecoveryShare`] and
/// [`crate::RecoveryShareSet`]. Today a presentation can only be verified in the
/// process that produced it. Combined with the issuer-seed limitation in the
/// crate documentation, cross-party disclosure is not yet deployable; both are
/// tracked, and neither is a limitation of the underlying construction.
pub struct Presentation {
    pub(crate) inner: WitPresentation,
    pub(crate) projection: crate::identity::Projection,
    pub(crate) schema: Vec<String>,
}

impl core::fmt::Debug for Presentation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Presentation")
            .field("disclosed", &self.disclosed())
            .finish_non_exhaustive()
    }
}

impl Presentation {
    /// The attributes this presentation actually discloses, by name.
    ///
    /// Undisclosed attributes are absent from the map rather than present with
    /// a zero, because a zero is a value an attribute could legitimately have
    /// and "not disclosed" is not "disclosed as zero".
    pub fn disclosed(&self) -> BTreeMap<&str, u64> {
        let mut out = BTreeMap::new();
        for (slot, name) in self.schema.iter().enumerate() {
            if slot < MAX_ATTRIBUTES && self.inner.disclosed.contains(slot_flag(slot)) {
                out.insert(name.as_str(), self.inner.disclosed_values[slot]);
            }
        }
        out
    }

    /// The holder's projection at this context. Public, and what verification
    /// anchors on.
    /// Returns [`crate::Projection`], the same type [`crate::Identity::project_at`]
    /// produces, so its `tau()`, `salt()`, `public_b()` and `to_bytes()` are
    /// available here too. It used to return the raw component type, which no
    /// consuming crate could name: that type comes from `aethel-core`, which is
    /// a dev-dependency here, so the accessor was unusable from outside.
    pub fn projection(&self) -> &crate::identity::Projection {
        &self.projection
    }
}

impl Identity {
    /// Issue a credential over this identity.
    ///
    /// In production the issuer runs this, not the holder: `issuer_seed` is the
    /// issuer's secret, and whoever holds it can issue credentials that verify
    /// under the issuer's public parameters. It is exposed here because
    /// `aethel-core` has no issuer key management yet, and a caller should know
    /// that this is the whole of the issuer's authority.
    pub fn issue_credential(
        &mut self,
        issuer_seed: &[u8],
        attributes: &[(&str, u64)],
    ) -> Result<Credential, Error> {
        if attributes.len() > MAX_ATTRIBUTES {
            return Err(Error::TooManyAttributes(attributes.len()));
        }

        let issued = attributes.len();
        let mut names: Vec<String> = attributes.iter().map(|(n, _)| (*n).to_string()).collect();
        let mut values = [0u64; MAX_ATTRIBUTES];
        for (i, (_, v)) in attributes.iter().enumerate() {
            values[i] = *v;
        }
        // Unused slots still need a name, or a later disclose-by-name lookup
        // could match one of them by accident.
        while names.len() < MAX_ATTRIBUTES {
            names.push(format!("__unused_{}", names.len()));
        }

        let randomness = fresh_randomness()?;
        let handle = self
            .bindings
            .aethel_core_identity()
            .credential()
            .call_issue(
                &mut self.store,
                self.handle,
                issuer_seed,
                &values,
                &randomness,
            )??;

        Ok(Credential {
            handle,
            schema: names,
            issued,
        })
    }

    /// Present a credential at `context`, disclosing the named attributes.
    ///
    /// Blinding randomness is fresh on every call, which is what makes two
    /// presentations of the same credential unlinkable.
    pub fn present(
        &mut self,
        credential: &Credential,
        context: &[u8],
        disclose: &[&str],
    ) -> Result<Presentation, Error> {
        let mask = credential.mask_for(disclose)?;

        let projection_randomness = fresh_randomness()?;
        let blinding_randomness = fresh_randomness()?;
        let presentation_randomness = fresh_randomness()?;

        let inner = self
            .bindings
            .aethel_core_identity()
            .credential()
            .call_present(
                &mut self.store,
                credential.handle,
                self.handle,
                context,
                &projection_randomness,
                mask,
                &blinding_randomness,
                &presentation_randomness,
            )??;

        // The verifier needs the projection this was proved against. It is
        // public, and deriving it here with the same randomness is what makes
        // the presentation self-contained.
        let projection = self
            .bindings
            .aethel_core_identity()
            .master_identity()
            .call_project_at_context(
                &mut self.store,
                self.handle,
                context,
                &projection_randomness,
            )??;

        Ok(Presentation {
            inner,
            projection: crate::identity::Projection::from_component(projection),
            schema: credential.schema.clone(),
        })
    }
}

/// Verify a presentation.
///
/// `expected_context` is supplied by the verifier and must match the one the
/// presentation was made for. A presentation is not allowed to certify its own
/// context, so passing `presentation`'s own context back in would defeat the
/// check rather than satisfy it.
///
/// Returns `Ok(false)` for a well-formed presentation that does not verify.
pub fn verify_presentation(
    issuer_seed: &[u8],
    presentation: &Presentation,
    expected_context: &[u8],
) -> Result<bool, Error> {
    let (mut store, bindings) = crate::component::load()?;
    let verified = bindings
        .aethel_core_identity()
        .call_saap_verify_presentation(
            &mut store,
            issuer_seed,
            &presentation.inner,
            presentation.projection.as_component(),
            expected_context,
        )??;
    Ok(verified)
}
