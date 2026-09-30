//! Registered signing purposes.
//!
//! A signature made under a purpose is bound to it: it does not verify under
//! another purpose, nor under the empty context that [`Identity::sign`] uses.
//! That is what stops a signature made for one kind of statement being replayed
//! as another.
//!
//! The registry lives in aethel-core and is read from the embedded component
//! (`registered-purposes`), not copied into this crate, so a purpose added to
//! core reaches the SDK with the next re-vendor and this crate links no
//! cryptography to know about it. A [`Purpose`] cannot be built from arbitrary
//! bytes: the only ways to get one are [`Purpose::registered`] and
//! [`Purpose::from_name`].
//!
//! [`Identity::sign`]: crate::Identity::sign

use std::sync::OnceLock;

use crate::component;
use crate::identity::Error;

/// A purpose from aethel-core's registry.
///
/// There is deliberately no constructor from bytes. A signing context that is
/// not in the registry is an ad hoc context string, which is what the registry
/// exists to prevent.
///
/// ```compile_fail,E0451
/// use aethel_sdk::Purpose;
/// let _ = Purpose { name: "MINE".into(), bytes: b"mine/v1".to_vec() };
/// ```
///
/// ```compile_fail,E0599
/// use aethel_sdk::Purpose;
/// let _ = Purpose::new(b"mine/v1");
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Purpose {
    name: String,
    bytes: Vec<u8>,
}

static REGISTRY: OnceLock<Vec<Purpose>> = OnceLock::new();

impl Purpose {
    /// The registry's name for this purpose, for example `AUTH_LOGIN_V1`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The exact bytes the component signs and verifies under.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Every registered purpose, in the registry's declaration order.
    ///
    /// Read from the embedded component the first time and kept for the life of
    /// the process: the registry is fixed by the artifact.
    pub fn registered() -> Result<&'static [Purpose], Error> {
        if let Some(registry) = REGISTRY.get() {
            return Ok(registry);
        }
        let (mut store, bindings) = component::load()?;
        let listed = bindings
            .aethel_core_identity()
            .call_registered_purposes(&mut store)?;
        let registry = listed
            .into_iter()
            .map(|p| Purpose {
                name: p.name,
                bytes: p.bytes,
            })
            .collect();
        Ok(REGISTRY.get_or_init(|| registry))
    }

    /// Look a purpose up by its registry name.
    ///
    /// Returns [`Error::UnknownPurpose`] for a name that is not registered.
    pub fn from_name(name: &str) -> Result<Purpose, Error> {
        Self::registered()?
            .iter()
            .find(|p| p.name == name)
            .cloned()
            .ok_or_else(|| Error::UnknownPurpose(name.to_string()))
    }
}
