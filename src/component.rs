//! Loading the embedded `aethel:core` component.
//!
//! Bindings are generated from `core/wit/` by [`wasmtime::component::bindgen!`]
//! at compile time. Nothing in this module is hand-written against the world,
//! and nothing should be: when P3-11 reshapes `saap-verify` to carry `b_tau`,
//! the fix is `scripts/sync-core.sh` followed by `cargo build`, and whatever
//! breaks here breaks at compile time rather than at runtime.
//!
//! This module loads and instantiates. It does not wrap the operations in
//! anything ergonomic. Generate, sign and verify are P5-04, contextual
//! projection is P5-06, and threshold recovery is P5-08.

use crate::artifact::{self, IntegrityError};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};

wasmtime::component::bindgen!({
    path: "core/wit",
    world: "aethel-core",
});

/// Why the embedded component could not be loaded.
#[derive(Debug)]
pub enum LoadError {
    /// The embedded bytes are not the bytes the package declares. The component
    /// is not instantiated in this case: an artifact that fails its own
    /// integrity check does not get to run.
    Integrity(IntegrityError),
    /// The component was the right bytes but the runtime rejected it.
    Runtime(wasmtime::Error),
}

impl core::fmt::Display for LoadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LoadError::Integrity(e) => write!(f, "{e}"),
            LoadError::Runtime(e) => write!(f, "the embedded component failed to load: {e}"),
        }
    }
}

impl std::error::Error for LoadError {}

impl From<IntegrityError> for LoadError {
    fn from(e: IntegrityError) -> Self {
        LoadError::Integrity(e)
    }
}

/// Instantiate the embedded component.
///
/// The hash is checked before the bytes reach the runtime. This is the point of
/// shipping a declared hash at all: a substituted artifact must not execute, and
/// checking after instantiation would be checking too late.
pub fn load() -> Result<(Store<()>, AethelCore), LoadError> {
    load_bytes(artifact::COMPONENT)
}

/// Instantiate `bytes` after checking them against the declared hash.
///
/// Exposed separately from [`load`] so the integrity gate can be handed an
/// artifact that is known to be wrong. A gate that has only been fed the correct
/// input is not known to gate anything.
pub fn load_bytes(bytes: &[u8]) -> Result<(Store<()>, AethelCore), LoadError> {
    artifact::verify(bytes)?;

    let mut config = Config::new();
    config.wasm_component_model(true);

    let engine = Engine::new(&config).map_err(LoadError::Runtime)?;
    let component = Component::from_binary(&engine, bytes).map_err(LoadError::Runtime)?;
    let linker = Linker::new(&engine);
    let mut store = Store::new(&engine, ());
    let bindings =
        AethelCore::instantiate(&mut store, &component, &linker).map_err(LoadError::Runtime)?;

    Ok((store, bindings))
}
