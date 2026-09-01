//! Loading the embedded `aethel:core` component.
//!
//! Bindings are generated from `core/wit/` by [`wasmtime::component::bindgen!`]
//! at compile time. Nothing in this module is hand-written against the world,
//! and nothing should be: when P3-11 reshapes `saap-verify` to carry `b_tau`,
//! the fix is `scripts/sync-core.sh` followed by `cargo build`, and whatever
//! breaks here breaks at compile time rather than at runtime.
//!
//! This module loads and instantiates. It does not wrap the operations in
//! anything ergonomic: [`crate::identity`] and [`crate::disclosure`] do that.
//! Contextual projection and threshold recovery are not yet wrapped anywhere in
//! this crate, though both are callable through the component.

use crate::artifact::{self, IntegrityError};
use std::sync::OnceLock;
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

/// Instantiate the embedded component, reusing the process-wide compilation.
///
/// The hash is checked before the bytes reach the runtime. This is the point of
/// shipping a declared hash at all: a substituted artifact must not execute, and
/// checking after instantiation would be checking too late.
///
/// Prefer holding a [`Runtime`] explicitly if you want control over when the
/// compile happens. This function is the convenient path and shares one.
pub fn load() -> Result<(Store<()>, AethelCore), LoadError> {
    shared()?.instantiate()
}

/// Instantiate `bytes` after checking them against the declared hash.
///
/// Exposed separately from [`load`] so the integrity gate can be handed an
/// artifact that is known to be wrong. A gate that has only been fed the correct
/// input is not known to gate anything.
pub fn load_bytes(bytes: &[u8]) -> Result<(Store<()>, AethelCore), LoadError> {
    Runtime::from_bytes(bytes)?.instantiate()
}

/// A compiled component, ready to instantiate repeatedly.
///
/// # Why this exists
///
/// [`load`] used to compile the component on every call. `Component::from_binary`
/// runs Cranelift over the 1.8 MB artifact, which measured at **230 ms**, or 78%
/// of the cost of a single `verify_presentation`. A verifier on a request path
/// paid that per request.
///
/// Compilation is a property of the bytes, not of the call, so it belongs here.
/// A `Runtime` compiles once; [`Runtime::instantiate`] then costs a fresh
/// `Store` and an instantiation, which is cheap. Hold one for the process and
/// call `instantiate` per operation.
///
/// The integrity check runs during construction, before Cranelift sees the
/// bytes, for the same reason it did before: an artifact that fails its own
/// check does not get to compile, let alone run.
pub struct Runtime {
    engine: Engine,
    component: Component,
    linker: Linker<()>,
}

impl Runtime {
    /// Compile the embedded component.
    pub fn new() -> Result<Self, LoadError> {
        Self::from_bytes(artifact::COMPONENT)
    }

    /// Compile `bytes` after checking them against the declared hash.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LoadError> {
        artifact::verify(bytes)?;

        let mut config = Config::new();
        config.wasm_component_model(true);

        let engine = Engine::new(&config).map_err(LoadError::Runtime)?;
        let component = Component::from_binary(&engine, bytes).map_err(LoadError::Runtime)?;
        let linker = Linker::new(&engine);

        Ok(Runtime { engine, component, linker })
    }

    /// Produce a fresh store and instance.
    ///
    /// No compilation happens here. Each call gets its own `Store`, so instances
    /// share no state: a resource handle from one instantiation is meaningless
    /// in another, which is why `Identity` owns its store for its whole life.
    pub fn instantiate(&self) -> Result<(Store<()>, AethelCore), LoadError> {
        let mut store = Store::new(&self.engine, ());
        let bindings = AethelCore::instantiate(&mut store, &self.component, &self.linker)
            .map_err(LoadError::Runtime)?;
        Ok((store, bindings))
    }
}

/// The process-wide runtime, compiled on first use.
///
/// Every operation in this crate goes through here, so the 230 ms compile is
/// paid once per process rather than once per call.
///
/// A failure is not cached. Construction fails only when the embedded artifact
/// is wrong or the runtime rejects it, which is a packaging fault that will
/// reproduce identically on the next call; returning the real error each time is
/// more useful than memoising a stale one, and it costs nothing in the case that
/// matters because that case never succeeds.
pub fn shared() -> Result<&'static Runtime, LoadError> {
    static SHARED: OnceLock<Runtime> = OnceLock::new();

    if let Some(runtime) = SHARED.get() {
        return Ok(runtime);
    }
    let runtime = Runtime::new()?;
    Ok(SHARED.get_or_init(|| runtime))
}
