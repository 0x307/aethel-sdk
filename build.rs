//! Tell cargo that the vendored component and its WIT are build inputs.
//!
//! `src/component.rs` generates its bindings from `core/wit` with
//! `wasmtime::component::bindgen!`. A proc-macro reading a file is invisible to
//! cargo's dependency tracking, so without this, re-vendoring a reshaped world
//! with `scripts/sync-core.sh` and then running `cargo build` **silently keeps
//! the old bindings**: the build succeeds, the tests pass, and they exercise a
//! world the shipped component no longer has.
//!
//! That is not hypothetical. It happened while migrating to `aethel-core`
//! 0.4.0, which changed `saap-verify-presentation` to take issuer public
//! parameters instead of the issuer seed. After the sync, `cargo build` was
//! clean and only `cargo clean -p aethel-sdk` surfaced the two call sites that
//! no longer typechecked. A green build after a re-vendor was worth nothing,
//! which is the same failure shape as trusting a test suite that never ran the
//! code it claims to cover.
//!
//! The component itself is listed too. It is `include_bytes!`'d, so cargo does
//! track it, but naming both here keeps the rule in one place.

fn main() {
    println!("cargo:rerun-if-changed=core/wit");
    println!("cargo:rerun-if-changed=core/aethel_core.component.wasm");
    println!("cargo:rerun-if-changed=core/component.sha256");
    println!("cargo:rerun-if-changed=core/pin.toml");
}
