//! `build.rs` is the whole fix for the stale-bindings incident, and nothing
//! tested it.
//!
//! `src/component.rs` generates its bindings from `core/wit` with `bindgen!`. A
//! proc-macro reading a file is invisible to cargo's dependency tracking, so
//! without the `rerun-if-changed` lines in `build.rs`, re-vendoring a reshaped
//! world and rebuilding **silently keeps the old bindings**: the build succeeds
//! and the suite passes against a world the shipped component no longer has.
//! That is not hypothetical — it happened during the 0.4.0 migration, and only
//! `cargo clean -p aethel-sdk` surfaced the two call sites that no longer
//! typechecked.
//!
//! Deleting one of those lines reintroduces that failure, and every other test
//! in this crate would still pass. This one does not.
//!
//! It asserts on the text of `build.rs` rather than on cargo's behaviour.
//! Observing the real thing means mutating a vendored world and running two
//! builds, which is C1-06's job end to end; this is the cheap guard that keeps a
//! line from going missing unnoticed in the meantime.

#![cfg(not(target_arch = "wasm32"))]

const BUILD_RS: &str = include_str!("../build.rs");

/// Every path the component bindings are generated from, and so every path a
/// change to which must force a rebuild.
const REQUIRED: [&str; 4] = [
    "core/wit",
    "core/aethel_core.component.wasm",
    "core/component.sha256",
    "core/pin.toml",
];

fn declared(source: &str) -> Vec<&str> {
    source
        .lines()
        .filter_map(|line| line.split("cargo:rerun-if-changed=").nth(1))
        .filter_map(|rest| rest.split('"').next())
        .collect()
}

#[test]
fn build_rs_declares_every_component_input() {
    let declared = declared(BUILD_RS);
    for path in REQUIRED {
        assert!(
            declared.contains(&path),
            "build.rs does not declare `{path}` as a build input. Changing it \
             would not trigger a rebuild, and the bindings in src/component.rs \
             would silently go stale against the shipped component.\n  \
             declared: {declared:?}"
        );
    }
}

/// Positive control for the test above.
///
/// An assertion that a list contains four names proves nothing unless the
/// extraction behind it can see a name go missing, so remove one line and
/// require it to be noticed. Without this, a `declared` that returned `REQUIRED`
/// unconditionally would look identical.
#[test]
fn a_deleted_declaration_is_detected() {
    let gutted: String = BUILD_RS
        .lines()
        .filter(|line| !line.contains("core/wit"))
        .collect::<Vec<_>>()
        .join("\n");

    let declared = declared(&gutted);

    assert!(
        !declared.contains(&"core/wit"),
        "the extraction still reports core/wit after its declaration was \
         removed. It cannot detect a deleted line, so the test above is \
         worthless"
    );
    assert!(
        declared.contains(&"core/pin.toml"),
        "the control removed more than the one line it meant to; it is not \
         isolating the deletion it claims to test"
    );
}
