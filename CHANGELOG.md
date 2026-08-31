# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to the breaking-change and deprecation rules in
[`STABILITY.md`](./STABILITY.md) rather than strict SemVer prior to `1.0.0` — see that
document for what counts as breaking inside `0.x`.

## [0.1.5] - 2026-08-31

Version numbers track `aethel-core`, so the SDK and the component it embeds are
identifiable as a pair. `0.1.0` was published before this changelog was split into
released sections; everything below is what that release and this one contain together.

### Changed

- The embedded component moved to `aethel-core` 0.1.5
  (`d8b53ef7d80cefb5748ea19e5a73afa2951b0660`), whose world no longer exports the
  superseded `attestation` interface. Nothing in this crate's public API used it, so
  there is no migration on this side: `Identity::issue_credential()`,
  `Identity::present()` and `verify_presentation()` are unchanged and go through
  `saap-verify-presentation`, as they already did.

  | | |
  |---|---|
  | artifact | `core/aethel_core.component.wasm` |
  | SHA-256 | `6a8ab7c07c0a100e2e3d3e0ec3362f0d6d93585be1e923bf8027613c86de0da9` |
  | aethel-core revision | `d8b53ef7d80cefb5748ea19e5a73afa2951b0660` |
  | canonical toolchain | ubuntu-24.04, Rust 1.97.0, wasm-tools 1.258.0 |

### Fixed

- `scripts/sync-core.sh` checked the rebuilt component for `saap-prove` and
  `saap-verify`, which 0.1.5 removed. Re-vendoring onto any newer core would have failed
  on that stale assertion rather than on anything real. It now checks the operations the
  world actually declares.

### Added

- The `aethel:core` WebAssembly component is embedded in the crate, built from a pinned
  `aethel-core` revision. The artifact, the SHA-256 the package declares for it, and the
  revision and toolchain that produced it are checked in together under `core/`.

  | | |
  |---|---|
  | artifact | `core/aethel_core.component.wasm` |
  | SHA-256 | `0437b9aa6dcd338c7ae03d2551c1ad3a43258d65d85b860d4a2d91d0f0a99c7b` |
  | aethel-core revision | `20c02db2da6fa54cc047cca6c3c37bfc1fb5f57e` |
  | canonical toolchain | ubuntu-24.04, Rust 1.97.0, wasm-tools 1.258.0 |

  The hash is platform-specific. See the README for how to rebuild it and compare.
- `scripts/sync-core.sh` re-vendors the WIT world, rebuilds the component, and rewrites the
  declared hash from the pinned revision, in a container pinned to the canonical platform so
  it can be run from any host. This is the documented command for moving to a newer
  `aethel-core`.
- A `component` CI job that rebuilds the artifact from the pinned revision, requires two
  builds to be byte-identical, requires the result to equal the committed artifact and the
  declared hash, and includes a positive control that a modified artifact is detected.
- Tests over the embedded artifact: it is present, it is a component rather than a core
  module, and its hash matches what the package declares. Each is paired with a positive
  control feeding the same machinery an artifact known to be wrong.
- README instructions for rebuilding the component and comparing it yourself, including why
  the hash is platform-specific.
- `aethel_sdk::component::load()`, which checks the declared hash before the bytes reach the
  runtime and instantiates the component through bindings generated from `core/wit/` at
  compile time. Nothing is hand-written against the world.
- An execution proof: the embedded component instantiates, its PLP projection agrees with
  `aethel-core`'s native API coefficient for coefficient, prove and verify round-trip, HTSS
  round-trips and reports `threshold-not-met` below threshold, and typed errors reach the
  caller rather than sentinels. Positive controls cover the integrity gate and the comparison
  itself.
- A `wasm32` CI job, because `wasmtime` is a host runtime scoped away from
  `wasm32-unknown-unknown` and that scoping needs a job rather than a comment.

- `Identity::generate()`, `Identity::from_entropy()`, `Identity::sign()` and `verify()`. The
  signing key is derived inside the component from entropy this crate supplies and never enters
  this process; only the public key crosses back. `Debug` on `Identity` prints a public key
  fingerprint and says where the secret lives.
- A quickstart in the README that generates an identity, signs, and verifies.
- The embedded component moved to `aethel-core` `55ceb20`, which adds the `master-identity`
  resource, `sign` and `verify-signature` to the world. Re-vendored with
  `scripts/sync-core.sh`, which needed no source changes here.
- `scripts/sync-core.sh` now works from Git Bash on Windows. It was passing container-absolute
  paths through MSYS path conversion, so `/out/build.sh` reached Docker as a Windows path and
  the run failed.

- **Selective disclosure.** `Identity::issue_credential()`, `Identity::present()` and
  `verify_presentation()`. Attributes are named end to end; no bitmask appears in the API, and a
  name the credential does not carry is an error rather than a silent no-op.
- **Sealed persistence.** `Identity::export_sealed()` and `Identity::open_sealed()`. The sealing
  input is a key, not a password: it must be high-entropy key material, because the component
  stretches it with SHAKE-256, which is fast by design.
- A cross-platform sealing fixture. `tests/fixtures/sealed-identity.bin` is sealed on Windows
  and opened by CI on Linux, so "written on one platform, loads on another" is tested rather
  than assumed.
- The component moved to `aethel-core` `a9b778c`, which adds the credential resource, sealed
  export and import, and widens attribute encoding to the full `u64` range.

### Changed

- The README no longer says SAAP disclosure does not work, because it does. It now states the
  limitation that remains: predicate proofs over hidden attributes are not implemented, so you
  can disclose a value or hide it, but not prove a statement about a hidden one.

### Security

- `wasmtime` is pinned at 48.0.1. The version originally copied from `aethel-core`, 34.0.2,
  carries 17 open RustSec advisories including sandbox escapes and out-of-bounds writes. That
  is a dev-dependency upstream and a runtime dependency here, so it was upgraded rather than
  inherited. `cargo deny check` passes on advisories, bans, licenses and sources.

### Notes

- Predicate proofs over hidden attributes are deliberately not built. You can disclose an
  attribute's value or hide it; you cannot prove a statement about a hidden one, so "age over
  21 without revealing age" does not work yet. A method name on this crate should not be read
  as evidence that it does.
- No crypto is implemented in this crate and none ever will be. The SHA-256 dependency is an
  integrity check over the embedded bytes, not an operation of the identity protocol.

- Initial scaffolding, no functionality yet. Repo structure, program artifacts (LICENSE,
  NOTICE, SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, STABILITY.md), CI, and a
  placeholder crate that builds and tests cleanly with nothing to test. See
  [ROADMAP.md](./ROADMAP.md) for what's designed but not yet built.
