# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to the breaking-change and deprecation rules in
[`STABILITY.md`](./STABILITY.md) rather than strict SemVer prior to `1.0.0` — see that
document for what counts as breaking inside `0.x`.

## [Unreleased]

### Added

- `Identity::project_at(context)`, PLP contextual projection. Each call samples fresh secret
  randomness from the OS, so two projections at the same context carry different salts and
  independent context matrices. The master secret stays inside the component.
- `Identity::project_at_with_randomness(context, randomness)`, for the cases that need a
  reproducible projection, such as tests or a protocol flow that must present the same
  projection twice. The randomness must be fresh and secret in ordinary use; reusing it at
  one context reproduces the projection byte-for-byte.
- `Projection`, exposing only public material: the padded context tag, the public salt, the
  public coefficients, and `to_bytes()` over the three of them.
- `MIN_PROJECTION_RANDOMNESS_BYTES`.
- `examples/projection.rs`, the worked example the README points at.
- `Identity::public_key_multibase()`, the public key as a W3C Multikey: base58btc over the
  registered ML-DSA-65 multicodec code and the key bytes. `public_key()` returns raw bytes
  that name no algorithm; a Multikey names it in-band, so a verifier that has never seen this
  SDK can decode it. Checked in `tests/multikey.rs` against the third-party `multibase` crate
  and against `pqc-sig`, two decoders that share no code with the encoder, plus a negative
  control that a key announcing a different algorithm is refused.
- `ML_DSA_65_MULTICODEC`.

### Changed

- SDK versions no longer track `aethel-core`'s. `0.1.5` said they did; they now version
  independently, because holding them equal means either cutting empty releases here to chase
  a core version or sitting on a shipped feature waiting for one. The pin identifies the pair
  instead: `core/pin.toml` names the revision, `core/component.sha256` names the artifact, both
  ship in the package, and every release entry states the embedded revision. See
  [`STABILITY.md`](./STABILITY.md) section 6.

### Security

- The narrow timing claim is now written down and enforced. `aethel-core` compares
  authentication-bearing bytes in constant time in `ct_verify.rs`, and this crate must not
  undo that with a plain `==` on a signature, a proof, or key material. Every comparison that
  decides whether something verifies happens inside the component; the SDK passes the bytes
  across the boundary and returns the answer. `scripts/check-comparisons.sh` runs in CI and
  fails on any equality in `src/` not listed in `scripts/allowed-comparisons.txt` with a
  written reason, so a new one is a decision rather than an unremarked diff. The three listed
  today are a build-metadata key name, the embedded component's published hash, and a public
  attribute name. None of this claims the SDK, the host runtime, or a calling application is
  constant-time end to end, and the README says so.

## [0.3.2] - 2026-09-03

### Security

- **`aethel-sdk` 0.1.0 and 0.1.5 were yanked from crates.io.** Both embedded `aethel-core`
  at `d8b53ef7d80cefb5748ea19e5a73afa2951b0660`, the exact revision an external security
  assessment ran against before its findings were fixed. This release embeds 0.3.2, which
  contains those fixes, and is the first version anyone can newly adopt since the yank.
  Lockfiles that already resolved a yanked version are unaffected and keep building; there
  was simply nothing new to install until this release.

### Changed

- The embedded component moved to `aethel-core` 0.3.2
  (`a09787d67a120f1d8a81b41755acf1e75c8f3289`), via `scripts/sync-core.sh`. The WIT world
  reshaped in four ways relative to the previously-embedded `d8b53ef`, none of which touch
  this crate's public API: `ephemeral-projection` drops `matrix-a` for a per-projection
  `salt` (`A` is now derived from `(tau, salt)` rather than trusted off the wire),
  `htss-reconstruct` takes and checks a Merkle root before interpolating, `identity-error`
  gains `invalid-share-set`, and the free-standing `for_proving` projection helper is gone in
  favor of `project_at_context`. None of the four are reachable through this SDK today — PLP
  contextual projection and HTSS recovery are still unbuilt on the SDK surface (see
  [ROADMAP.md](./ROADMAP.md)) — so there is no migration on this side.

  0.3.2 rather than 0.3.1: `aethel-core`'s own `pqc-sig` dependency was still pinned to a
  version that crates.io had since yanked (CRA-8), which broke this crate's `cargo-deny`
  advisories check and, it turned out, broke a from-scratch `cargo add aethel-core` for
  anyone. Fixed upstream and re-verified before this re-pin.

  | | |
  |---|---|
  | artifact | `core/aethel_core.component.wasm` |
  | SHA-256 | `375bf1f3c546fef84b45757417c39e22729b7df44063e8658bb6d0a973bc5218` |
  | aethel-core revision | `a09787d67a120f1d8a81b41755acf1e75c8f3289` |
  | canonical toolchain | ubuntu-24.04, Rust 1.97.0, wasm-tools 1.258.0 |

- The `aethel-core` dev-dependency moves off the yanked `^0.1` line to `^0.3`.

### Fixed

- `tests/fixtures/sealed-identity.bin` regenerated against the 0.3.2 component; the fixture
  sealed under `d8b53ef` did not open against it.
- CI and `scripts/sync-core.sh` silence three lint categories (`unexpected_cfgs`,
  `dead_code`, `missing_docs`) that surface when building the pinned `aethel-core` revision
  as a component. Confirmed benign for this exact revision rather than assumed: the
  dead-code warnings are the retired standalone SAAP interface, kept in `aethel-core` only so
  two of its own test files can pin its historical defects; the lone `unexpected_cfg` is a
  stale `#[cfg(feature = "wasm")]` left from a removed feature. Tracked for a real fix
  upstream rather than re-verified by hand on every sync — CRA-7.

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
