# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to the breaking-change and deprecation rules in
[`STABILITY.md`](./STABILITY.md) rather than strict SemVer prior to `1.0.0` — see that
document for what counts as breaking inside `0.x`.

## [Unreleased]

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

### Notes

- SAAP selective disclosure does not work in the embedded component. `saap-verify` denies
  unconditionally because the corrected verifier needs a public key the current WIT signature
  cannot carry. It fails closed rather than accepting forgeries. The README says so, and a
  future method name on this crate should not be read as evidence it started working.
- No crypto is implemented in this crate and none ever will be. The SHA-256 dependency is an
  integrity check over the embedded bytes, not an operation of the identity protocol.

- Initial scaffolding, no functionality yet. Repo structure, program artifacts (LICENSE,
  NOTICE, SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, STABILITY.md), CI, and a
  placeholder crate that builds and tests cleanly with nothing to test. See
  [ROADMAP.md](./ROADMAP.md) for what's designed but not yet built.
