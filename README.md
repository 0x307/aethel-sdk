# aethel-sdk — Rust SDK for Post-Quantum Identity

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](#license)

> ⚠️ **This project ships `0.x`.** Nothing here is stable yet, and breaking changes are
> expected between minor versions until `1.0`. See [`STABILITY.md`](./STABILITY.md) for
> exactly what that means.

`aethel-sdk` is planned as an ergonomic Rust surface over
[`aethel-core`](https://github.com/0x307/aethel-core)'s post-quantum identity primitives.
Where `aethel-core` exposes the cryptographic building blocks (Polymorphic Lattice
Projection, Selective Attribute Attestation, 5D Hypercube Threshold Secret Sharing) as a
`no_std`/WASM component, this crate is meant to give an application developer the everyday
verbs on top of it:

- **Generate** an identity and persist it
- **Sign** a message and **verify** a signature
- **Project** an identity into a caller-supplied context (PLP), so the same identity is
  unlinkable across contexts
- **Disclose** selected attributes without revealing the rest (SAAP)
- **Recover** an identity from threshold shares (HTSS)

## What runs today vs. what is designed

**Runs today:**

- Repo scaffolding and program artifacts: `LICENSE`, `NOTICE`, `SECURITY.md`,
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `STABILITY.md`, CI.
- **The `aethel:core` component is embedded in the crate**, built from a pinned
  `aethel-core` revision, with its SHA-256 declared in the package and checked by tests and
  by CI. See [The embedded component](#the-embedded-component) below, including how to
  rebuild it yourself and compare.
- Nothing cryptographic is implemented in this crate, and nothing ever will be. Every
  cryptographic operation lives inside the component. That is the charter's L1 boundary: one
  artifact, embedded by every language, and adding a language never adds crypto.

**Designed, not yet implemented:**

- Generate / load / sign / verify / round-trip an identity
- Offline generation, proven by network isolation in CI
- PLP contextual projection (`project_at(context)`)
- SAAP selective disclosure over named attributes
- HTSS threshold recovery (split and recombine)
- A ten-minute quickstart
- A published security model
- Publishing `0.x` to crates.io

See [ROADMAP.md](./ROADMAP.md) for the milestone sequence this is built in.

## Quickstart

There isn't one yet. Nothing in this crate does anything a developer would call. This section
will hold a copy-paste-tested quickstart once generate/sign/verify lands (see the roadmap).

## The embedded component

Everything cryptographic happens inside `aethel_core.component.wasm`, a WebAssembly Component
Model component built from [`aethel-core`](https://github.com/0x307/aethel-core). It is
**embedded in this crate at compile time**, not downloaded at install time, so what you build
against is what you audited.

Three files under `core/` are meant to be read together:

| File | What it is |
|---|---|
| `core/aethel_core.component.wasm` | the artifact itself |
| `core/component.sha256` | the hash this package *claims* those bytes have |
| `core/pin.toml` | the aethel-core revision and toolchain that produced them |

### Rebuild it yourself and compare

Shipping a compiled binary inside a source package is only defensible if you do not have to
take our word for what is in it. You do not:

```bash
git clone https://github.com/0x307/aethel-sdk && cd aethel-sdk
scripts/sync-core.sh
git diff --stat core/
```

A clean `git diff` means the committed artifact is exactly what the pinned `aethel-core`
revision builds. The script clones aethel-core at the pinned revision, builds it twice,
requires the two builds to be byte-identical, validates the component, checks that every
operation the WIT world declares is actually present in it, and writes the result with its
hash. It needs Docker and network access, and nothing else. The same comparison runs in CI on
every push, along with a positive control that a modified artifact is detected.

To do it without the script, `.github/workflows/component.yml` is the same sequence written
out step by step.

### The hash is platform-specific

`rustc` embeds platform paths and links a different `std`, so the same source built on Windows
or macOS produces **different bytes** from the same revision. That is expected and is not a
reproducibility failure. The canonical platform and toolchain are recorded in `core/pin.toml`,
and `scripts/sync-core.sh` reproduces that environment in a container so the canonical bytes
can be built and checked from any host.

### Updating to a newer aethel-core

```bash
scripts/sync-core.sh <revision>
cargo test
```

That re-vendors the WIT world, rebuilds the artifact, rewrites the declared hash, and moves
the pin. Bindings are generated from `core/wit/` at compile time, so a reshaped world is
picked up by the next `cargo build` with nothing hand-written to update.

### SAAP disclosure does not work

`saap-verify` in the embedded component **denies unconditionally**. It returns `false` for
every input, including honestly generated proofs. The corrected verifier needs a public key
that the current WIT signature has no parameter to carry, so the operation fails closed rather
than accepting forgeries. This is deliberate, it is documented upstream, and it is tracked as
[0X3-79](https://github.com/0x307/aethel-core) in aethel-core's P3 work.

Selective disclosure is therefore **not usable through this SDK today**, and no future method
name on this crate should be read as evidence that it started working.

## Stability and support

This project ships `0.x`. See [`STABILITY.md`](./STABILITY.md) for what counts as a breaking
change, deprecation notice, release cadence, and support posture.

## Security

See [`SECURITY.md`](./SECURITY.md) to report a vulnerability.

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md), including the current external-contribution
posture.

## License

Apache-2.0

## Maintainer

Ed Johnson
