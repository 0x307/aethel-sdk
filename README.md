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

- Repo scaffolding and program artifacts only — `LICENSE`, `NOTICE`, `SECURITY.md`,
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `STABILITY.md`, CI. A placeholder crate that builds
  and tests cleanly (`cargo build`, `cargo test`) with nothing to actually test yet.
- Nothing cryptographic. There is no `aethel-core` embedding, no key generation, no signing,
  no projection, no disclosure, and no recovery implemented in this crate.

**Designed, not yet implemented:**

- Embedding the `aethel-core` WASM component as the L1 boundary
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

There isn't one yet — nothing in this crate does anything. This section will hold a
copy-paste-tested quickstart once generate/sign/verify lands (see the roadmap).

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
