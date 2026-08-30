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
- **The embedded component loads and executes.** `aethel_sdk::component::load()` checks the
  hash, refuses to instantiate an artifact that fails it, and returns bindings generated from
  the WIT world. Tests call it and compare the results against `aethel-core`'s native API at
  the same pinned revision, coefficient for coefficient.
- **Generate an identity, sign a message, verify a signature.** `Identity::generate()`,
  `Identity::sign()` and `verify()`. The signing key never exists in this process: it is derived
  inside the component and stays there.
- **Persist an identity and load it again**, on the same machine or another.
  `Identity::export_sealed()` and `Identity::open_sealed()`.
- **Selective disclosure.** Issue a credential over named attributes, present it disclosing only
  the ones you choose, and verify the presentation. `issue_credential()`, `present()` and
  `verify_presentation()`.
- Nothing cryptographic is implemented in this crate, and nothing ever will be. Every
  cryptographic operation lives inside the component. That is the charter's L1 boundary: one
  artifact, embedded by every language, and adding a language never adds crypto.

**Designed, not yet implemented:**

- Predicate proofs over hidden attributes. See [What this cannot
  do](#what-this-cannot-do-yet)
- Multikey encoding of the public key
- Offline generation, proven by network isolation in CI
- PLP contextual projection (`project_at(context)`)
- SAAP selective disclosure over named attributes
- HTSS threshold recovery (split and recombine)
- A ten-minute quickstart
- A published security model
- Publishing `0.x` to crates.io

See [ROADMAP.md](./ROADMAP.md) for the milestone sequence this is built in.

## Quickstart

```toml
[dependencies]
aethel-sdk = "0.1"
```

```rust
use aethel_sdk::{verify, verify_presentation, Identity};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Entropy comes from the OS. The signing key is derived from it inside the
    // embedded component and never enters this process.
    let mut identity = Identity::generate()?;

    // Sign and verify.
    let message = b"the message that was actually signed";
    let signature = identity.sign(message)?;
    assert!(verify(identity.public_key(), message, &signature)?);
    assert!(!verify(identity.public_key(), b"something else", &signature)?);

    // Persist it. `key` must be high-entropy key material, NOT a password.
    let key = b"a sealing key of thirty-two byte";
    let sealed = identity.export_sealed(key)?;
    let mut identity = Identity::open_sealed(&sealed, key)?;

    // Issue a credential over named attributes, and disclose only one of them.
    let credential = identity.issue_credential(
        b"the issuer's secret seed, 32 byte",
        &[("tier", 3), ("date_of_birth", 19_900_101)],
    )?;
    let presentation = identity.present(&credential, b"checkout-session", &["tier"])?;

    // The verifier learns the tier and nothing about the date of birth.
    assert_eq!(presentation.disclosed().get("tier"), Some(&3));
    assert!(presentation.disclosed().get("date_of_birth").is_none());
    assert!(verify_presentation(
        b"the issuer's secret seed, 32 byte",
        &presentation,
        b"checkout-session",
    )?);

    Ok(())
}
```

No network access is involved, and nothing is fetched at install time: the component is
compiled into the crate.

### What you are trusting

`verify` returns `Ok(false)` for a signature that does not verify and an error only for input
it could not process. Those are different answers on purpose. Treating an error as "invalid"
is the mistake that makes malformed input look like a failed check.

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

## What this cannot do yet

**Predicate proofs over hidden attributes are not implemented.** You can disclose an attribute's
value, or keep it hidden. You cannot prove a statement *about* a hidden value.

So this works:

> "I hold a credential from this issuer, and my `tier` is 3."

and this does not:

> "I hold a credential from this issuer, and my `age` is at least 21, and I am not telling you
> my age."

The second is the case most people want from selective disclosure, and it is the third of the
protocol's three relations. It is scoped to a later phase, and until then the honest answer is
that you disclose the value.

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
