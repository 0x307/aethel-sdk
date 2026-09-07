# Security Model

What this crate claims, how each claim is checked, and what it does not claim. To report a
vulnerability, see [`SECURITY.md`](./SECURITY.md).

This is a `0.x` library. **It has not had a third-party security audit.** That is stated first
rather than buried, because it is the single fact most likely to change how you should read
everything below. An external assessment was run against `aethel-core` at revision `d8b53ef`,
and its findings were fixed upstream; that is not the same as an audit of this crate, and
nobody should treat it as one.

## The shape of the thing

`aethel-sdk` implements no cryptography and never will. Every cryptographic operation happens
inside a compiled WebAssembly component, `aethel-core`, which is embedded in the package. This
crate loads that component, passes bytes across the boundary, and returns answers.

That boundary is the reason most of the claims below can be made at all, and the reason the
rest of them are the caller's problem rather than ours.

```
your application
      │
      ▼
aethel-sdk (this crate) ......... no keys, no crypto, no comparisons that decide anything
      │
      ▼
aethel-core component (L1) ...... key derivation, signing, projection, disclosure, recovery
```

## What is claimed, and how it is checked

**No cryptography above L1.** Nothing in `src/` implements a cryptographic operation. The one
computation this crate performs on bytes is a SHA-256 integrity digest over the embedded
artifact, and a base58btc encoding of an already-public key.

**No secret-bearing types in this crate.** The ML-DSA-65 signing key and the PLP master seed
are derived inside the component from caller entropy and stay there. The public key is the only
key material that crosses the boundary. Checked by tests that format key-bearing types and
search the output, each with a positive control proving the check can fail.

**The embedded component is the one we published.** `core/component.sha256` records the digest,
`core/pin.toml` records the `aethel-core` revision and the exact toolchain that built it, and
`scripts/sync-core.sh` rebuilds it in a pinned container so anyone can reproduce the bytes. CI
rebuilds and compares on every change. A substituted component is refused before it runs.

**Identity generation is offline.** Creating an identity reaches nothing, and the component is
compiled into the crate rather than fetched at install time. Proven by the `offline generation
(network-isolated)` CI job, which runs the suite inside a network namespace with no interface,
and by a negative control that opens a real TCP connection and is required to *fail* there. A
suite that merely passes cannot distinguish working isolation from isolation that silently
stopped being applied; a control that must fail can.

**Comparisons that decide whether something verifies happen in L1, in constant time.**
`aethel-core` does constant-time comparison in `ct_verify.rs`. This crate does not undo that:
it passes signatures, proofs and keys across the boundary and returns the answer. Enforced by
`scripts/check-comparisons.sh`, a CI job that fails on any equality comparison in `src/` not
listed in `scripts/allowed-comparisons.txt` with a written reason.

## What you are responsible for

These are not weaknesses in the library. They are places where the guarantee ends and yours
begins, and every one of them can be got wrong while the API returns `Ok`.

**The sealing key is a single point of failure.** `export_sealed`, `open_sealed`, and both
recovery calls take a sealing key that must be high-entropy key material, not a password. Lose
it and the identity is gone, including from a full set of recovery shares. Threshold recovery
protects the *availability* of the sealed blob; it does not replace the key that opens it.

**Store the HTSS Merkle root apart from the shares.** Recovery authenticates every share
against a root you supply. The serialized envelope also carries a claimed root so a share can
travel alone, and that copy is untrusted: a share set that supplies its own root can
authenticate itself, and reconstruction would return whatever that set encodes. Keep the root
somewhere the holder of the shares does not control.

**Projection randomness must be fresh and secret.** `project_at` samples it for you and is the
path to use. `project_at_with_randomness` exists for reproducibility; its randomness must never
be derived from the context or from identity data. Reusing it at one context is safe, because
that carries no new sample to average. Deriving it deterministically is not.

**Disclosed attributes are self-asserted.** This is the one most likely to be
over-read, because selective disclosure sounds like it carries an issuer's word.
It does not, yet. Verification checks that a presentation opens to a short
preimage under the issuer's public parameters; it does not check that an issuer
authorised the attribute values. A holder must hold those parameters in order to
present at all, so any holder can construct a credential over their own identity
with attributes of their choosing, and it will verify. What the separation of
public parameters from the seed does buy is real but narrower: a verifier holds
no secret, a verifier can be a public endpoint, and a compromised verifier cannot
issue against anybody else's identity. If your deployment needs "the issuer said
this" rather than "the holder says this and the shape is right", you need
issuer-authenticated issuance, which is not shipped. `aethel-core`'s
`docs/ISSUER-AUTHENTICATION.md` states the gap and the construction that closes
it.

**Issuer public parameters are publishable; the issuer seed is not.** Deriving
the parameters from the seed is one-way, so publishing them does not leak the
seed. The seed is the whole of the issuer's authority: whoever holds it can
issue. Keep the two apart, and give verifiers only the parameters.

**Authenticated is not confidential.** Recovery shares, sealed blobs, and the sealing key are
all recovery-sensitive. Authentication stops substitution; it does nothing about disclosure.
Protect them with access control and transport encryption, and keep them out of logs.

**Entropy quality is yours.** `Identity::generate()` reads the OS CSPRNG.
`Identity::from_entropy()` takes what you give it and stretches it through SHAKE-256 with
domain separation. Generation is deterministic in that entropy, so weak entropy means a
predictable identity, and the component cannot tell the difference.

## What is out of scope

**No third-party audit.** Stated again because it belongs in this list too.

**Side channels above L1.** The timing claim above is narrow and deliberately so. It says
comparisons that decide verification happen inside the component in constant time, and that
this crate does not reintroduce a variable-time one. It is **not** a claim that the SDK,
wasmtime's compilation and execution, your allocator, or your application is constant-time end
to end. A serious side-channel posture has to account for all of those, and this library does
not give you one.

**Physical and hardware attacks.** No PUF, no secure element, no protection against an attacker
with physical access to the machine or its memory. Secrets live in the component's linear
memory while a process holds an identity.

**`aethel-runtime`.** A separate project with a separate posture. Nothing here says anything
about it.

**Predicate proofs.** Not implemented. You disclose an attribute's value or you keep it hidden;
you cannot prove a statement about a hidden value. See the README's "What this cannot do yet".

**The correctness of `aethel-core`'s constructions.** The security of PLP, SAAP and HTSS rests
on `aethel-core`'s stated assumptions, notably M-LWE. This crate's tests check observable
behaviour at its own boundary, such as that a projection exposes only public material. They are
not, and cannot be, proofs of the underlying cryptography.

## Version history worth knowing

`aethel-sdk` 0.1.0 and 0.1.5 were **yanked from crates.io**. Both embedded `aethel-core` at
`d8b53ef`, the exact revision the external assessment ran against, before any of its findings
were fixed. Every release since embeds a core containing those fixes. Lockfiles that already
resolved a yanked version keep building, which is why the yank is stated here rather than left
to be discovered.
