# Roadmap

This roadmap is expected to move. That is by design, not a caveat: this project ships `0.x`
(see [`STABILITY.md`](./STABILITY.md)), and a public roadmap for a `0.x` project describes
current intent, not a committed schedule. Milestones will be reordered, split, merged, or
dropped as real implementation work surfaces things this list can't see yet. What's fixed is
the destination — an ergonomic Rust SDK over `aethel-core`'s post-quantum identity
primitives — not the path.

Four of the milestones below are done, and this list said "nothing below is implemented yet"
for long enough after that stopped being true that it was actively misleading. The four are
marked **(shipped)**. The rest are still ahead of us — see the README's "what runs today vs.
what is designed" section for the authoritative current split.

## Embed the core (shipped)

Bring in `aethel-core`'s compiled WASM component as this crate's L1 boundary — one `.wasm`
shipped inside the package, not fetched at install time, with a reproducible build and a
published hash so anyone can verify the binary matches the published source. Everything else
in this SDK is built on top of that embedding.

## Generate, sign, verify, round-trip (shipped)

The core identity lifecycle: generate an identity and persist it, load it back on a different
platform, sign a message and verify the signature (rejecting both a tampered message and a
wrong-key signature), and emit W3C Multikey output that validates against an independent
verifier. No function may return, print, or log private key material. Generation must succeed
fully offline, proven in CI by denying network access at the boundary — a real network
namespace with no interface, plus a negative-control test that fails when isolation is
actually enforced — not by an in-process "am I offline?" assertion.

A related constraint that runs alongside this milestone rather than after it: nothing in the
ergonomic layer may reintroduce variable-time comparison above the L1 boundary. `aethel-core`
already does constant-time comparison internally; a plain `==` on a signature, MAC, or proof
up here would quietly undo that.

Multikey output and the offline-generation CI gate are not yet built; the rest of this
milestone is.

## PLP contextual projection (shipped)

Contextual projection — `project_at(context)` — so the same identity produces projections
that use fresh secret randomness and are independent both across contexts and across repeated
calls at one context. Reproducibility is valid only when identity, context, and caller-supplied
randomness are all the same. This is the part of the SDK that makes it more than another signing
library, and it should read as roughly one line of caller code.

Shipped as `Identity::project_at()` and `Identity::project_at_with_randomness()`. Standalone
PLP proof and verification (`prove`, `plp-verify`) are callable through the component but are
not wrapped on this surface yet, so a projection is not yet something a caller can prove
ownership of.

## SAAP selective disclosure (shipped)

Selective disclosure on top of a projection: disclosure masks expressed as named attributes
(never a raw bitmask), a proof that reveals exactly the named attributes and no others, proof
verification that fails on tampering, and no way to recover an undisclosed attribute from the
proof. Documented with a worked example — "prove one thing without revealing the rest."

Shipped as disclosure over a credential's own named attributes
(`issue_credential()`/`present()`/`verify_presentation()`); it does not sit on top of a PLP
projection yet, since it was built before that milestone. Predicate proofs over a hidden
attribute are also not implemented — see the README's "what this cannot do" section.

## HTSS recovery

Threshold recovery: splitting real key material (not a placeholder integer) into shares,
threshold recombination that reconstructs the identity, below-threshold shares that
demonstrably fail to reconstruct, and shares that are documented as safe to serialize and
transport. Losing one share above the threshold must not lose the identity.

## Quickstart (shipped, minus `project`)

A quickstart that works copy-pasted, end to end, in under ten minutes, on a machine that
isn't the author's — covering generate, sign, verify, project, and disclose, with every code
block actually run as part of producing it. This is treated as the single highest-leverage
artifact for adoption: if it doesn't work pasted cold, nothing else here matters as much.

The README's quickstart covers generate, sign, verify, persist, and disclose end to end.
`project` is the one step it can't show yet, because PLP contextual projection isn't built
on this SDK's surface — see the milestone above.

## Security model

A short, honest threat-model document: what this SDK claims, what it explicitly does not
claim, and — plainly — that it has not had a third-party audit. Published before crates.io,
not after.

## Publish

Publish `0.x` to [crates.io](https://crates.io), with the package name reserved ahead of time
(also on npm, for the future TypeScript binding — see the `0x307/aethel-core` "same artifact"
work this SDK depends on). A published `CHANGELOG.md` describing what's actually in the
release, `STABILITY.md` linked from the README, `cargo add` working into an empty project
against the real published crate (not a local path), and the crates.io repository link
returning `200` anonymously.
