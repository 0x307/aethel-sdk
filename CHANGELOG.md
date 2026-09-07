# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to the breaking-change and deprecation rules in
[`STABILITY.md`](./STABILITY.md) rather than strict SemVer prior to `1.0.0` — see that
document for what counts as breaking inside `0.x`.

## [0.5.2] - 2026-09-07

### Fixed

- **The `aethel-core` dev-dependency was still pinned to the 0.3.2 revision after 0.5.0 vendored
  0.4.0.** `tests/component_execution.rs` says it compares the embedded component against
  "aethel-core's native API at the same pinned revision"; for one release that was not true, and
  it compared a 0.4.0 component against 0.3.2's native API and passed. `scripts/sync-core.sh`
  rewrites `core/pin.toml` and does not touch `Cargo.toml`, and nothing checked that they
  agreed.

  `the_dev_dependency_matches_the_vendored_revision` in `tests/embedded_artifact.rs` now fails
  when they disagree. Verified by pointing the pin at a different revision of the same version,
  which is the drift cargo cannot catch on its own.

- **`cargo publish` failed** because the same dev-dependency asked for `aethel-core = "0.3"`
  while every 0.3.x had been yanked upstream. Publishing drops the git source and resolves the
  version requirement against crates.io, so a requirement that stopped matching the pinned
  revision goes unnoticed locally and only surfaces at publish. Now `"0.4"`, matching what is
  vendored.

## [0.5.1] - 2026-09-07

Documentation, from a second blind test against the published 0.5.0. One reader built against
it cold and reached a working program in 3m46s; a second was asked only what the documentation
led them to *believe*, which found more than the build did.

### Fixed

- **`Presentation`'s docs named `Projection` as having `from_bytes`. It does not.** A reader
  wrote `Projection::from_bytes` on the strength of that sentence, got `E0599`, and could not
  tell from the docs whether they had hit a bug, an unreleased feature, or a doc error. That
  was the one moment in the run they wanted to open the source. Introduced in 0.4.0.
- **`verify_presentation` claimed a public verifying endpoint was possible** while
  `Presentation` said it has no serialised form. Both are true separately and they contradict
  each other: a presentation can only be verified in the process that made it, so the endpoint
  cannot be built yet. The claim now says what the split does buy and what it does not.

### Added

- **A "What `Ok(true)` does and does not mean" section on `verify_presentation` itself.** The
  self-assertion caveat was on the module page and the `IssuerPublicParameters` page, and a
  reader arriving from an IDE lands on the function, where none of it was.
- **The crate root now leads with the two limits** that decide whether this is usable for a
  given purpose, before the feature list. A reader who only skimmed the root came away
  believing this was a working credentials system with one known gap, and revised only on
  reaching a type page. The honesty was there; the ordering buried it.
- **A "what you are responsible for" summary in the crate docs**, and the out-of-scope list,
  rather than only a link to `SECURITY-MODEL.md`. That file is cited as the authority on what
  is claimed and is the one document a docs.rs reader cannot open.
- `MIN_ISSUER_SEED_BYTES`. The issuer seed was the only secret input without a stated length:
  entropy, seal keys and projection randomness all had one. Both blind rounds flagged it, and
  the second said its 32-byte guess came from prior knowledge rather than from us.
- `MAX_ATTRIBUTES` states its value where it is read, and `issue_credential` says attribute
  values are `u64` with no encoding for strings, so caller and verifier must agree a mapping
  out of band.
- A runnable `Verifier` example. The docs recommend `Verifier` for anything on a request path
  while every worked example used the free function they tell you not to use there.

## [0.5.0] - 2026-09-07

Embeds `aethel-core` 0.4.0 (`d01258563c7aaf99226b428793873d968180e99f`), which adds issuer
public parameters. Rebuilt hash `5fee03ee725d32da4949d8d0769dc48fe2f68d5b664b33bdd928a889b7f50dd4`,
matching the one `aethel-core` records for that revision.

### Breaking

- **Verification no longer takes the issuer seed.** `verify_presentation` and
  `Verifier::verify_presentation` take [`IssuerPublicParameters`] instead. Previously every
  party that could verify also held the full authority to issue, so an issuer and a verifier
  could not be separate parties and a verifier could not be a public endpoint. Deriving the
  parameters from a seed is one-way, so a compromised verifier can no longer issue against
  anyone else's identity.

  *Migration:* derive once and hold the result.

  ```rust
  let issuer = IssuerPublicParameters::derive(issuer_seed)?;
  verify_presentation(&issuer, &presentation, context)?;
  ```

  `IssuerPublicParameters::as_bytes` / `from_bytes` round-trip the published form, which is
  what you hand to a verifier. `issue_credential` still takes the seed, as it must.

### Fixed

- **`cargo build` silently kept stale bindings after re-vendoring the component.**
  `src/component.rs` generates its bindings from `core/wit` through a proc macro, and cargo
  does not see a file a macro reads. So after `scripts/sync-core.sh` pulled a reshaped world,
  the build succeeded against the *old* bindings and the tests passed while exercising a world
  the shipped component no longer had. It took `cargo clean -p aethel-sdk` to surface the two
  call sites that no longer typechecked, and `sync-core.sh` ends by telling you to run
  `cargo test`, which would have lied. A `build.rs` now declares `core/` as a build input.
  Verified by editing the WIT and confirming a rebuild is triggered.

### Documentation

- **What a verified presentation actually proves, restated.** The docs said the verifier
  "learns that the credential was issued by the issuer they named." It does not. The relation
  checks that the presentation opens to a short preimage under the issuer's parameters, and it
  does not check that an issuer authorised the attribute values. A holder must hold those
  parameters to present at all, so a holder can construct a credential over their own identity
  with attributes of their choosing and it will verify. Disclosed attributes are self-asserted.
  This was wrong before this release in one way and would have been wrong after it in a subtler
  way, which is the more dangerous kind.
- `SECURITY-MODEL.md` gains "Disclosed attributes are self-asserted" and "Issuer public
  parameters are publishable; the issuer seed is not" under what the caller is responsible for.
  The first is the item most likely to be over-read, because selective disclosure sounds like
  it carries an issuer's word.
- Deployments needing "the issuer said this" rather than "the holder says this and the shape is
  right" are pointed at `docs/ISSUER-AUTHENTICATION.md` in `aethel-core`, which states the gap
  and the construction that closes it.

## [0.4.0] - 2026-09-06

Everything here came out of blind-testing the quickstart: three readers were given only the
published crates.io page, no repository access, and told to build something and report every
point where they had to guess. All three succeeded, in about six minutes each. The list below
is what they hit on the way, and two of them independently found the same three API defects.

### Breaking

- **`Presentation::projection()` returns [`Projection`] instead of the raw component type.**
  It previously returned `&EphemeralProjection`, which comes from `aethel-core` and is a
  dev-dependency here, so no consuming crate could name the type: the accessor was unusable
  from outside this crate, and a reader who tried got a type error naming something they could
  not import. It now returns the same `Projection` that `Identity::project_at` produces, so
  `tau()`, `salt()`, `public_b()` and `to_bytes()` are available.

  *Migration:* field access becomes a method call. `presentation.projection().public_b` becomes
  `presentation.projection().public_b()`, and likewise for `tau` and `salt`.

- **`Credential::attribute_names()` returns only the attributes you issued over.** A credential
  occupies eight slots internally and the unused ones carry placeholder names; those
  placeholders were being returned to callers, so issuing over three attributes gave back
  `["tier", "age", "region", "__unused_3", ...]`. One reader noted they would have rendered the
  placeholders in a UI. `Debug` for `Credential` no longer shows them either.

  *Migration:* if you were filtering out `__unused_` prefixes yourself, stop.

- **A placeholder slot name is no longer disclosable.** `present()` searched all eight slot
  names, so `__unused_1` resolved to a slot and produced a valid disclosure of an attribute
  that was never issued. Name lookup is now restricted to the issued prefix, and an unissued
  name returns `UnknownAttribute` as it always should have.

### Fixed

- Recovery against a wrong `expected_root` reported "shares belong to different recovery sets"
  when the shares were all from one set and the root was the wrong input. It now names both
  possibilities instead of asserting the one that was false.

### Added

- **A runnable example on the crate's front page, and one on `verify`.** Both are doctests, so
  CI runs them. The published API previously had no code example anywhere: readers assembled
  their programs from type signatures alone, and the one worked example the docs pointed at
  (`examples/quickstart.rs`) was not reachable from the rendered documentation.
- `verify`'s documentation now names the `is_ok()` trap directly. `verify(..).is_ok()` is true
  for a signature that did not verify, and one reader identified this as the one place a
  newcomer could ship a program that accepts every signature.
- The crate documentation and README now state the build cost before you pay it: this crate
  embeds a WebAssembly runtime, so it pulls wasmtime and Cranelift, and a cold build takes
  minutes and a gigabyte. All three readers sat through it not knowing whether the build had
  hung. Both also now say the crate is host-only and will not build for `wasm32-unknown-unknown`.
- `MIN_ENTROPY_BYTES`, `MIN_SEAL_KEY_BYTES` and `MIN_PROJECTION_RANDOMNESS_BYTES` state their
  value in prose rather than only in the constant, and `MIN_SEAL_KEY_BYTES` now says that the
  length is enforced while the quality of the bytes is not and cannot be.
- `MIN_SEAL_KEY_BYTES` also says where to get a key. The docs told readers not to use a
  password without naming a way to produce a real key, and one reader had to guess a crate and
  version to make one.
- `recover_from_shares` documents that it takes three shares of the five, where `expected_root`
  comes from, and that a wrong sealing key surfaces as the sealed-blob error rather than a
  distinct variant.
- `README.md` gains the `[dependencies]` line it never had, and the crate documentation links
  `SECURITY-MODEL.md`, which was cited as required reading while being unreachable from any
  published page.
- `documentation` and `homepage` are set in the manifest. Neither was, so nothing pointed a
  reader from crates.io to docs.rs.

### Documentation

- **Verifying a presentation currently requires the issuer's secret seed**, which means any
  party that can verify can also issue. This is now stated in "What is not built anywhere"
  alongside the other gaps. Two readers found it independently and both re-read the pages twice
  assuming they had misunderstood the parameter; neither could tell whether it was intended.
  It is a limitation of the current `aethel-core` world rather than of the construction, and
  fixing it properly means issuer public parameters upstream.
- **`Presentation` has no serialised form**, though it is described as what the holder sends.
  Stated on the type. Together with the issuer-seed limitation, cross-party disclosure is not
  yet deployable, and saying so is better than letting a reader discover it while building.
- The README no longer opens by saying the crate "is planned as" and "is meant to give" before
  listing what runs today. It has run for several releases.
- "Runs today" no longer opens with `LICENSE`, `CI` and the other scaffolding. A reader
  scanning that list wants to know what they can call.

## [0.3.3] - 2026-09-06

The first release whose version does not match the `aethel-core` it embeds. That is deliberate
and is now policy: see [`STABILITY.md`](./STABILITY.md) section 6. The embedded revision is
recorded in `core/pin.toml` and stated in every release entry, which identifies the pair more
precisely than a matching number ever did. This release embeds `aethel-core` 0.3.2,
`a09787d67a120f1d8a81b41755acf1e75c8f3289`, unchanged from 0.3.2.

Four of the five verbs the SDK advertises now work: generate, sign and verify; project;
disclose; and recover. The quickstart and predicate proofs are what remain.

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
- `Identity::split_for_recovery()` and `Identity::recover_from_shares()`, authenticated 3-of-5
  HTSS recovery, with `RecoveryShare`, `RecoveryShareSet`, and the `InvalidRecoveryMaterial`
  error. What is split is the sealed identity blob rather than the raw signing key: the
  component never returns that, so the sealed representation is the only thing above L1 there
  is to split. Recovery consequently needs the original sealing key as well as a threshold of
  shares, which the README states up front.

  `recover_from_shares` takes the authenticating Merkle root as its own argument. The
  serialized envelope also carries a claimed root for transport, but that copy is treated as
  untrusted: a share set that supplies its own root can authenticate itself, which is what
  `aethel-core`'s `htss-split` documentation means when it says it does not vouch for the root.
  The root must be retained separately and passed in. Substitution, fabricated share content,
  duplicate indices, and oversized share sets are each rejected and each covered by a test.
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

### Added

- Offline generation is now proven in CI rather than asserted. The `offline generation
  (network-isolated)` job runs the suite inside a network namespace with no interface, and
  `tests/network_isolation_negative_control.rs` opens a real TCP connection that the job
  requires to **fail** there. Without that control, isolation silently ceasing to apply and
  isolation working look identical from a passing suite. Mirrors `aethel-core`'s proof of the
  same property, deliberately: the core proves its generation reaches nothing, and this proves
  the SDK around it did not introduce a fetch.

### Fixed

- The published package now contains `examples/`. The README tells the reader to run
  `cargo run --example projection` and `--example quickstart`, and neither was in the package,
  so that instruction could not be followed from what crates.io served. `scripts/` now also
  carries the comparison check and its allowlist, which `SECURITY-MODEL.md` names as the
  enforcement behind the timing claim: a claim you cannot inspect from the package you
  installed is worth less.

### Security

- `SECURITY-MODEL.md`, the published security model. It states what this crate claims and how
  each claim is checked, what the caller is responsible for (the sealing key as a single point
  of failure, storing the HTSS root apart from the shares, projection randomness, that
  authenticated is not confidential, entropy quality), and what is out of scope (side channels
  above L1, physical attacks, `aethel-runtime`, predicate proofs, and the correctness of
  `aethel-core`'s constructions). It says in its second paragraph that there has been no
  third-party audit, and it records why 0.1.0 and 0.1.5 were yanked.
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
