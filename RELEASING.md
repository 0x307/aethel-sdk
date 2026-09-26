# Releasing `aethel-sdk`

Publishing is deliberately manual. The release workflow does not publish, tag,
create releases, or yank crates.

## Before publishing

- Confirm the intended SDK version and finalize the release commit.
- Confirm the embedded `aethel-core` revision is the intended one. Re-run
  `scripts/sync-core.sh` when the core artifact needs to change.
- Verify `core/component.sha256` records the embedded component's SHA-256.
- Run the relevant SDK tests and `cargo fmt --check`.
- Run COR-9 package-content validation:
  `python3 scripts/validate-package.py --negative-control` and
  `python3 scripts/validate-package.py`.
- Confirm the package check is green on the exact release commit.
- Review `Cargo.toml` metadata and features. Credentials must remain opt-in
  behind `experimental-credentials`.
- Inspect the release notes and `CHANGELOG.md`.

## Publishing

1. Publish the finalized version by hand:
   `cargo publish`.
2. Confirm that exact immutable version is available on crates.io.
3. Create and push the matching release tag by hand, following the repository's
   tag convention (for example, `v0.8.0`).

## After publishing

1. Manually run **Post-publish smoke** (`post-publish-smoke.yml`) from the
   Actions UI.
2. Provide the exact crates.io version and its matching release tag.
3. Confirm the external, default-feature consumer completes identity generation,
   sealing and reopening, Multikey export, signing, independent verification,
   and both signature rejection controls.
4. Confirm its `DECLARED_COMPONENT_SHA256` equals the value read from
   `core/component.sha256` at the supplied tag.
5. Confirm the deliberately corrupted expected-hash negative control passes.

For local rehearsal against an already published version, obtain the expected
digest from the matching tag and run:

```bash
scripts/post-publish-smoke.sh 0.8.0 \
  6f87f48a00d65c1a130d0b739046ea2413cead4caf758c5cd5b1113017acd348
```

This is useful for reproducing the external-consumer procedure, but it does
not prove an unpublished future version. The manually triggered workflow is
the authoritative release verification.

## If post-publish smoke fails

Treat the published release as defective. Do not republish or overwrite its
immutable version, and CI must never yank it automatically.

1. Yank the defective crate version manually on crates.io.
2. Record the yank and its reason in `CHANGELOG.md`.
3. Fix the issue in a new version and repeat the manual pre-publish checks.
4. Publish the corrected version, push its matching tag, and rerun
   `post-publish-smoke.yml` for that exact version and tag.
