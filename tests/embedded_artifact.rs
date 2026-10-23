//! The package ships a compiled component and makes a claim about its bytes.
//! These tests check the claim, and check that the checking machinery can fail.
//!
//! The second half matters as much as the first. A hash comparison that has only
//! ever been run against matching inputs is not known to detect anything, and
//! this repo's initiative has already been bitten twice by a check that looked
//! like verification and could not fail. So every assertion of the form "the
//! artifact is correct" here is paired with a positive control that feeds the
//! same machinery an artifact that is known to be wrong.

use aethel_sdk::artifact;

/// The WebAssembly Component Model preamble: `\0asm` then layer `0x000d`.
/// A *core module* is the same magic with version `0x0001`, and shipping a core
/// module while calling it a component is exactly the drift this file guards.
const COMPONENT_PREAMBLE: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];
const CORE_MODULE_PREAMBLE: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

#[test]
fn the_artifact_is_embedded_not_empty() {
    assert!(
        !artifact::COMPONENT.is_empty(),
        "no component is embedded. core/aethel_core.component.wasm is empty or missing"
    );
}

/// The embedded bytes are a component, not a core module.
///
/// aethel-core shipped a wasm-bindgen core module for most of its life. If this
/// package ever picks that up by mistake it will still be a valid `.wasm` file,
/// it will still hash to something, and nothing else here would notice.
#[test]
fn the_artifact_is_a_component_not_a_core_module() {
    let head = &artifact::COMPONENT[..8];
    assert_ne!(
        head, CORE_MODULE_PREAMBLE,
        "the embedded artifact is a core module, not a Component Model component"
    );
    assert_eq!(
        head, COMPONENT_PREAMBLE,
        "the embedded artifact is not a WebAssembly component"
    );
}

/// The AC: a test asserts the artifact hash matches the one the package declares.
#[test]
fn the_embedded_artifact_matches_the_declared_hash() {
    if let Err(mismatch) = artifact::verify_embedded() {
        panic!(
            "the embedded component is not the artifact this package declares.\n  \
             declared: {}\n  actual:   {}\n\
             Rebuild with scripts/sync-core.sh, which rewrites both.",
            mismatch.declared, mismatch.actual
        );
    }
}

/// Positive control for the test above.
///
/// Substitute one byte of the artifact and the check must fail. Without this,
/// `verify_embedded` passing tells us nothing: a function that returned `Ok(())`
/// unconditionally would look identical.
#[test]
fn a_substituted_artifact_is_rejected() {
    let mut tampered = artifact::COMPONENT.to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;

    let err = artifact::verify(&tampered).expect_err(
        "a component with a flipped byte passed the hash check. The check cannot \
         detect a substituted artifact and is worthless",
    );
    assert_eq!(err.declared, artifact::declared_sha256());
    assert_ne!(err.actual, err.declared);
}

/// Positive control, second form: a wholly different artifact, not a bit flip.
#[test]
fn an_unrelated_artifact_is_rejected() {
    let err = artifact::verify(&CORE_MODULE_PREAMBLE)
        .expect_err("an eight-byte stub passed the hash check");
    assert_ne!(err.actual, err.declared);
}

/// The declared hash is a real SHA-256 and not, say, a truncated paste.
#[test]
fn the_declared_hash_is_well_formed() {
    let declared = artifact::declared_sha256();
    assert_eq!(
        declared.len(),
        64,
        "declared hash is not 64 hex characters: {declared}"
    );
    assert!(
        declared
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "declared hash is not lowercase hex: {declared}"
    );
}

/// Positive control for the hash function itself, against a value that does not
/// come from this codebase: the SHA-256 of the empty string.
#[test]
fn the_digest_agrees_with_a_known_answer() {
    assert_eq!(
        artifact::sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

/// The pin is readable and identifies a specific aethel-core commit. "Which
/// source produced this binary" has to have an answer for the rebuild
/// instructions to mean anything.
#[test]
fn the_pinned_revision_is_a_full_commit_sha() {
    let rev = artifact::core_revision();
    assert_eq!(rev.len(), 40, "pinned rev is not a full commit sha: {rev}");
    assert!(
        rev.chars().all(|c| c.is_ascii_hexdigit()),
        "pinned rev is not hex: {rev}"
    );
}

/// What is wrong with the manifest's aethel-core pin, if anything.
///
/// A function rather than inline asserts so the control below can show it says
/// no. The pin must be exact (`"=X.Y.Z"`) and come from crates.io: a range lets
/// the comparison target move under the execution proof, and a git source is the
/// arrangement this replaced. A manifest with no pin at all is a problem too, so
/// deleting the line cannot make the check pass.
///
/// It reads both forms the pin takes. The repository's manifest writes it on
/// one line, `aethel-core = "=X.Y.Z"`. `cargo package` normalizes that into a
/// table, `[...dev-dependencies.aethel-core]` followed by `version = "=X.Y.Z"`,
/// and that is the manifest a crates.io user's copy of this test reads. Reading
/// only the one-line form failed every packaged run, 0.9.0's included.
fn aethel_core_pin_problem(manifest: &str) -> Option<String> {
    let live = |line: &&str| !line.trim_start().starts_with('#');
    if manifest
        .lines()
        .filter(live)
        .any(|l| l.contains("git = \""))
    {
        return Some("the manifest has a git source".into());
    }
    let quoted = |line: &str| line.split('"').nth(1).unwrap_or("").to_string();

    // One entry per aethel-core dependency found. A table form starts as None
    // and stays None if the table has no `version` key.
    let mut requirements: Vec<Option<String>> = Vec::new();
    let mut in_aethel_core_table = false;
    for line in manifest.lines().filter(live) {
        let line = line.trim();
        if line.starts_with('[') {
            let header = line.split('#').next().unwrap_or("").trim_end();
            in_aethel_core_table = header.ends_with("dependencies.aethel-core]");
            if in_aethel_core_table {
                requirements.push(None);
            }
        } else if in_aethel_core_table {
            let is_version = line
                .strip_prefix("version")
                .is_some_and(|rest| rest.trim_start().starts_with('='));
            if is_version {
                if let Some(last) = requirements.last_mut() {
                    *last = Some(quoted(line));
                }
            }
        } else if line.starts_with("aethel-core = ") {
            requirements.push(Some(quoted(line)));
        }
    }

    if requirements.is_empty() {
        return Some("the manifest has no aethel-core dependency".into());
    }
    for requirement in requirements {
        let Some(requirement) = requirement else {
            return Some("the aethel-core dependency table has no version".into());
        };
        let exact = requirement.strip_prefix('=').is_some_and(|v| {
            let parts: Vec<&str> = v.split('.').collect();
            parts.len() == 3
                && parts
                    .iter()
                    .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        });
        if !exact {
            return Some(format!(
                "aethel-core is required as {requirement:?}, not an exact =X.Y.Z"
            ));
        }
    }
    None
}

/// The aethel-core dev-dependency is an exact crates.io pin, not a git source.
///
/// `tests/component_execution.rs` compares the embedded component against
/// aethel-core's native API. The old arrangement pinned a git `rev` that had to
/// equal `core/pin.toml`'s, and drifted at the 0.4.0 migration. It is replaced
/// by an exact release, with the agreement checked by bytes in
/// `tests/core_provenance.rs` (`aethel_core::COMPONENT_SHA256` against the
/// vendored digest), which a label comparison never could.
///
/// The control half shows the check can fail: a git source, a range, a partial
/// version and a missing pin are each refused, next to the real manifest being
/// accepted. The same holds for the table form `cargo package` writes: an exact
/// version is accepted, and a range, a git source or no version is refused.
#[test]
fn the_aethel_core_dev_dependency_is_an_exact_crates_io_pin() {
    let manifest = include_str!("../Cargo.toml");
    assert_eq!(
        aethel_core_pin_problem(manifest),
        None,
        "the aethel-core dev-dependency is not an exact crates.io pin"
    );

    let git =
        "aethel-core = { version = \"0.7\", git = \"https://example.invalid/x\", rev = \"abc\" }";
    assert!(
        aethel_core_pin_problem(git).is_some(),
        "a git source was accepted"
    );
    assert!(
        aethel_core_pin_problem("aethel-core = \"0.7\"").is_some(),
        "a range was accepted"
    );
    assert!(
        aethel_core_pin_problem("aethel-core = \"=0.7\"").is_some(),
        "a partial version was accepted"
    );
    assert!(
        aethel_core_pin_problem("# aethel-core = \"=0.7.4\"").is_some(),
        "a missing pin was accepted"
    );

    // The normalized form, as `cargo package` writes it into the .crate.
    let table = |body: &str| {
        format!(
            "[dev-dependencies.multibase]\nversion = \"0.9\"\n\n\
             [target.'cfg(not(target_arch = \"wasm32\"))'.dev-dependencies.aethel-core]\n\
             {body}\n\n[features]\nversion = \"0.1\"\n"
        )
    };
    assert_eq!(
        aethel_core_pin_problem(&table("version = \"=0.7.5\"")),
        None,
        "the packaged table form with an exact version was refused"
    );
    assert!(
        aethel_core_pin_problem(&table("version = \"0.7\"")).is_some(),
        "a range in the table form was accepted"
    );
    assert!(
        aethel_core_pin_problem(&table(
            "version = \"=0.7.5\"\ngit = \"https://example.invalid/x\""
        ))
        .is_some(),
        "a git source in the table form was accepted"
    );
    assert!(
        aethel_core_pin_problem(&table("default-features = false")).is_some(),
        "the table form with no version was accepted"
    );
}
