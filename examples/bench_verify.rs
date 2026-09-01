//! Hot-path cost measurement for the verifier side (spec Q3).
//!
//! SAGP is a gateway: it verifies on the request path. The design question is
//! whether per-request presentation is viable, or whether the integration needs
//! a session model (verify once, issue a short-lived bearer token) that
//! reintroduces exactly the correlatable identifier Aethel exists to avoid.
//!
//! The decomposition that matters: `verify_presentation` and `verify` both call
//! `component::load()` internally, so every verification pays for a fresh
//! `Store` and a fresh instantiation. Neither pays for a fresh wasmtime Engine
//! or a fresh compile of the component any more — those are amortised across
//! the process behind `component::shared()`, and holding a `Verifier` moves
//! even that first-use compile to construction time. That is an SDK structure
//! cost, not a cost of the cryptography. This measures both so the two can be
//! told apart, and adds a case that holds one `Verifier` across N
//! verifications alongside the existing free-function case.
//!
//!   cargo run --release --example bench_verify

use aethel_sdk::{component, verify, verify_presentation, Identity, Verifier};
use std::time::{Duration, Instant};

const WARMUP: usize = 3;

fn bench<F: FnMut()>(label: &str, iters: usize, mut f: F) -> Duration {
    for _ in 0..WARMUP {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let total = start.elapsed();
    let per = total / iters as u32;
    println!("{label:<46} {per:>12.3?}  (n={iters})");
    per
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\naethel-sdk verifier hot-path cost");
    println!("{}", "=".repeat(74));
    println!("build: {}\n", if cfg!(debug_assertions) { "DEBUG (numbers are not meaningful, use --release)" } else { "release" });

    // ---- setup, not measured ------------------------------------------------
    let issuer_seed = b"the issuer's secret seed, 32 byte";
    let context = b"checkout-session";

    let mut identity = Identity::generate()?;
    let message = b"the message that was actually signed";
    let signature = identity.sign(message)?;
    let public_key = identity.public_key().to_vec();

    let credential =
        identity.issue_credential(issuer_seed, &[("tier", 3), ("date_of_birth", 19_900_101)])?;
    let presentation = identity.present(&credential, context, &["tier"])?;

    // Sanity: the thing we are timing must actually succeed.
    assert!(verify_presentation(issuer_seed, &presentation, context)?);
    assert!(verify(&public_key, message, &signature)?);

    // ---- 1. compile vs instantiate -----------------------------------------
    // Runtime::new() compiles (Cranelift over 1.8 MB). load() reuses the
    // process-wide compilation and only instantiates. Before Q3 Fix 1 these
    // were the same call and every verify paid the compile.
    println!("-- compile (once per process) vs instantiate (per call) --");
    let compile = bench("Runtime::new()         [Cranelift compile]", 5, || {
        let _ = component::Runtime::new().expect("compile");
    });
    let load = bench("component::load()      [instantiate only]", 20, || {
        let _ = component::load().expect("load");
    });
    println!("  compile is amortised across the process, not per call");
    let _ = compile;

    // ---- 2. verifier operations, end to end (load + crypto) ----------------
    println!("\n-- verifier path as SAGP would call it today --");
    let e2e_pres = bench("verify_presentation()  [load + crypto]", 20, || {
        let ok = verify_presentation(issuer_seed, &presentation, context).expect("verify");
        assert!(ok);
    });
    let e2e_sig = bench("verify()               [load + crypto]", 20, || {
        let ok = verify(&public_key, message, &signature).expect("verify");
        assert!(ok);
    });

    // ---- 2b. the same two operations through a held Verifier ---------------
    // Same runtime, same per-call instantiate. Verifier::new() is what SAGP
    // would call once at startup instead of paying the first-use compile on
    // whichever request happens to land first.
    println!("\n-- same operations through a Verifier constructed once --");
    let verifier = Verifier::new()?;
    let verifier_pres = bench("Verifier::verify_presentation()", 20, || {
        let ok = verifier
            .verify_presentation(issuer_seed, &presentation, context)
            .expect("verify");
        assert!(ok);
    });
    let verifier_sig = bench("Verifier::verify()", 20, || {
        let ok = verifier.verify(&public_key, message, &signature).expect("verify");
        assert!(ok);
    });
    println!(
        "  per-verification cost should match the free-function case above: {:>10.3?} vs {:>10.3?} (presentation)",
        e2e_pres, verifier_pres
    );
    println!(
        "  per-verification cost should match the free-function case above: {:>10.3?} vs {:>10.3?} (signature)",
        e2e_sig, verifier_sig
    );

    // ---- 3. prover operations on a warm instance (crypto only) -------------
    // `Identity` owns its Store, so these do NOT reload the component. They are
    // a direct read on what the lattice work costs with instantiation amortised.
    println!("\n-- prover path on a warm instance (crypto only, no load) --");
    let warm_present = bench("present()              [crypto only]", 20, || {
        let _ = identity.present(&credential, context, &["tier"]).expect("present");
    });
    let warm_sign = bench("sign()                 [crypto only]", 20, || {
        let _ = identity.sign(message).expect("sign");
    });

    // ---- 4. the decomposition ----------------------------------------------
    let crypto_pres = e2e_pres.saturating_sub(load);
    let crypto_sig = e2e_sig.saturating_sub(load);

    println!("\n{}", "=".repeat(74));
    println!("DECOMPOSITION (end-to-end minus instantiation)\n");
    println!("  instantiation, per call                     {load:>12.3?}");
    println!("  verify_presentation, crypto only (derived)  {crypto_pres:>12.3?}");
    println!("  verify_signature,    crypto only (derived)  {crypto_sig:>12.3?}");
    println!("  present,             crypto only (measured) {warm_present:>12.3?}");
    println!("  sign,                crypto only (measured) {warm_sign:>12.3?}");

    let pct = if e2e_pres.as_nanos() > 0 {
        (load.as_nanos() as f64 / e2e_pres.as_nanos() as f64) * 100.0
    } else {
        0.0
    };
    println!("\n  instantiation is {pct:.1}% of verify_presentation now");

    let rps_now = 1.0 / e2e_pres.as_secs_f64();
    let rps_pooled = if crypto_pres.as_secs_f64() > 0.0 {
        1.0 / crypto_pres.as_secs_f64()
    } else {
        f64::INFINITY
    };
    println!("\n  single-core verifications/sec, pooled        {rps_now:>10.0}");
    println!("  single-core verifications/sec, if pooled    {rps_pooled:>10.0}");
    println!("{}", "=".repeat(74));

    Ok(())
}
