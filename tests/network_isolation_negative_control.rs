//! Negative control for the offline-generation CI proof (P5-05).
//!
//! This test deliberately makes a real outbound network connection. It is
//! **expected to fail** under the `offline-generation` CI job's
//! network-isolated step, and that failure is the proof the isolation is real.
//!
//! An in-process "am I offline?" assertion can only observe the paths it knows
//! to instrument, so it would pass even if some dependency three levels down
//! still had a route out. This crate embeds a WebAssembly runtime and a
//! compiled component, which is exactly the shape where that matters: the
//! claim is that generating an identity reaches nothing, and the layers
//! underneath it are not ones an assertion in this crate can see.
//!
//! Denying the capability at the boundary is the only proof that holds. See
//! `.github/workflows/ci.yml`, job `offline-generation`, which runs the suite
//! inside a network namespace with no interface and then runs this test there
//! and requires it to fail. If this test ever *passes* inside that isolated
//! step, the isolation has silently broken and the "generation works offline"
//! claim in the README is unproven; the step inverts this test's result
//! specifically to catch that.
//!
//! Mirrors `aethel-core`'s test of the same name, deliberately. The proof
//! belongs at both layers: the core proves its own generation reaches nothing,
//! and this proves the SDK wrapped around it did not introduce a fetch.

#![cfg(not(target_arch = "wasm32"))]

use std::net::TcpStream;
use std::time::Duration;

/// Attempts a real outbound TCP connection to a public host, by IP literal so
/// there is no DNS dependency. Expected to succeed whenever a route exists,
/// and to fail (`Network is unreachable`, or a timeout) inside a network
/// namespace with no interface.
#[test]
fn network_call_succeeds_when_a_route_exists() {
    let addr = "1.1.1.1:443"
        .parse()
        .expect("literal socket address must parse");

    let result = TcpStream::connect_timeout(&addr, Duration::from_secs(5));

    assert!(
        result.is_ok(),
        "expected outbound TCP connect to {addr} to succeed (no network isolation active); \
         got error: {:?}. If this failure happened inside the offline-generation CI job's \
         isolated step, that is the *expected*, desired outcome — see ci.yml.",
        result.err()
    );
}
