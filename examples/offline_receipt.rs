//! An agent signs a receipt; anyone holding its public key checks it later,
//! offline, with no call to 0x307. Referenced from docs/AGENT-IDENTITY.md.
//!
//!   cargo run --example offline_receipt -- sign   <dir>
//!   cargo run --example offline_receipt -- verify <dir>
//!
//! `sign` and `verify` are separate processes. `verify` reads only the three
//! files `sign` wrote and holds no identity and no sealing key. It exits
//! non-zero when the receipt does not verify.

use aethel_sdk::{public_key_from_multibase, verify_typed, Identity, Signature};
use std::{env, fs, path::Path, process::ExitCode};

fn sign(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(dir)?;
    let mut agent = Identity::generate()?;

    // What the agent did, for whom, and when. Plain bytes; the signature binds them.
    let statement = b"agent=7 action=delivered-report customer=A at=2026-09-30T12:00:00Z";
    let signature = agent.sign_typed(statement)?;

    fs::write(dir.join("statement.txt"), statement)?;
    fs::write(dir.join("signature.json"), signature.to_json()?)?;
    fs::write(dir.join("agent.multikey"), agent.public_key_multibase())?;
    println!("signed: wrote statement.txt, signature.json, agent.multikey to {}", dir.display());
    Ok(())
}

fn verify(dir: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    let statement = fs::read(dir.join("statement.txt"))?;
    let signature = Signature::from_json(&fs::read_to_string(dir.join("signature.json"))?)?;
    let key = public_key_from_multibase(fs::read_to_string(dir.join("agent.multikey"))?.trim())?;
    Ok(verify_typed(&key, &statement, &signature)?)
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let (mode, dir) = match (args.get(1), args.get(2)) {
        (Some(m), Some(d)) => (m.as_str(), Path::new(d)),
        _ => {
            eprintln!("usage: offline_receipt <sign|verify> <dir>");
            return ExitCode::from(2);
        }
    };
    let outcome = match mode {
        "sign" => sign(dir).map(|()| true),
        "verify" => verify(dir),
        _ => {
            eprintln!("usage: offline_receipt <sign|verify> <dir>");
            return ExitCode::from(2);
        }
    };
    match outcome {
        Ok(true) => {
            if mode == "verify" {
                println!("ok: receipt verifies");
            }
            ExitCode::SUCCESS
        }
        Ok(false) => {
            eprintln!("receipt does NOT verify");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("receipt rejected: {e}");
            ExitCode::FAILURE
        }
    }
}
