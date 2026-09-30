# Running an agent identity

The README shows the calls. This guide shows how to run an identity: keep it across restarts,
decide whom to trust, and hand someone a receipt they can check later without calling anyone.

Every Rust block below is compiled as a doctest, and the two examples run in CI, so this guide
cannot drift from the API.

## Persistence

Generate once, seal the identity, store the sealed blob, and open it at startup.

```rust
use aethel_sdk::Identity;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut identity = Identity::generate()?;

    // The sealing key must be 32 bytes of high-entropy key material, NOT a password.
    let sealing_key = [7u8; 32]; // stand-in: load yours from wherever you keep secrets
    let sealed = identity.export_sealed(&sealing_key)?;
    // ... write `sealed` to disk or a database ...

    // At the next startup:
    let restored = Identity::open_sealed(&sealed, &sealing_key)?;
    assert_eq!(restored.public_key(), identity.public_key());
    Ok(())
}
```

**What the sealing key is.** It encrypts and authenticates the stored blob. It is not the
identity's signing key and never leaves your process. It belongs wherever you already keep
secrets for this agent: an OS keystore, a secrets manager, a hardware module. Keep it apart
from the sealed blob, or sealing adds nothing.

**If it is lost.** The blob cannot be opened and the identity is gone. Plan for that before it
happens: `Identity::split_for_recovery` turns the identity into five authenticated shares, any
three of which recover it with `Identity::recover_from_shares`. Give the shares to different
custodians.

**Never** store the unsealed secret, and never have a service hold it for the agent. The SDK
does not expose it: signing happens inside the embedded component.

## Publishing the key

The agent's public identifier is its Multikey string, a W3C Multikey that names the algorithm.

```rust
use aethel_sdk::{public_key_from_multibase, Identity};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let identity = Identity::generate()?;
    let multikey = identity.public_key_multibase();

    // Anyone can decode it and learn the algorithm and key bytes.
    let key = public_key_from_multibase(&multikey)?;
    assert_eq!(key.as_bytes(), identity.public_key());
    Ok(())
}
```

What it proves: that whoever signs with the matching private key controls this identity. What
it does not prove: who that is, or that they are authorised to do anything. A valid signature
from an unknown key means only that someone holds that key.

If you would otherwise reuse this identifier with several unrelated parties, do not. A single
identifier lets them correlate the agent. Use `Identity::project_at` to present a fresh,
context-bound projection to each one instead.

## Trusting a signer

Trust is the verifier's decision. A verifier keeps its own allowlist of Multikey strings and
accepts a signature only when it is valid and its key is on that list. There is no registry
run by us. See `examples/trusted_signer.rs`: two identities, a verifier that trusts one of
them, and a run that fails if the trusted one is refused or the untrusted one is accepted.

```sh
cargo run --example trusted_signer
```

## Offline receipts

An agent signs a statement of what it did, for whom and when. Anyone holding the agent's
public key can verify it later, offline, with no call to 0x307. See
`examples/offline_receipt.rs`. Signing and verifying are separate processes, and verifying
reads only files:

```sh
cargo run --example offline_receipt -- sign   ./receipt
cargo run --example offline_receipt -- verify ./receipt
```

Change one byte of `receipt/statement.txt` and `verify` exits non-zero.

## What this does not do yet

- Purpose-separated signing is not on the SDK surface. `sign` and `sign_typed` sign under the
  empty context, so use one key for one kind of statement until it is.
- Credentials are experimental and off by default (`experimental-credentials`). Do not rely
  on them.
