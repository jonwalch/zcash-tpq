# Native SLH authorization

This verifier-only crate implements `slh-dsa-b-128s-exp-v1`.
It supports the exact `53 20 <commitment> c0` template and all 120 policies through 15-of-15.
It parses canonical authorizations, constructs messages, reserves checks, and verifies signatures.
The [protocol](../../docs/slh-dsa-b128s/protocol.md) specifies bytes and Regtest integration.
This experimental BLAKE3 construction is not a FIPS 205 profile.

The caller must authenticate previous outputs and supply them in input order.
`TransactionContext` prepares the shared digest once.
Neither preparation nor `input_authorization` establishes UTXO provenance.
`reserve_input` binds policies and keys before one atomic reservation callback.
Signature boxes move into checks that cannot be cloned.
Failure does not refund a reservation. Reservation alone does not authorize a spend.

`InputSigningContext` exposes the derived message, verifies partials, and assembles exactly the required threshold.
It contains no secrets, signer, randomness, subprocess, or fixture dependency.
The primitive receives the 101-byte message and empty Pure context.
The optional `test-observer` reports reservations and calls but cannot replace verification results.

Run focused checks from the repository root:

```sh
cargo test -p zakura-pq-slh-dsa-b-exp --locked --features test-observer
cargo clippy -p zakura-pq-slh-dsa-b-exp --all-targets --locked --features test-observer -- -D warnings
```

Structural tests and the independent signed corpus cover separate properties.
Node integration is implemented behind the feature, which is off by default.
Live acceptance remains open.
