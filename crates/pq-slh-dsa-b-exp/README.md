# Experimental SLH-DSA-B-128s native authorization

This verifier-only crate implements `slh-dsa-b-128s-exp-v1`: the exact `53 20
<commitment> c0` template, all 120 policy shapes through 15-of-15, canonical
authorization parsing, trusted-context messages, reservation and real primitive
verification. The [protocol](../../docs/slh-dsa-b128s/protocol.md) defines the
bytes and Regtest-only integration requirements. This BLAKE3 construction is not
a FIPS 205 profile.

The caller supplies authenticated previous outputs in transaction input order.
`TransactionContext` prepares the shared digest once; neither this preparation
nor `input_authorization` establishes UTXO provenance. `reserve_input` binds the
policy and keys before invoking one atomic reservation callback. Its signature
boxes move into non-clonable checks, and verification failure does not refund a
reservation. Successful reservation alone does not authorize spending.

`InputSigningContext` exposes the derived message, verifies public partials and
assembles exactly the threshold number of them. It contains no secret keys,
signing, randomness, subprocess or fixture dependency. The runtime primitive
always receives the native 101-byte message and empty external Pure context.
The optional `test-observer` reports actual reservations and primitive calls; it
cannot replace verification results.

Focused offline checks, after registering the package in the root workspace:

```sh
cargo test -p zakura-pq-slh-dsa-b-exp --locked --features test-observer
cargo clippy -p zakura-pq-slh-dsa-b-exp --all-targets --locked --features test-observer -- -D warnings
```

Structural and failure tests are distinct from the independent signed corpus
and live-node acceptance. Node integration and human acceptance remain required
before advertising usable experimental runtime support.
