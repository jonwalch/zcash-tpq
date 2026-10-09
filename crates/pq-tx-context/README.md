# Prepared transaction context

This crate holds one immutable v5/v6 transaction and a shared list of previous outputs in input order.
It prepares the existing Zakura `SigHasher` once. It checks the reviewed NU7 version/branch/backend pair and input shape.
The `historical-test-vectors` feature admits saved earlier pairs only for tests.

The caller authenticates every previous output and its outpoint ordering. Shape checks and shared ownership do not authenticate UTXOs. The digest alone
does not bind the network; the authorization method supplies domain framing.
This crate does not classify scripts, verify signatures or enforce budgets.

`accounting` provides checked output serialization sizes. These byte counts do
not establish memory, CPU or admission budgets.

Focused checks from the repository root:

```sh
cargo test --locked -p zakura-pq-tx-context
cargo test --locked -p zakura-pq-tx-context --features historical-test-vectors
```
