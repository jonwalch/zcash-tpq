# Source reuse and scope

This test-only adapter reuses the MIT/Apache-2.0 `zakura-pq-test-support`
`TransactionRecipe`, ordered `Spend` and `install` helpers, the native SLH
`Policy`, prepared/signing context, authorization encoder and verifier, and
upstream Zakura's serialization and transaction hash display conversion.
Their source provenance and licenses remain beside the respective crates.

The small complete-consumption decoding and sorted-commitment signer association
patterns are adapted from `jonwalch/zcash-transparent-pq` commit
`e759cb86a06510893f8e7d1eb986b7025401c8c9`,
`experiments/hash-four-payments/common/src/payment.rs`. Recursive canonical JSON
key ordering extends the explicit `BTreeMap` technique from that revision's
`crates/pq-experiment-support/src/catalog.rs`. Both sources carry the project's
MIT OR Apache-2.0 license. No experiment catalog, lifecycle, timing machinery,
backend loader, alternate scheme or source-checkout dependency is imported.

New behavior is limited to the strict, bounded, public-only fixture interface
specified in `docs/slh-dsa-b128s/transaction-fixtures.md`, its deterministic
18-case producer and source/binary receipts. The host holds only public keys,
signatures, transactions and explicitly synthetic previous outputs. It never
spawns a signer or processes secret material. The Python producer invokes the
separate pinned signer only for prescribed public test material. Unit controls
exercise transport bounds, canonical JSON, ordered recipes, complete decoding,
invalid assembly, exact profile classification and absence of secret-bearing
fields in output. Independent digest/crypto acceptance is a separate checker.
