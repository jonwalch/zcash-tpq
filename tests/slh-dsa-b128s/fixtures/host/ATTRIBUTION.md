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

The original behavior is the strict, bounded, public-only fixture interface
specified in `docs/slh-dsa-b128s/transaction-fixtures.md`, its deterministic
18-case producer and source/binary receipts. These operations hold only public
keys, signatures, transactions and explicitly synthetic previous outputs. The
host never spawns a signer. The Python producer invokes the
separate pinned signer only for prescribed public test material. Unit controls
exercise transport bounds, canonical JSON, ordered recipes, complete decoding,
invalid assembly, exact profile classification and absence of secret-bearing
fields in output. Independent digest/crypto acceptance is a separate checker.

The acceptance extension also implements `classical-info`, `classical-spend`,
`mixed-prepare`, `mixed-assemble` and `control-block`, documented in
[`acceptance.md`](../../../../docs/slh-dsa-b128s/acceptance.md) and
[`lifecycle-controls.md`](../../../../docs/slh-dsa-b128s/lifecycle-controls.md).
`classical.rs` adapts `examples/pq_regtest_fixture/nu7.rs::legacy_scripts` and
`examples/pq_regtest_fixture/relay.rs::legacy_signature` from the same pinned
research revision. It uses fixed **public test secret scalars** 91, 92 and 93,
each repeated 32 times. It supports the retained P2SH CHECKSIG and an explicit
2-of-3 CHECKMULTISIG control with the required dummy/minimal PUSHDATA1 redeem
script push. Those public scalars are never suitable for real funds. No API
accepts an operational secret key.

`controls.rs` reuses the pinned transparent `examples/pq_regtest_fixture.rs::block`
and `nu7.rs::miner_fees` patterns for exact block candidates; it reuses the
existing native SLH context and isolated public signer for mixed-input controls.
It neither creates shielded proofs nor imports other PQ backends. Source/target
hashes and adaptations are recorded in [`acceptance/sources.json`](../../acceptance/sources.json). Parent bytes
received by any helper are untrusted: human drivers authenticate actual mature
outpoints, values, scripts and chain tips through both nodes before use.

The transparent controls in `transparent.rs` adapt the authorization-only
mutation from pinned research
`node/zakura/crates/zakura-consensus/src/transaction/pq_test_support.rs::bad_pq`.
They use the existing SLH codec to preserve effects/TXID while corrupting a
signature, and add narrow public multisig quorum and signature-family substitution
cases. No alternate backend is imported. `control-funding` reuses the same public
classical signer and adds exact unsupported `0x51`/`0x52` templates only for these
negative cases. Ordinary `classical-spend` remains unchanged. Both-order mixed
controls and NU7 pre-SLH block construction reuse `controls.rs`; explicit height
105–109 coverage is an adaptation for retaining genuine funding across rollback.
See [transparent-controls.md](../../../../docs/slh-dsa-b128s/transparent-controls.md).

The optional `shielded.rs` helper selectively adapts real bundle constructors
from the same pinned research revision's `node/tests/mixed_traffic_fixture/src/main.rs`,
`examples/pq_ironwood_fixture.rs`, plus Sapling batch-validation calls from
`benches/sapling.rs`, as detailed in [SHIELDED_ATTRIBUTION.md](SHIELDED_ATTRIBUTION.md)
and the shared source map. It uses the existing pinned Zakura proof
libraries, explicit local Sapling parameters and the public fixture signer.
It adds output-only real proof/binding controls, with zero-valued Orchard outputs
under inherited NU7 rules; no workload or benchmark machinery is imported.
`controls.rs` exposes a separate shielded block operation while retaining the
ordinary transparent-only operation. The independent synthetic shielded digest
reference and original corpus remain unchanged. Agents must obtain user approval
before proof generation and live node validation under [AGENTS.md](../../../../AGENTS.md).
Source preparation is not acceptance.
