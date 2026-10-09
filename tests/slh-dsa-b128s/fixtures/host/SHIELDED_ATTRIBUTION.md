# Shielded fixture source reuse

The optional `shielded-fixtures` operations are public human-run test tooling
under MIT OR Apache-2.0, with the existing project licenses. They add no node or
wallet dependency edge. The construction source is `jonwalch/zcash-transparent-pq`
revision `e759cb86a06510893f8e7d1eb986b7025401c8c9`:

| Source at that revision | SHA-256 | Selective reuse |
| --- | --- | --- |
| `node/zakura/crates/zakura-consensus/examples/pq_ironwood_fixture.rs` | `648a989db129ffbfff768dc5e9e8796023d237f207745de76cc7a698400b7b21` | Canonical action conversion through the node parser; real public output proof; temporary authorization, full-effect sighash, final binding; valid proof donor and wrong-digest binding variants; same-TXID checks |
| `node/tests/mixed_traffic_fixture/src/main.rs` | `7656ccc6f1a8b709a7bd0e56e043657f07e213dc2a57eec20d64b2b34d6f9475` | Output-only deposit, disabled-spend empty anchor and public local proof batch verification concepts only; no note-count workload, witness/payment loop or benchmark imported |
| `node/zakura/crates/zakura-consensus/benches/sapling.rs` | `3157b7dec0e7d2cae7914c3d829c6141a4a03041a942807b4ad9a4d9da0eed8b` | Narrow existing LocalTxProver verifying-keys and Sapling BatchValidator verification sequence only; no Criterion or measurement code |

`shielded.rs` adapts this mechanism to one authenticated transparent parent,
one change output, bounded two-output/action bundles, all three pools and the
existing external public SLH signer. It does not import research mixed classical/PQ
inputs, obsolete funding coinbases, PQ signing code, or caller-selected backends.
The fixed shielded recipient key `[42;32]` remains public test material.

The Sapling output builder and canonical output-description conversion are new
narrow glue using the existing pinned `zakura-sapling-crypto =2.2.0` API. Sapling
has no proof-construction implementation in the referenced research benchmark;
its builder, `create_proofs` and `apply_signatures` APIs are used directly instead
of implementing cryptography. The parameter loader directly reuses
`zakura-proofs =2.2.0::LocalTxProver::from_bytes`, including its established
parameter hashes, after bounded reads and explicit SHA-256 correspondence.
Only `local-prover` is enabled; no download or default-path operation is called.
Its optional directory dependencies are a library feature requirement, not
permission to search for or fetch parameters.

Orchard/Ironwood use pinned `zakura-orchard =2.2.0`, `BundleVersion::{orchard_v3,
ironwood_v3}`, and `OrchardCircuitVersion::PostNu6_3`. Zero Orchard value and disabled
cross-address transfers preserve pinned upstream NU6.3/NU7 rules. Spend/anchor
construction remains outside this adapter. The independent shielded digest corpus
is unchanged and is not used as an accepting real-proof fixture.

`controls.rs` adds one explicit feature-gated `shielded-block` entry to its existing
header/fee/auth-root construction, limited to one transparent input and bounded
output-only bundles. The original `control-block` remains transparent-only.
`main.rs`/`model.rs` extend the existing strict schema and public operation envelope.
`shielded_controls.py` reuses the existing strict fixture transport, build receipt,
classical signing, mature coinbase authentication, UTXO agreement, exact block
replay and source/binary checks. The driver adapts the research
`node/tests/pq_ironwood_live.py` positive/negative state-preservation flow to legal
mature parents, all-SLH inputs, two peerless nodes and exact expected diagnostics.
The Python fake chain and Rust validation tests are new offline causal checks.

Research `benches/pq_measurements/shielded.rs` (SHA-256
`0f1feecaeed2f5f7dc1b084afbc961ef98197398e40eeaa953ad6f01e140e129`) was inspected
first but only verifies unchanged historical mainnet transactions. It supplies
no construction source and none of its measurement wrapper is imported.
The pinned upstream revision remains
`9b175e9d3d46a6aa4cfb5552517c3d828852ecbc`; registry checksums remain bound by
`Cargo.lock`. See the [public guide](../../../../docs/slh-dsa-b128s/shielded-controls.md)
for executable human commands, evidence limits and exact pending scope.
