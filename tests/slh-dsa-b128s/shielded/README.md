# Shielded effects in SLH transparent signing messages

These offline controls compare the SLH transaction and input-signing contexts
against a separately parsed digest reference for v5/v6 at NU7. They reuse four
existing public shielded bundles and their field/collection mutation controls.
No signing implementation or proof generator is part of this target.

Run from the repository root:

```sh
cargo test -p zakura-pq-slh-dsa-b-exp --test shielded_digest_controls --locked
cargo fmt -p zakura-pq-slh-dsa-b-exp -- --check
cargo clippy -p zakura-pq-slh-dsa-b-exp --all-targets --locked -- -D warnings
```

## Expected values and source attribution

[`reference.rs`](reference.rs) serializes each candidate and reparses it through
the pinned `zakura-primitives` 2.2.0 transaction parser. It builds a transparent
authorizing context from every supplied previous output, runs `TxIdDigester`
and `signature_hash`, and writes the
[`slh-dsa-b-128s-exp-v1` message](../../../docs/slh-dsa-b128s/protocol.md)
without importing SLH framing constants. Expected values never call Zakura's
`SigHasher`, native ZIP-244 cache, SLH transaction context or verifier.
Those are comparison targets only. Both paths share low-level hash, curve and
librustzcash-family dependencies; this is a separate digest/parser comparison,
not complete implementation independence.

[`sources.json`](sources.json) records the registry checksums and fixture pins.
The four hex files are unmodified encodings from the already retained upstream
[`ironwood_v6_tx_hash.rs`](../../../crates/zakura-chain/src/transaction/tests/ironwood_v6_tx_hash.rs)
cases `sapling_anchor_a`, `sapling_negative_value_balance`, `orchard_anchor_a`
and `ironwood_anchor_a`. That file attributes them to
`valargroup/zcash-test-vectors@16b5d0cee253e9947cbd9860f2ec2be1633d6484`,
`test-vectors/rust/ironwood_v6_tx_hash.rs`. Existing repository
[MIT](../../../LICENSE-MIT) / [Apache-2.0](../../../LICENSE-APACHE)
attribution and dependency license terms remain applicable.
The provenance test checks file/wire hashes and exact bytes against those
retained upstream cases. Their placeholder version-group and branch identifiers
are normalized in memory before reusing their bundles in new NU7 transactions.

## Bounded coverage

The 12 tests exercise both transparent input positions. The reference digest,
neutral prepared digest, native message and input-signing message must agree.

| Controls | Coverage |
| --- | --- |
| Pool combinations | All 3 nonempty v5 and 7 nonempty v6 combinations, including wire round trips |
| Effecting data | Sapling spends/outputs; Orchard and Ironwood actions; balances, nullifiers, commitments, keys, flags and every ciphertext region |
| Authorizing data | Proofs and spend/binding signatures excluded; Sapling/Orchard anchors committed in v5 and excluded in v6; Ironwood anchor excluded in v6 |
| Collections | Add, remove and reorder spends, outputs and actions; empty Sapling sides; remove/swap Orchard and Ironwood pools |
| Destinations | Five shapes with only shielded destinations, including Sapling outputs only |
| Transparent context | Every supplied amount, both input positions, network framing and wrong sighash modes; transparent authorization bytes excluded |
| Provenance | Four source file/wire hashes and exact upstream case encodings |

The field/collection loops contain 114 shielded mutations (94 effecting and
20 excluded), plus 4 excluded transparent authorization mutations. Context
controls add 36 comparisons for alternate modes, shielded-input digests,
input positions, supplied amounts and network domains.

The transactions use synthetic previous outputs and synthetic combinations of
public shielded bundles. These checks establish digest and message behavior;
they do not authenticate UTXOs, verify SLH authorizations for these shielded
shapes, verify zero-knowledge proofs or establish node acceptance. Existing
transparent signed-corpus controls remain separate. Valid shielded proofs,
failed-shielded-authorization accounting suppression and live consensus
acceptance require their respective runtime tests and human acceptance evidence.
