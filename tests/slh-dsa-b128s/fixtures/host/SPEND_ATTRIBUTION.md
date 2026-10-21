# Shielded spend fixture attribution

This optional public test tooling uses the repository's MIT OR Apache-2.0
licenses. It selectively adapts the following files from
`jonwalch/zcash-transparent-pq` revision
`e759cb86a06510893f8e7d1eb986b7025401c8c9`; upstream Zakura remains pinned at
`9b175e9d3d46a6aa4cfb5552517c3d828852ecbc`.

| Pinned research source | SHA256 | Use |
| --- | --- | --- |
| `node/zakura/crates/zakura-consensus/examples/pq_ironwood_spend_fixture.rs` | `8b1a0e0bb0abd1f0945c270f11a330f601c9675da900091d17c84e37bd3a03db` | Real note/path builder, metadata real-spend index, temporary then full-effect signatures, wrong-digest authorization, real donor proof, full-transaction field repair and unchanged digest/TXID checks |
| `node/zakura/crates/zakura-consensus/examples/pq_ironwood_spend/history.rs` | `ad80f4dd6f3ae1dd0c760d83bb43c5466d46f2f7da1585a7c644e0eed9d5e577` | Bounded canonical contiguous Regtest history, actual ordered funding prevouts, fixed-public-key decryption, commitment position and later-leaf witness, node/export root agreement, scanned nullifier and unspent parent boundary; position/malformed-leaf tests |
| `node/zakura/crates/zakura-consensus/examples/pq_ironwood_spend_state.rs` | `93581188733137a5a91aa00344d9ba5fb9a496e94370a9d2c9a0bf280507aece` | Inspected as reference for distinguishing contextual refusal from internal nullifier membership; no state-replay or node code imported |

`shielded_spend/history.rs` preserves the research trust boundary and strengthens
transport/allocation and duplicate limits. It generalizes the same position-based
witness to Sapling via the pinned library's `CommitmentTree`/`IncrementalWitness`
APIs. It accepts separate real note and transparent funding transactions so
nullifier controls can use an independently available transparent parent.
History is supplied by a trusted node export, not treated as independent consensus
verification. It never accepts caller amount/script fields as chain authority.
The research helper handles Ironwood only. The Sapling adaptation also reuses
the pinned node's `sapling::tree::Root::bytes_in_display_order`, as used by
`zakura-rpc/src/methods.rs::z_get_treestate`, to compare RPC-display roots during
recovery and finalization. Sapling reverses canonical anchor bytes for this RPC;
the research Ironwood convention is unchanged. Proof-free regressions use the
actual per-pool RPC conversions and reject internal-order or altered Sapling
roots, while exercising v5/v6 finalization correspondence with explicit invalid
shielded proof/signature placeholders.

`shielded_spend.rs` generalizes the research Ironwood construction to the supported
v5/v6 pool subsets. It reuses current `shielded.rs` canonical bundle adapters,
parameter loader, whole-effect digest, batch checks and transaction wire adapter.
The existing authorization step is narrowly shared between output and spend
finalizers; no signing implementation or operational-key interface is added.
Sapling spends extend the existing canonical output adapter with the node's
`SpendPrefixInTransactionV5` parser and `Spend::from_v5_parts`.

With upstream Zakura at `e33dc43089acca2fe2c6516927932f2b7618b8bc`, Common 3
can verify historical Orchard circuits but cannot build their proofs. The optional
fixture host therefore retains `zakura-orchard =2.2.0` as `orchard_legacy` only for
pre-NU6.3 funding. Current output and spend builders use Common 3 and propagate
its proving-key errors. Both Orchard versions use the existing canonical bundle
conversion. The history regression builds ciphertext with invalid proof and
signature placeholders, then checks decoding, public-note recovery and finalization
with current node types. It does not generate or verify a real proof. The dependency
guard rejects the historical builder in default and SLH-enabled node graphs.

With upstream Zakura at `3f36c35031126a8f8cd52865ef0be9e5dc494b8d`,
the current fixture builders and `zakura-proofs` use Common 4. The optional
host enables `zip32-addresses` for its fixed public Orchard and Sapling recipients;
node dependency settings stay unchanged. The historical Orchard builder remains
at 2.2.0. A compile check with
`shielded-fixtures` checks this adaptation without generating real proofs.

New narrow glue uses pinned `zakura-sapling-crypto =2.2.0` builders, note decryption,
`CommitmentSum` binding verification and LocalTxProver, and
`zakura-orchard =2.2.0` builders/note decryption/verifiers. No cryptography is
reimplemented. The sole new direct witness dependency is the existing workspace
`incrementalmerkletree 0.8.2` with `legacy-api`; registry identities are in the
lockfile. The output fixture's [original mappings](SHIELDED_ATTRIBUTION.md) remain
applicable to reused helpers, including `mixed_traffic_fixture` concepts.

The pre-NU6.3 Orchard deposit is a required adaptation to the inherited upstream
net-deposit rule. It uses `BundleVersion::orchard_v2()` and
`OrchardCircuitVersion::FixedPostNu6_2` at height 102, followed by legal post-NU6.3
withdrawal using Orchard v3 with cross-address transfers disabled. This adds no
upstream consensus exception, backend, downloader, node instrumentation, state
injection or research runtime dependency.

`controls.rs` adds a separate bounded spend block mode using its existing block
builder. `model.rs`/`main.rs` register strict feature-gated operations.
`SPEND_SCHEMA.md` records the full contract and validation limits. New synthetic
history/ciphertext tests intentionally carry invalid proof/signature placeholders;
they test recovery/buildability only and never claim real proof validity.
Sapling per-proof component verdict remains null rather than mislabeling its
batch result as independent primitive verification.
