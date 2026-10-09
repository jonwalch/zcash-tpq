# Real shielded spends and anchor lifecycle

The [acceptance driver](../../tests/slh-dsa-b128s/acceptance/shielded_spend_controls.py)
prepares genuine Sapling, Orchard and Ironwood spends alongside final SLH or
classical transparent authorization. Source and offline models are preparation;
only a completed live receipt establishes acceptance. The existing
[output controls](shielded-controls.md) and independent digest corpus retain their
original scope and bytes. Wallet approval remains transparent-only.

Use the ten supported version/pool subsets: in v5, `sapling`, `orchard`, and
`sapling,orchard`; in v6, every nonempty subset of `sapling,orchard,ironwood`.
List pool names in that order. Each included pool spends one genuine 50,000-zatoshi
note and creates its builder's two padded outputs/actions. Public fixture keys
are deliberately reproducible. Never send real funds to those identities.

## Funding and history boundary

This isolated profile uses NU6.2 at height 1, NU6.3 at 104, NU7 at 105 and SLH at
110. Ordinary acceptance defaults are unchanged. Two connected local enabled
nodes agree on funding, history and state. The driver authenticates real mature
classical coinbase outpoints by raw transaction, block membership, amount, script
and maturity through the existing node helper.

Orchard receives a real 50,000-zatoshi deposit at height 102, before NU6.3, using
a v5 transaction expiring at 103 and the pinned Orchard v2 circuit. The driver
relays and mines it through the ordinary node. The inherited prohibition on net
Orchard additions after NU6.3 is preserved. Ironwood tree state is unavailable at
this point: the receipt records `null` for its root only while the RPC explicitly
returns empty commitments before height 104; it does not invent an empty root.

After height 110, the existing output fixture deposits 50,000 zatoshis into each
selected Sapling/Ironwood pool. Separate classical funding creates two actual
3,000,000-zatoshi transparent parents. In SLH mode both parents lock to the public
SLH policy. Another independently funded output transaction then advances all
selected pool trees. Its Orchard output is zero-valued, as required by the active
rule. This later root supplies the anchor used by both genuine note spends.

The bounded export includes genesis through the stable current tip, exact raw
blocks, and `z_gettreestate`. Both nodes must agree on every raw block, hash,
height, previous-block link and exported treestate; funding transaction bytes,
best-chain membership and both available transparent parents are checked again.
The driver allows at most 512 blocks after genesis and 12 MiB of encoded history;
the host additionally enforces its stricter raw-block, transaction and commitment
bounds. The host reconstructs canonical linked history, decrypts notes with the
fixed public fixture identities, finds their actual positions and witnesses,
and matches every selected root to the node treestate.

These are trusted-node observations and bounded witness reconstruction, not an
independent consensus verifier. Requested amounts never replace authenticated
chain amounts. No new RPC or production state instrumentation is introduced.

## Saved bytes and causal controls

All pool effects and real proofs precede shielded signatures. The native SLH
signer signs the final complete 101-byte message, then the host verifies assembly.
The second transaction spends exactly the same shielded notes using the other
available transparent parent, so its complete effects, TXID and native message
differ. Each transaction receives its own SLH signature. Its saved authorization
bytes are never silently regenerated for retry.

For each selected pool the host provides isolated real-spend authorization,
binding-signature and other-public-input proof variants. They preserve the
positive transaction's effects, TXID and native message, while changing its
bytes and authorization digest. One SLH signature may therefore be reused across
that transaction's authorization-only mutants. The driver verifies aggregate
pool verdicts and individual signature/binding results. Sapling's proof component
is explicitly `null`: the host's aggregate and field-isolation checks do not
claim a separate proof primitive observation. None of these results count node
worker entries or prove drained retry queues.

The driver performs the following bounded sequence:

1. Both original and independent-parent duplicate transactions pass positive
   block proposals while the later anchor exists.
2. Invalidate only the later output block. The original notes and both transparent
   parents remain available; exact roots, values and outpoints return to the prior
   snapshot. Submit the unchanged original by relay, proposal and block submission.
   Only an actual unknown-anchor diagnostic is accepted. The proof and anchor
   bytes were not mutated to manufacture this state failure.
3. Reconsider the exact later block and require its original bytes and state.
   Positive proposals bracket every spend-auth, binding and proof refusal on
   both nodes, with exact diagnostic matching and unchanged roots, values, parents
   and tip. Rejected transactions must remain absent from both mempools.
4. Relay the original saved spend, observe its exact template bytes, mine it,
   and authenticate its saved transaction/block bytes and transparent change.
   Each selected pool decreases by exactly 50,000 zatoshis and appends commitments;
   all other pool roots and values remain unchanged.
5. Submit the separately preflighted duplicate with its genuinely unspent
   transparent parent. Require the pool-specific duplicate-nullifier diagnostic
   on relay and direct block paths. Missing transparent inputs, expiry or unrelated
   verification errors cannot stand in for this refusal.
6. Invalidate the mined spend, restore exact roots, values and parents, and mine
   two replacement blocks above the retained anchor. Repeat positive-bracket
   authorization controls, then use the existing `reconcile_saved` helper to
   reenter and mine the exact original spend bytes. Require the same resulting
   pool state and authenticated output.

The replacement branch is selected after explicit invalidation; it is not a
competing-peer timing experiment. Existing clean restarts delimit negative
windows and preserve the inherited node retry behavior. The driver does not
assert internal nullifier-set membership, cache hits, primitive counts or
publication barriers. Duplicate-nullifier refusal is a functional state result
with a valid independent transparent parent. Direct internal membership queries
would require a separately scoped supported state replay helper.

## Build and explicit run

Use the [matching build receipts](acceptance.md#build-receipts) from a clean
committed source: `node-slh`, `host-shielded`, and the isolated public `signer`.
The spend operations use the existing optional host shielded feature. Sapling
requires explicit absolute paths to existing public parameters; each regular
file is bounded to 64 MiB and hashed. No parameter download or search occurs.
These fixture host and public signing dependencies are not introduced into the
node dependency graph; inherited upstream proof-library dependencies retain their
existing scope.

```sh
python3 tests/slh-dsa-b128s/acceptance/shielded_spend_controls.py --human-run \
  --node "$SLH_ACCEPTANCE_ROOT/node-slh/zakurad" \
  --node-build "$SLH_ACCEPTANCE_ROOT/node-slh/build.json" \
  --host "$SLH_ACCEPTANCE_ROOT/host-shielded/slh-dsa-b128s-fixture-host" \
  --host-build "$SLH_ACCEPTANCE_ROOT/host-shielded/build.json" \
  --signer "$SLH_ACCEPTANCE_ROOT/signer/slh-dsa-b128s-public-fixture" \
  --signer-build "$SLH_ACCEPTANCE_ROOT/signer/build.json" \
  --version 6 --pools sapling,orchard,ironwood --authorization slh \
  --sapling-spend-parameters /absolute/public/sapling-spend.params \
  --sapling-output-parameters /absolute/public/sapling-output.params \
  --artifacts "$SLH_ACCEPTANCE_ROOT/shielded-spend-v6-all-slh"
```

Omit both Sapling parameter arguments when that pool is absent. A fresh artifact
directory is required. `--authorization single --classical single` and
`--authorization multisig --classical multisig` run classical signatures through
the same shielded lifecycle on the enabled binaries; this driver makes no
default-versus-enabled binary compatibility claim.

Every proof request has a finite 1,800-second subprocess deadline and uses the
existing bounded concurrent transport. `execution.json` starts incomplete, retains
failures, and binds exact source/lock/build/binary/config/parameter identities.
The output preserves public funding transactions, raw history, proof requests,
host results, signed artifacts, proposals, accepted blocks and RPC request/reply
hashes. Both signed artifact hashes are checked again after lifecycle execution;
retries use the cached exact authorization. Local receipts are traceability, not
hostile-host attestations. Proving, node execution and acceptance remain pending
until an actual matching live receipt completes.

## Offline checks and attribution

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/acceptance \
  -p 'test_shielded_spend_controls.py' -v
```

The focused models cover all ten host shapes and all seven pool combinations
through the causal lifecycle. They reject forged/changed/disconnected history,
changed effect or authorization identities, absent or expired-parent confounders,
wrong refusal reasons, skipped subject operations, no-op rollback/reconsideration,
missing replacement blocks and no-op saved-byte reentry. They also verify the
pre-NU6.3 funding gate and one final-message SLH signing call per effect identity.
Model proof/signature bytes are not cryptographic evidence; tests launch no nodes,
signer, prover or subprocess transport.

Selective source lineage is research commit
`e759cb86a06510893f8e7d1eb986b7025401c8c9`:
`node/tests/pq_ironwood_spend_fixture.py` supplies bounded stable history export
and exact note/funding/root correspondence;
`node/tests/pq_ironwood_spend_live.py` supplies positive-bracket refusals, value/tree
observations and exact saved-byte reorg/reentry;
`node/tests/test_pq_ironwood_spend_fixture.py` and
`node/tests/test_pq_ironwood_spend_live.py` supply adversarial reporting and ordering
controls. Their original source/license attribution is retained through the
repository's source mapping and MIT OR Apache-2.0
[MIT](../../LICENSE-MIT) / [Apache](../../LICENSE-APACHE) licenses.

The driver reuses product `shielded_controls`, `Network`, `Controls`,
`authenticate_coinbase` and `reconcile_saved`, rather than copying node lifecycle,
proof transport or signing implementations. Necessary adaptations are all-pool
and v5/v6 support, native SLH final-message authorization, strict dual-node
history/UTXO authentication, the legal Orchard funding profile, a later genuinely
removed anchor, and the independent transparent parent for duplicate-spend
causality. No alternate backend, research node overlay, benchmark history or
operational secret is imported.
