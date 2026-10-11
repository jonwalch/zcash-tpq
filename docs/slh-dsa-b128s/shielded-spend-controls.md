# Shielded spends and anchor tests

The [driver](../../tests/slh-dsa-b128s/acceptance/shielded_spend_controls.py)
prepares real Sapling, Orchard, and Ironwood spends with SLH or classical transparent authorization.
Only a complete live receipt establishes acceptance.
The [output tests](shielded-controls.md) and independent digest corpus retain their separate scope.
Wallet approval remains transparent-only.

The driver uses the same ten version/pool subsets as the output tests.
Pool names occur in the order Sapling, Orchard, Ironwood.
Each selected pool spends one genuine 50,000-zatoshi note and creates two padded outputs or actions.
Fixture keys are public. Do not send real funds to them.

## Funding and history

This isolated profile uses NU6.2=1, NU6.3=104, NU7=105, and SLH=110.
It does not change ordinary acceptance defaults.
Both connected nodes use enabled binaries and agree on funding, history, and state.
The driver authenticates mature classical coinbases through bytes, block membership, amount, script, and maturity.

Orchard receives 50,000 zatoshis at height 102, before NU6.3.
The deposit uses v5, expiry 103, and the pinned Orchard v2 circuit.
It relays and confirms through the ordinary node.
The inherited prohibition on later net Orchard additions remains unchanged.
Ironwood has no available tree state before height 104.
The receipt records a null root only when RPC explicitly returns empty commitments.
It does not invent a root.

After height 110, the output fixture deposits 50,000 zatoshis into each selected Sapling/Ironwood pool.
Separate classical funding creates two transparent parents of 3,000,000 zatoshis each.
In SLH mode, both parents use the public SLH policy.
A separate output transaction then advances all selected trees.
Its Orchard output is zero-valued under the active rule.
The later root supplies the anchor for both spends.

History export includes genesis through the stable tip, exact blocks, and `z_gettreestate`.
Both nodes must agree on bytes, hashes, heights, links, and tree state.
The driver checks funding membership and both available transparent parents again.
Export permits at most 512 blocks after genesis and 12 MiB of encoded history.
The host applies stricter block, transaction, and commitment bounds.

The host reconstructs linked history and decrypts notes with public fixture identities.
It finds note positions and witnesses, then matches selected roots to node tree state.
Sapling uses the RPC display-order conversion while internal witness and tree checks retain canonical order.
Note metadata keeps the exact RPC root.
Orchard and Ironwood retain their existing byte order.
These are trusted-node observations, not independent consensus verification.
Requested amounts cannot replace authenticated chain amounts.

## Saved signatures and variants

The host completes effects and proofs before shielded signatures.
The SLH signer signs the final 101-byte message, and the host verifies assembly.
The second transaction spends the same notes through a different available transparent parent.
Its effects, TXID, and native message differ.
Each transaction receives its own SLH signature.
Retries use the saved authorization bytes.

Each pool supplies spend-authorization, binding-signature, and wrong-public-input proof variants.
They retain the positive transaction's effects, TXID, and native message.
Their bytes and authorization digest differ.
Thus, authorization-only variants can reuse that transaction's SLH signature.
The host checks aggregate pool results and individual spend/binding signatures.
Sapling's separate proof result is null.
Aggregate and field-isolation checks do not establish a separate proof-primitive observation.

## Required lifecycle

| Stage | Required result |
| --- | --- |
| Positive setup | Both original and independent-parent duplicate transactions pass block proposals with the later anchor present. |
| Remove anchor | Invalidate only the later output block. Notes and transparent parents remain available. Roots and values return to the prior snapshot. |
| Unknown-anchor refusal | Submit unchanged original bytes through relay, proposal, and block submission. Only the exact unknown-anchor diagnostic counts. |
| Restore anchor | Reconsider the exact later block. Its bytes and state must match. |
| Authorization controls | Positive proposals surround each negative on both nodes. Exact diagnostics, unchanged state, and mempool absence are required. |
| Confirm original | Relay saved bytes, check both templates, and mine. Authenticate transaction bytes, block bytes, and transparent change. |
| Duplicate-nullifier refusal | Use the separately checked duplicate with its unspent transparent parent. Require the pool-specific diagnostic through relay and block paths. |
| Reorg and reentry | Invalidate the spend, restore state, and mine two replacement blocks above the anchor. Repeat controls and accept the exact cached spend in a block. |

Anchor failure uses actual state removal. It does not mutate proof or anchor bytes.
Missing transparent parents, expiry, and unrelated errors cannot substitute for nullifier refusal.
A confirmed spend decreases each selected pool by 50,000 zatoshis and appends commitments.
Unselected roots and values stay unchanged.
Reentry must produce the same resulting pool state and authenticated output.

## Publication and restart limits

The driver records each node's initial transaction state.
It submits exact bytes directly where the transaction is absent.
Exact existing mempool presence skips that submission.
Only known already-queued or already-in-mempool races permit bounded waiting after an RPC refusal.
Before mining, both mempools and templates must contain exact bytes.
A successful RPC response alone cannot establish acceptance.
These observations do not prove fresh peer gossip.

Final reentry records `mode: direct-saved-block`, initial absent states,
block hashes, and the original transaction hash.
`Controls.accept(publish=False)` supplies two positive proposals before block submission.
Duplicate submission responses require authenticated best-chain block and confirmed transaction bytes.
The replacement branch follows explicit invalidation, not competing-peer timing.

Anchor invalidation and reconsideration remain in the same processes.
Inherited invalidated-block records exist only in memory.
Before a later restart, the driver observes all canonical backup blocks.
After spend rollback, it also waits for the removed backup file to disappear.
The [crash helper](crash-controls.md) bounds backup checks to 128 blocks.
That covers this driver's approximately 117-block maximum.
These observations do not force a flush or establish a writer barrier.

Restarts separate negative windows and retain inherited retry behavior.
The driver does not inspect internal nullifier membership, cache hits, primitive counts, or publication barriers.
Nullifier refusal is a functional result with a valid independent transparent parent.
Internal membership checks would need a separately scoped state helper.

## Human command

Build `node-slh`, `host-shielded`, and `signer` from clean, committed source.
Use the [acceptance build workflow](acceptance.md#build-receipts).
For Sapling, supply existing public parameter files by absolute path.
Each regular file has a 64 MiB limit and a recorded hash.
The tool does not search for or download parameters.
Fixture dependencies remain outside the node graph.

Agents must obtain user approval before this run under [AGENTS.md](../../AGENTS.md):

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

Without Sapling, omit both parameter arguments.
Use a new artifact directory for each run.
For classical authorization, use either option pair:

- `--authorization single --classical single`
- `--authorization multisig --classical multisig`

Both nodes still use enabled binaries.
This driver does not compare default and enabled builds.
Proof requests use bounded transport and a 1,800-second deadline.

Receipts retain failures and identify source, locks, builds, binaries, configurations, and parameters.
Artifacts include funding, history, requests, host results, signatures, proposals, blocks, publication responses, and RPC hashes.
The driver checks both signed-artifact hashes again after execution.
Retries use exact cached authorization.
Local receipts provide traceability, not hostile-host attestation.
Live proof and node outcomes remain open.

## Offline tests and attribution

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/acceptance \
  -p 'test_shielded_spend_controls.py' -v
```

Models cover ten host shapes and seven pool combinations through the lifecycle.
They also cover the driver's funding order, duplicate-note check, and saved history and authorization checks.
They reject false history, changed identities, missing parents, wrong diagnostics,
omitted operations, no-op state changes, and incorrect reentry.
Publication models cover absent peer propagation, bounded races, refusal, exact bytes, and both templates.
Replay models require correct blocks, membership, and confirmed transactions despite duplicate-submission responses.
They check legal Orchard funding and one final-message signature per effect identity.
They start no node, signer, prover, or subprocess transport.
Model proof bytes have no cryptographic validity claim.

Research revision `e759cb86a06510893f8e7d1eb986b7025401c8c9` supplies these patterns:

- `node/tests/pq_ironwood_spend_fixture.py`: bounded history and note/root correspondence.
- `node/tests/pq_ironwood_spend_live.py`: positive brackets, pool state, and saved-byte reentry.
- The corresponding `test_*.py` files: adversarial ordering and reporting checks.

The source map retains attribution under [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE).
The driver shares product node, proof, signature, and transaction-state helpers.
Adaptations add all-pool v5/v6 support, native SLH authorization, two-node authentication,
legal Orchard funding, removed anchors, and independent transparent parents.
