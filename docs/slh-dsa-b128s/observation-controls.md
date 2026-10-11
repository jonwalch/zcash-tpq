# Funded tests for primitive-call observations

The [driver](../../tests/slh-dsa-b128s/acceptance/observation_controls.py)
prepares functional controls for [primitive observations](observations.md).
Live execution and primitive-count results remain open.
Offline tests use mocks and the real parser without a daemon, host, or signer.
The [acceptance guide](acceptance.md) supplies matching builds.
[AGENTS.md](../../AGENTS.md) reserves live execution for humans.

## Human command

Build `node-slh`, `host`, and `signer` from clean, committed source.
Choose a new absolute artifact directory under an existing private parent.
Use a public token of 32 lowercase hexadecimal characters.
Run the driver:

```sh
python3 tests/slh-dsa-b128s/acceptance/observation_controls.py --human-run \
  --node "$SLH_ACCEPTANCE_ROOT/node-slh/zakurad" \
  --node-build "$SLH_ACCEPTANCE_ROOT/node-slh/build.json" \
  --host "$SLH_ACCEPTANCE_ROOT/host/slh-dsa-b128s-fixture-host" \
  --host-build "$SLH_ACCEPTANCE_ROOT/host/build.json" \
  --signer "$SLH_ACCEPTANCE_ROOT/signer/slh-dsa-b128s-public-fixture" \
  --signer-build "$SLH_ACCEPTANCE_ROOT/signer/build.json" \
  --version 5 --token 0123456789abcdef0123456789abcdef \
  --artifacts "$SLH_ACCEPTANCE_ROOT/observation-v5"
```

Repeat with version `6` and a new directory.
The profile uses NU7=105, SLH=110, 16 checks per transaction, and 64 per block.
Fixture keys are public test material.
The driver adds no feature, identity field, backend selector, or operational signer change.

## Funded setup and windows

Both peers authenticate a mature classical coinbase.
The public 2-of-3 signer funds ten outputs of 3,000,000 zatoshis in a direct block at height 108.
Rollback above height 108 preserves these outputs.
Both peers check their scripts and amounts.
A separate mature coinbase at height 2 funds the classical zero-work subject.
Fabricated previous outputs cannot supply chain authority.

Four distinct funded 1-of-1 SLH transactions form the positive brackets.
Each must receive an accepted block-proposal response from both nodes.
Candidate bytes are retained. Parents, tips, and mempools must stay unchanged.
These positives establish successful proposals, not mempool admission.
Each active process has two windows:

| Window | Subjects | Required counts |
| --- | --- | --- |
| Structural, classical, and mixed | ECDSA substituted into SLH. Valid classical funding. SLH mixed with classical, `0x51`, or `0x52`, in both orders. | Zero total window entries. Zero process entries for each of the eight subjects. |
| Authorization change and repeated proposal | Propose the saved valid block twice. Reject changed SLH authorization with the same TXID. Propose the original block again. | At least three valid-subject entries and one changed-authorization entry within the window. |

Structural and mixed cases use both peers' submission, proposal, and block-submission paths.
Each failure must have the intended diagnostic.
Missing inputs, expiry, and unrelated errors do not count.
The classical subject must receive successful proposals without a parent spend during capture.
After both windows, the exact classical and SLH transactions must relay and confirm in one block.
Both nodes must return the saved bytes and positive confirmations.
Both parents must be spent.

## Identities and attempted calls

The host's `control-authorization` operation supplies identities bound to the original transaction hash.
Its mutation provides an identity witness for an unchanged original.
Malformed subjects also retain their generated identities.
All witnesses and originals remain in the artifacts.
The driver checks raw-byte hashes and unchanged effects.
After mining, both nodes must agree on bytes, TXID, and authorization digest through `getrawtransaction`.
Zakura has no `decoderawtransaction` RPC.
Changed authorization preserves TXID but changes the authorization digest.
These checks do not replace the independent digest oracle.

`attempts.json` records each intended call before dispatch.
It includes node, method, identity, transaction hash, and relevant block hashes.
Completed calls include outcomes. Failed calls retain a reason and remain incomplete.
An ordered manifest prevents omitted subjects or repeated proposals from satisfying a stage.
RPC hashes and public artifacts remain available.
Only successful functional, lifecycle, and capture checks complete `execution.json`.

## Lifecycle and full-process counts

The driver performs three stages:

1. Start at tip 110. Check both windows and mine the saved pair at 111.
2. Invalidate that block and restart at tip 110. Check restored parents and repeat capture and mining.
3. Invalidate height 109 and restart at tip 108. Check inactive mixed-input failures, then reactivate and repeat capture and mining.

The third stage retains original funding.
At tip 109, candidate 110 must apply active SLH rules.
A no-op rollback, reactivation, or retry cannot satisfy the state and byte checks.

Each peer has three cleanly stopped processes.
The parser checks every process, including bootstrap and the inactive part of the third stage.
Each process produces two reports, for twelve reports total.
Missing captures, failed shutdown, absent positives, or incomplete sequences cause failure.
Reports bind source, binary, configuration, token, PID, and log bytes.
The driver writes counts before it checks the expected zero/nonzero result.

Counts describe process/window attempts, never isolated RPC calls.
Three valid entries are a lower bound, not proof of one call per proposal.
Retries and concurrency remain possible.
Late subject entries fail a full-process zero requirement.
Other entries remain in the full-process count.
No RPC rejection proves worker completion.
The inactive interval alone has no zero-work claim because it lacks a valid SLH positive bracket.

## Queue and cache limits

The existing tests establish these narrower properties:

| Existing source | Existing test scope |
| --- | --- |
| [mempool vector tests](../../crates/zakurad/src/components/mempool/tests/vector.rs), `mempool_cancel_downloads_after_network_upgrade` and `mempool_reverifies_after_tip_change` | Private mock verifier/download orchestration at the inherited NU5 boundary, including in-flight work, completed-result revalidation and empty storage. This file and `downloads.rs` match the pinned upstream baseline. No SLH queue scheduling extension is claimed |
| [SLH tip tests](../../crates/zakura-state/src/service/chain_tip/tests/vectors.rs), `experimental_slh_dsa_b128s_resets_at_its_own_next_block_activation` | SLH reset action on activation, rollback, reactivation and same-height fork. Does not establish live pending/completed queue occupancy |
| [prepared candidate tests](../../crates/zakura-consensus/src/block/prepared.rs), `experimental_slh_dsa_b128s_active_candidates_never_reuse_prepared_work` | Both cache partitions refuse active insertion and active lookup, including entries inserted under inactive rules |
| [SLH dispatch tests](../../crates/zakura-consensus/src/transaction/tests/slh_dsa_b128s.rs), `slh_trusted_block_dispatch_uses_real_worker_and_preserves_fresh_attempts` and `slh_cancelled_inflight_worker_keeps_reservation_and_discards_result` | Actual immutable fixture verification and same-TXID bad authorization, plus test-observer cancellation with retained reservation. No daemon queue claim |

Public RPC exposes mempool presence, transaction bytes, and chain state.
It cannot distinguish pending workers, completed unconsumed results, and stored work at a chosen instant.
This driver cannot populate those states deterministically at reset.
Restart clears process-local retries but does not prove in-process cancellation.
Repeated proposals exercise the public path expected to bypass prepared work.
The source test checks the cache rule directly.
The driver does not change inherited scheduling, RPC, or caches.

## Focused tests and attribution

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/acceptance -p 'test_observation*.py' -v
```

Mocks reject omitted operations, missing captures, failed shutdown, late entries,
missing revalidation, no-op transitions, wrong diagnostics, and changed identities or state.
They use the real parser with synthetic logs.
They do not establish cryptographic or daemon success.
Both live versions remain open.

The driver adapts MIT/Apache-2.0 research revision
`e759cb86a06510893f8e7d1eb986b7025401c8c9`:

- `node/tests/sqisign_c_comparison.py`: proposal outcomes and process captures.
- `node/tests/pq_history_live.py`: exact block bytes and lifecycle boundaries.
- `node/tests/pq_relay_live.py`: saved-byte relay and reorg tests.

It reuses product observation, node, fixture, and reconciliation helpers.
The [source map](../../tests/slh-dsa-b128s/acceptance/sources.json) records adaptations and hashes.
