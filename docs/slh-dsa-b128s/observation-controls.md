# Funded observation brackets and SLH lifecycle controls

[observation_controls.py](../../tests/slh-dsa-b128s/acceptance/observation_controls.py)
prepares actual functional controls for the existing opt-in
[primitive observation](observations.md). **No daemon execution or primitive-entry
result is claimed by this preparation.** The offline ledger tests exercise the
orchestration and real capture parser without launching a daemon, host or signer.
The [acceptance workflow](acceptance.md) supplies clean matching build receipts;
[AGENTS.md](../../AGENTS.md) governs human execution.

## Human command

From a clean committed product checkout, build the `node-slh`, `host` and `signer`
recipes from [acceptance.md](acceptance.md#build-receipts). Use a fresh absolute
artifact directory for each version, an existing private parent directory, and a
32-character lowercase hexadecimal public capture token:

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

Repeat with `--version 6` and a different new artifact directory. This uses the
existing Regtest profile NU7=105, SLH=110, 16 checks/transaction and 64/block.
The deterministic fixture keys are public test material; the operational wallet
signer and entropy policy are unchanged. No additional build feature, verifier
identity field, primitive/backend selection or production hook is introduced.

## Actual setup and attempted subjects

Both peers authenticate a mature real classical coinbase. The existing public
2-of-3 classical signer funds ten 3,000,000-zatoshi outputs in a legal direct
block at height 108. This retains the funding when the later rollback removes
height 109 onward. Both peers authenticate all output scripts and amounts before
controls. A distinct mature coinbase at height 2 funds the classical zero-work
subject; no fabricated previous output is supplied as chain authority.

The driver uses four distinct, valid, funded 1-of-1 SLH transactions as its
positive brackets. Each positive must receive an accepted block-proposal result
from each node, with exact candidate bytes retained and parents, tips and
mempools unchanged. These are successful functional **block proposals**, not
mempool admission claims. The later saved-byte relay/mining operation establishes
separate actual admission and confirmation outcomes.

Each active process contains two windows:

| Window | Operations strictly between positive controls | Required capture result |
| --- | --- | --- |
| Structural / classical / mixed | Real ECDSA authorization substituted into the SLH input; valid classical spend creating an SLH output; classical+SLH, unsupported `0x51`+SLH and unsupported `0x52`+SLH in both input orders | Zero total entries within this window and zero entries for each of its eight subject identities across the entire captured process |
| Same-TXID authorization / prepared candidate | Exact saved valid block proposed twice; same-TXID corrupted SLH authorization rejected; exact original valid block proposed again | At least three observed valid-subject entries and at least one changed-authorization entry within this window, alongside the exact successful/rejected functional calls |

Structural and mixed negatives attempt both peers' `sendrawtransaction`, block
proposal and `submitblock` paths. Exact known diagnostic reasons are required;
missing inputs, expiry and unrelated errors cannot count as the intended refusal.
The classical funding subject receives successful proposals without spending its
parent during the bracket. After both brackets, that exact funding transaction
and the saved valid SLH spend must relay and mine together in one new block;
both peers must return the exact saved transaction bytes and positive
confirmations, and both actual parents must be spent.

The existing host `control-authorization` operation supplies the original TXID
and authorizing digest, bound to the exact original transaction SHA-256. Its
existing missing-classical-quorum or corrupt-SLH mutation provides an identity
witness for unmodified transactions; both actual malformed subjects already
carry their exact generated identities. Every witness and original is retained,
and raw byte hashes and unchanged effects are checked. Pinned Zakura has no
`decoderawtransaction` RPC, and a rejected transaction is not available through
`getrawtransaction`. After saved-byte mining, both peers' `getrawtransaction`
results must agree on raw bytes, TXID and authorizing digest. Changed
authorization preserves TXID and changes authorizing digest. These host/node
identities are not an independent digest oracle; existing independent
digest/vector references remain unchanged.

`attempts.json` retains each intended subject/control call before dispatch,
including node, method, identity, exact transaction hash, and candidate block
hash/byte hash where relevant. Completed calls retain outcomes; failed calls
retain the fixed failure reason and remain incomplete. An explicit ordered call
manifest prevents a skipped subject or repeat from completing a stage. Ordinary
per-node RPC request/response hashes and identified public fixture/block artifacts
remain in the artifact directory. `execution.json` starts incomplete and retains
failed attempts; only all functional, lifecycle and capture checks complete it.

## Lifecycle and complete process accounting

The active stage starts at tip 110 and mines the saved pair at 111. Invalidate
that block and use the existing disposable restart to return to the exact tip
110; verify restored parents and repeat the brackets and saved-byte mining.
Next invalidate height 109, restart at tip 108 with the original funding intact,
and require all six mixed subjects to fail under the inactive classical rules.
Mine to tip 109, require candidate-height SLH activation at 110, repeat the two
active brackets and mine the same saved pair again. A no-op rollback,
reactivation or saved-byte retry cannot satisfy these state and byte checks.

There are exactly three cleanly stopped processes per peer, one for each stage,
and every process is analyzed with the existing parser. The initial bootstrap
and the inactive portion of the third process remain included in their complete
process capture. Each process yields two reports, twelve in total. A missing
capture, unclean shutdown, absent positive bracket or incomplete sequence fails.
Each report binds binary, configuration, source, token/PID and exact log bytes.
Reports are written before a zero/nonzero expectation is checked, retaining the
actual observation on failure.

Counts are **process/window primitive attempts**, never isolated RPC counts.
The count of three is a lower bound in the shared process/window, not a proof
that precisely one entry belongs to each proposal. Relay retries and concurrency
remain possible. Both total process counts and window counts are retained;
late subject entries outside a zero window fail its process-zero requirement.
Other out-of-window entries stay in the process count and log. No rejected RPC
is treated as a worker-drain barrier. No zero-work claim is made for the inactive
portion alone, where a valid SLH positive bracket cannot exist.

## Queue and cache observation limits

The existing bounded source tests were audited before adding this adapter:

| Existing source | Established test scope; not new execution evidence |
| --- | --- |
| [mempool vector tests](../../crates/zakurad/src/components/mempool/tests/vector.rs), `mempool_cancel_downloads_after_network_upgrade` and `mempool_reverifies_after_tip_change` | Private mock verifier/download orchestration at the inherited NU5 boundary, including in-flight work, completed-result revalidation and empty storage. This file and `downloads.rs` match the pinned upstream baseline; no SLH queue scheduling extension is claimed |
| [SLH tip tests](../../crates/zakura-state/src/service/chain_tip/tests/vectors.rs), `experimental_slh_dsa_b128s_resets_at_its_own_next_block_activation` | SLH reset action on activation, rollback, reactivation and same-height fork; does not establish live pending/completed queue occupancy |
| [prepared candidate tests](../../crates/zakura-consensus/src/block/prepared.rs), `experimental_slh_dsa_b128s_active_candidates_never_reuse_prepared_work` | Both cache partitions refuse active insertion and active lookup, including entries inserted under inactive rules |
| [SLH dispatch tests](../../crates/zakura-consensus/src/transaction/tests/slh_dsa_b128s.rs), `slh_trusted_block_dispatch_uses_real_worker_and_preserves_fresh_attempts` and `slh_cancelled_inflight_worker_keeps_reservation_and_discards_result` | Actual immutable fixture verification and same-TXID bad authorization, plus test-observer cancellation with retained reservation; no daemon queue claim |

Public RPCs expose mempool presence, exact transaction bytes and chain state.
They do not expose a deterministic boundary between a pending worker, a completed
but unconsumed result, and stored mempool work. This driver therefore does not
claim to populate those three states at a chosen reset boundary. Restarting
clears the process-local relay retry state for the next scenario; it cannot
establish an in-process queue-drain or cancellation result. The repeated exact
proposals exercise the public path expected to bypass prepared work, with the
source test above supplying the narrower cache invariant. No inherited scheduler,
RPC or cache is rewritten to manufacture observability.

## Bounded checks and attribution

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/acceptance -p 'test_observation*.py' -v
```

The causal mock ledger reuses the existing transparent-control tests. It rejects
omitted subject operations/repeated proposals, missing captures, dirty shutdown,
late out-of-window entries, missing valid revalidation entries, no-op
rollback/reactivation/retry, unrelated diagnostics, missing parents, changed
state and mismatched transaction identity. It runs the actual bounded log parser
and capture sealing against synthetic diagnostics, not a simulated claim of
cryptographic or daemon success. Dedicated builds, live capture and both version
runs remain pending human execution. No performance or resource result is made.

This selectively reuses the MIT/Apache-2.0 research sources at
`e759cb86a06510893f8e7d1eb986b7025401c8c9`:
`node/tests/sqisign_c_comparison.py` for real proposal outcomes and closed-process
primitive-entry checks; `node/tests/pq_history_live.py` for retained exact block
bytes and clean lifecycle boundaries; `node/tests/pq_relay_live.py` for saved-byte
relay/reorg orchestration. Current product `observations`, `ManagedNode`/`Network`,
`transparent_controls`, `single_artifact` and `reconcile_saved` provide those
mechanisms directly. New glue adds distinct positive brackets, the fixed attempted
subject manifest and narrow lifecycle receipts. No research benchmark, resource
stack, alternate backend, history or notes are imported. Exact source/target
hashes belong to the shared [source map](../../tests/slh-dsa-b128s/acceptance/sources.json).
