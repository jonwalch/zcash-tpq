# SLH process crash and restart controls

`acceptance/crash_controls.py` prepares six bounded process interruption cases
for one transaction version: three for an ordinary 2-of-3 classical spend and
three for a genuine 1-of-1 SLH spend. Both isolated nodes are killed at each
checkpoint, giving **six logical checkpoints and twelve required SIGKILL exits**
per run. Repeat with v5 and v6 in separate artifact directories. Offline mocks
establish adapter behavior; they do not establish live crash recovery.

The adapter uses deterministic public fixture keys and actual mature coinbase
funding authenticated through both nodes. A classical transaction creates
separate 3,000,000-zatoshi classical and SLH parents. The two saved spends remain
separate controls on the same inherited node machinery. Ordinary positive block
proposals bracket a malformed classical quorum or SLH signature refusal before
each subject is admitted. Unrelated refusal diagnostics fail the control.

## Checkpoints and permitted recovery

| Checkpoint | Acknowledged state before SIGKILL | Only permitted state immediately after isolated reopen |
| --- | --- | --- |
| `admitted-unmined` | Exact transaction bytes, TXID and authorization digest are in each mempool; the unchanged chain has an observed ordinary backup | The exact same chain and UTXOs. The subject may be absent or present with identical bytes in the volatile mempool |
| `mined-unbacked` | One new block confirms the exact saved transaction. The ancestor was backed up; no wait for the new block's backup is requested | Either the exact old ancestor with the parent restored and subject outputs absent, or the complete new block with parent spent and exact subject outputs. Each node is classified separately |
| `reorg-backed` | A fresh isolated fork replays the saved ancestor and supplies two distinct empty blocks, overtaking the one-block subject branch. Both nodes show the replacement chain, restored parent and absent orphan outputs. Every canonical recent-block backup file is observed in full | The complete replacement chain and exact UTXOs. The subject may be absent or present with identical bytes in the volatile mempool |

`mined-unbacked` names the absence of a requested backup wait; the asynchronous
backup may already have completed. It does not claim the block is definitely
missing on disk. Lost new blocks are replayed from their saved exact bytes, and
tip/hash/bytes must advance to the expected block. After the reorg reopen, the
same saved authorization is submitted again and must confirm in one new block.
Retries never call the signer. Other tracked transaction states must stay exact;
an arbitrary partial UTXO view or an unrelated transaction appearing in the
mempool is not an accepted old/new outcome.

All nodes have no peers. Blocks move through explicit `submitblock` calls, so
automatic peer synchronization cannot mask missing local recovery. Fresh fork
nodes replay at most 128 ancestor blocks, with the normal run ending at height
117. The driver does not advance the 1,000-block finalization window. It uses the
ordinary asynchronous backup configuration without enabling a synchronous debug
flush or changing databases, queues, consensus, or clean-stop behavior.

## Exact process and artifact evidence

`checkpoints.json` persists the intended checkpoint, unique public token,
acknowledged state, allowed chain hashes, exact process IDs and source/config/
binary/saved-file bindings before sending SIGKILL. The controller rechecks that
the same `Popen` object and PID are still alive, sends SIGKILL to that child,
waits for the exact Unix `-SIGKILL` exit status, and requires a distinct live
process on restart. A missing signal, prior exit, stale PID, no-op restart,
timeout, different authorization or changed source/config/file fails. This is
a controller handshake over an observed RPC checkpoint; there is no in-process
write-stage marker or worker-drain barrier.

Receipts retain before/after UTXOs, transaction states, replay classifications,
signal and reopened PIDs, exact saved transaction/block files, full bounded fork
history, config files, RPC transcripts and node logs. `execution.json` starts
incomplete, records failures, and becomes complete only after all six checkpoints
and their final retries succeed. State directories remain local artifacts and
are excluded from the public file-hash manifest. Inputs are public fixtures;
never use operational keys or existing node data with this adapter.

Ordinary backup evidence compares the entire canonical block after the inherited
eight-byte deferred-pool prefix, including all required ancestors because backup
iteration order is not guaranteed. Backup visibility plus isolated reopen is
evidence about these nonfinalized blocks in a running OS. It is not a guarantee
of atomic snapshot publication, physical persistence, torn-write recovery, a
power cut, device-cache behavior, finalized RocksDB durability, or all possible
crash timings. Mempool acknowledgment is explicitly not a durability promise.
Pending/completed internal queues and primitive-cache state are unobserved.

The existing [wallet fault controls](fault-controls.md) cover private wallet
write stages separately. This driver neither duplicates those hooks nor adds
node failpoints. The ordinary [lifecycle controls](lifecycle-controls.md) retain
their clean shutdown and namespace checks.

## Explicit live execution

Use a clean committed checkout and matching receipts from the shared
[acceptance build workflow](acceptance.md). Live builds, signing, and process
kills require explicit workload authorization under [AGENTS.md](../../AGENTS.md);
the adapter retains `--human-run` as its execution opt-in. A coordinator may
schedule these exact runs when the user explicitly authorizes them. Preparation
and review do not themselves execute the command.

```sh
python3 tests/slh-dsa-b128s/acceptance/crash_controls.py --human-run \
  --node /absolute/path/to/slh/zakurad \
  --node-build /absolute/path/to/node-slh-build.json \
  --host /absolute/path/to/slh-dsa-b128s-fixture-host \
  --host-build /absolute/path/to/host-build.json \
  --signer /absolute/path/to/slh-dsa-b128s-public-fixture \
  --signer-build /absolute/path/to/fixture-signer-build.json \
  --version 5 --artifacts /absolute/path/to/new-crash-v5
```

Repeat with `--version 6` and a fresh directory. Use `node-slh`, `host` and
`signer` build recipes; shielded proving parameters are not used. The
driver starts no Cargo or Docker command. Startup, kill, backup and RPC waits
are bounded by existing helpers; kill wait is ten seconds. Unix SIGKILL semantics
are required. The controller and OS remain running during subject interruption.

## Source reuse and offline checks

MIT/Apache-2.0 research revision
`e759cb86a06510893f8e7d1eb986b7025401c8c9` supplies
`node/tests/pq_history_live.py` (isolated ordinary backup, exact UTXOs and fresh
replay), `pq_relay_live.py` (same-authorization reentry after a longer branch),
and `pq_live.py` (exact block submission and restored-parent checks). The product
calls existing `ManagedNode`, `Network`, `copy_blocks`, `backup_tip`, `Controls`,
`single_artifact`, identity witnesses and `reconcile_saved` directly. Necessary
adaptations are a local isolated network adapter, the explicit process handshake,
SLH identities and bounded old/new classification. No research checkout, Docker
wrapper, benchmark stack, new dependency or node production change is required.

The pinned upstream state configuration and
`crates/zakura-state/src/service/non_finalized_state/backup.rs` at
`9b175e9d3d46a6aa4cfb5552517c3d828852ecbc` were checked for the five-second
asynchronous backup interval, arbitrary chain iteration order, ordinary block
format and revalidation on restore. Their inherited behavior is unchanged.

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/acceptance \
  -p test_crash_controls.py -v
```

The mocks model independent node chains and persisted snapshots, including both
legal mined outcomes. They reject wrong/missing kills, stale processes, no-op
restart/replay/reorg/reentry, skipped checkpoints, changed exact bytes/identity/
source/config, partial UTXOs, unrelated diagnostics and incomplete backups. No
process, real signal, signer, daemon, socket listener or proof generator runs.
