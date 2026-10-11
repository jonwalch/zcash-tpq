# Node process crash tests

`acceptance/crash_controls.py` prepares three checkpoints for each of two spend types:
ordinary classical 2-of-3 and genuine SLH 1-of-1.
Both isolated nodes receive SIGKILL at each checkpoint.
One version run requires six logical checkpoints and twelve SIGKILL exits.
Offline mocks check the driver. Live crash recovery remains open.

Both nodes authenticate mature coinbase funding with public fixture keys.
Classical funding creates separate classical and SLH parents of 3,000,000 zatoshis each.
Positive block proposals surround a malformed quorum or bad SLH signature control before admission.
An unrelated rejection cannot satisfy a control.

## Checkpoints and permitted results

| Checkpoint | State before SIGKILL | Permitted result after isolated reopen |
| --- | --- | --- |
| `admitted-unmined` | Both mempools contain exact subject bytes and identities. The unchanged chain has an observed backup. | The same chain and UTXOs. The subject can be absent or present with exact bytes in the volatile mempool. |
| `mined-unbacked` | A new block confirms the subject. The ancestor has a backup. There is no requested wait for the new backup. | The exact old ancestor with parent restored, or the complete new block with parent spent. Subject UTXOs must match that choice. |
| `reorg-backed` | Two new empty blocks replace the subject branch. Parents are restored and orphan outputs are absent. All recent canonical backups are observed. | The complete replacement chain and exact UTXOs. The subject can be absent or present with exact bytes in the volatile mempool. |

`mined-unbacked` means no requested backup wait.
The asynchronous backup can already be complete.
Each node receives its own old/new classification.
A lost new block must replay from exact saved bytes and produce the expected tip.
After reorg reopen, the same authorization must confirm in a new block.
Retries do not call the signer.
Other tracked transactions must stay exact.
Partial UTXO states and unrelated mempool transactions are not permitted outcomes.

All nodes have no peers. Explicit `submitblock` calls transfer blocks.
Peer synchronization cannot hide missing local recovery.
Fork nodes replay at most 128 ancestor blocks.
A normal run ends at height 117, before the 1,000-block finalization window.
The driver uses ordinary asynchronous backups without a debug flush or database changes.

## Process and artifact evidence

Before SIGKILL, `checkpoints.json` records the checkpoint, token, observed state,
allowed chain hashes, PIDs, and source/configuration/binary/file identities.
The controller checks that the same child process and PID remain alive.
It sends SIGKILL and requires the exact Unix `-SIGKILL` exit status.
Restart must produce a distinct live process.
Missing signals, prior exits, stale PIDs, no-op restarts, timeouts, and changed identities cause failure.
The checkpoint comes from RPC observations, not an internal write marker or worker-completion barrier.

Receipts retain UTXOs, transaction states, classifications, PIDs, saved bytes,
bounded fork history, configurations, RPC transcripts, and logs.
`execution.json` remains incomplete until all six checkpoints and final retries succeed.
State directories remain local and are excluded from the public hash manifest.

Use only public fixtures and disposable node data.
Do not use operational keys or existing node databases.

Backup checks compare each complete canonical block after the eight-byte deferred-pool prefix.
They include required ancestors because backup iteration order is not fixed.
Observed backups and isolated reopen test nonfinalized blocks with a running OS.
They do not establish physical persistence, atomic snapshots, torn-write recovery,
power-loss behavior, device-cache behavior, or finalized RocksDB durability.
Mempool acknowledgment does not promise durability.
Internal queue and primitive-cache states remain unobserved.

[Wallet fault tests](fault-controls.md) cover wallet write stages separately.
[Lifecycle tests](lifecycle-controls.md) cover clean shutdown and namespaces.
This driver adds no node failpoints.

## Human command

Create matching builds from clean, committed source with the [acceptance workflow](acceptance.md).
Agents must obtain user approval before running the driver under [AGENTS.md](../../AGENTS.md):

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

Repeat with version `6` and a new directory.
Use the `node-slh`, `host`, and `signer` recipes.
No shielded proving parameters are needed.
`--human-run` is required. It does not replace user approval for agent execution.
The driver starts no Cargo or Docker command.
Existing helpers bound startup, backup, and RPC waits.
Kill waits have a ten-second limit.
Unix SIGKILL behavior is required. The controller and OS stay active.

## Source and offline tests

The driver adapts MIT/Apache-2.0 research revision
`e759cb86a06510893f8e7d1eb986b7025401c8c9`:

- `node/tests/pq_history_live.py`: backups, UTXOs, and replay.
- `pq_relay_live.py`: authorization reentry after a longer branch.
- `pq_live.py`: block submission and restored parents.

It directly uses existing product node, backup, fixture, identity, and reconciliation helpers.
The adaptations add isolated nodes, a process handshake, SLH identities, and bounded old/new classification.
No research checkout, Docker wrapper, new dependency, or node production change is required.

The pinned upstream backup code uses a five-second asynchronous interval and revalidates restored blocks.
Its block format and iteration behavior remain unchanged.
The reference is `crates/zakura-state/src/service/non_finalized_state/backup.rs`
at `9b175e9d3d46a6aa4cfb5552517c3d828852ecbc`.

Run the offline mocks:

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/acceptance \
  -p test_crash_controls.py -v
```

Mocks model independent chains and persisted snapshots, including both permitted mined outcomes.
They reject missing kills, stale processes, no-op transitions, omitted checkpoints,
changed identities, partial UTXOs, unrelated failures, and incomplete backups.
They start no process, signal, signer, daemon, listener, or proof generator.
