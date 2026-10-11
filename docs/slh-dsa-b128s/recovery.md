# Backup and recovery

The wallet supports key backups and operational snapshots.
The library and [CLI commands](cli.md#recovery-commands) implement both formats.
Live recovery and terminal tests remain open.

## Backup types

| Type | Contents | Limit |
| --- | --- | --- |
| Encrypted root and inventory | Local keys, policies, cosigner details, and generated addresses | No payment journal. Restore stays monitor-only. |
| Operational snapshot with matching encrypted backup | Keys, inventory, proposals, signatures, reservations, and journal history | Cannot prove that no newer state or signature was lost. |

An **allocator** is the watch store permitted to issue addresses and manage payment reservations.
A **monitor** can scan public inventory. It cannot issue addresses, sign, or submit payments.
A **fingerprint** is a hash that identifies exact data.
A fingerprint from an untrusted backup cannot authenticate that backup.

## Save backups

Keep a backup for each required cosigner.
A 2-of-3 policy needs two keys. A 15-of-15 policy needs all fifteen.

Enrollment publishes and checks a backup before it makes new addresses available.
Keep a recovery copy outside disposable working state before you issue or export addresses.

For an operational snapshot, retain this complete set:

- `backup.tpq`: the matching encrypted keys and inventory.
- `receipt.json`: identities and hashes for the snapshot.
- `watch/state.json`: the exact watch state.
- `watch/journal/`, when present: all retained objects, including valid orphan and temporary objects.

`WatchStore::save_operational_snapshot` locks the allocator and checks payment history before the copy.
The journal limits include retained orphan and temporary objects.
Unrelated temporary files and root-level `state-pre-v3` files are outside the format.
Journal files do not receive an additional encryption layer.

Protect the snapshot directory.
Retain the receipt fingerprint through an independent trusted channel.

## Restore keys and inventory

`Wallet::decrypt` and `Wallet::load_backup` check the approved profile and decrypt the backup.
They regenerate enrolled local public keys and compare their commitments with the inventory.
The format uses Argon2id, ChaCha20-Poly1305, a 56-byte header, and an 8 MiB plaintext limit.
It contains no payment journal.

`recovery::restore_inventory` requires the independently checked latest inventory fingerprint.
It creates `backup-original.tpq`, `backup-restored.tpq`, and `watch/` in a new private directory.
It replaces the allocator identity and retires old receive/change ranges.
Those ranges remain available for scans.
The restored store stays **monitor-only**, including after synchronization.

## Restore an operational snapshot

`recovery::restore_operational_snapshot` checks the files and their links.
It preserves saved approvals, signatures, transactions, and reservations.
It writes a new encrypted backup, replaces the allocator identity, and retires old address ranges.
Unknown authority discards cached coins, the scan checkpoint, and reorg undo data.
Synchronization rebuilds these observations from trusted history, starting at the wallet birthday.
This rescan is required even when the saved checkpoint matches the trusted tip.
Known authority retains authenticated cached observations, but scan completeness is cleared.
Payments require synchronization with a trusted node and the normal approval checks.
New addresses require generation, enrollment, and a covering backup.

The restore has two trust modes:

| Mode | Requirement and result |
| --- | --- |
| Unknown | Restore stays monitor-only. Synchronization, restart, and an empty mempool cannot change this role. |
| Known authority | Requires a separately trusted latest receipt fingerprint, reconciliation of outstanding signatures, and retirement of every old allocator. |

A snapshot from a monitor always restores a monitor.
Neither mode can recover signatures made after capture or prove that no newer state was lost.

## Publication and failures

Restore uses bounded copies and private files.
It checks the files before atomic publication into a new directory under a trusted, stable parent.
It does not overwrite an existing destination.
Linux and Apple targets support publication. Other platforms return an error.
A final directory-sync error can leave a complete new directory while it reports failure.

Keep the original backups.
After a publication error, inspect the destination before another attempt.

Focused tests cover formats, key checks, enrollment, snapshots, trust modes, paths, and publication failures.
They do not establish live funded recovery.
The [acceptance guide](acceptance.md) describes human tests.
[Recovery provenance](../../crates/pq-wallet/RECOVERY_PROVENANCE.json) records source reuse.
