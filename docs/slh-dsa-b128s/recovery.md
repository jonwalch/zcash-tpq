# Encrypted inventory and operational recovery

The feature-enabled wallet reuses the existing version 1 encrypted root and
inventory envelope, strict canonical JSON, durable backup publication,
enrollment, allocator lock, discovery/reorg bookkeeping and v2/v3 payment
journal. Only SLH suite `f7` is supported. This document describes the library
APIs; it does not claim CLI, live funded recovery or terminal backup validation.

`Wallet::decrypt` and `Wallet::load_backup` authenticate the envelope against an
independently approved profile and regenerate **every** enrolled local public
root and commitment. The password rules, Argon2id parameters, 56-byte header,
ChaCha20-Poly1305 authentication and 8 MiB plaintext bound are unchanged.
`enroll_backup` checks the complete approved origin mapping and cumulative
inventory, publishes and verifies the covering backup, then installs it.
Publication failure never installs the candidate inventory. Export and pairing
still require an independently authenticated inventory fingerprint and a
recovery copy outside disposable working state.

`recovery::restore_inventory` takes the encrypted backup, approved profile and
independently reconciled latest inventory fingerprint. It creates a new private
directory with `backup-original.tpq`, a fresh `backup-restored.tpq`, and `watch/`.
It rotates the allocator and retires the complete previous receive/change
ranges, preserving all entries for scanning. The result is **monitor-only**:
this mode cannot establish complete payment history or outstanding authority.

`WatchStore::save_operational_snapshot` holds the allocator lock while validating
all reachable journal pages, capabilities, predecessors, historical aliases and
reservations. Its documented artifact set is:

- `backup.tpq`: the exact matching encrypted root/inventory backup;
- `receipt.json`: bounded canonical metadata binding the backup hash, exact
  state-file hash, wallet, suite, profile, inventory, cursors and journal root;
- `watch/state.json`: the exact authoritative existing state;
- `watch/journal/`: the existing immutable object store, when present, including
  **every retained orphan or temporary object** under its existing quotas.

This is a coherent state-and-journal copy, not a clone of unrelated files in the
working directory. Non-authoritative root temporary files and old `state-pre-v3`
copies remain untouched at the source. The destination obtains a new allocator
lock file. Failed first journal migrations may legitimately leave a v2 state
with an empty journal directory or retained orphan objects; those remain
recoverable. No journal data is added to the encrypted root backup and no new
encrypted journal container is introduced.

`recovery::restore_operational_snapshot` can recover using only that documented
artifact set. It copies bounded streams, validates the copied state again,
rotates the allocator, retires issuance, saves a fresh covering encrypted backup,
and preserves approved effects, exact saved authorization bytes and reservations.
Cached coins and undo history remain available, but scan completeness and trusted
node context are cleared. New payment operations must complete the existing
trusted-node synchronization and approval checks. New receive/change issuance
requires new generation/enrollment and its covering backup.

A receipt is an integrity binding, **not proof that no outstanding authority was
omitted**. `SnapshotTrust::KnownAuthority` requires a receipt fingerprint retained
through an independently trusted channel, reconciliation of the latest known
authority generation, and retirement of every previous allocator. It cannot
prove that a newer lost snapshot or later signature never existed.
`SnapshotTrust::Unknown` restores a monitor permanently; synchronization, an empty
mempool and reopening do not promote it to an allocator. A snapshot originally
held by a monitor also remains a monitor, even with a trusted receipt.

All publication stages use private files and directories, file/directory sync,
full validation before publication, and atomic no-clobber publication into a
**new** destination under a trusted stable parent. The safe pinned Rustix wrapper
provides atomic directory `NOREPLACE` on Linux and Apple targets; unsupported
platforms return an explicit error. A destination race never overwrites existing
state. As with existing backup publication, a directory-sync failure can leave a
fully published new directory while returning an error; retain the previous
recovery artifacts and reconcile before retrying.

Source and license attribution are recorded in
[`RECOVERY_PROVENANCE.json`](../../crates/pq-wallet/RECOVERY_PROVENANCE.json).
Focused library tests cover independent encrypted answers, strict schema/root
validation, all receiver policy shapes, enrollment failure, discovery/reorg,
corruption, private-file/path checks, trusted versus unknown recovery and atomic
publication. Live payment/recovery/discovery, terminal backup and restart/reorg
matrices remain pending human execution.
