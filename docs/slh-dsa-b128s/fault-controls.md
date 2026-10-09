# Wallet durable fault controls

This human adapter prepares executable wallet library fault cases using the
existing private durable hooks. **No fault matrix or live recovery result has
been executed during preparation.** Read the [wallet](wallet.md),
[recovery](recovery.md) and [acceptance](acceptance.md) contracts first.

The controller launches exactly the ignored
`payment::tests::faults::human_fault_case` test from a receipt-bound wallet **test
executable**. Ordinary wallet and node binaries have no fault environment
variables, operational switches or new entropy APIs. The small test-only receive
wrapper calls the existing hook unchanged. Write, rename, file/directory sync,
journal formats, approval source and operational signer entropy are unchanged.

## Human commands

Use a clean committed checkout and a new directory under a trusted, stable,
private parent. These builds and fault/signing/backup/snapshot operations are
human-only under [AGENTS.md](../../AGENTS.md):

```sh
export SLH_FAULT_ROOT=/absolute/private/slh-wallet-faults
mkdir -m 700 "$SLH_FAULT_ROOT"
python3 tests/slh-dsa-b128s/acceptance/build.py --human-run \
  --kind wallet-faults --artifacts "$SLH_FAULT_ROOT/build"
python3 tests/slh-dsa-b128s/acceptance/fault_controls.py --human-run \
  --wallet-tests "$SLH_FAULT_ROOT/build/wallet-fault-tests" \
  --wallet-build "$SLH_FAULT_ROOT/build/build.json" \
  --case migration --mode both --artifacts "$SLH_FAULT_ROOT/migration"
```

Repeat with `--case receive`, `backup`, `entropy`, `final-publication` and `quota`,
using a fresh artifact directory each time. `--mode io` runs returned-error
controls; `--mode kill` is supported only for migration, receive and backup.
Requests combining `--case all --mode kill` refuse before starting any child.
`--mode both` selects both mechanisms where supported and the returned-error
mechanism for the other cases. `--case all --mode both` covers all 59 named
case/mechanism combinations. Each is bracketed by successful independent runs
with fresh state, followed by a separately launched reopen/recovery phase.

The build recipe uses locked release compilation with `--lib --no-run`; it copies
only Cargo's exact reported `zakura-pq-wallet` library test executable. Building
does not execute ignored tests. The execution adapter requires a matching clean
source/build receipt and rechecks the executable and source after the matrix.
It never launches Cargo, a daemon, a terminal or the operational CLI itself.

## Prepared cases and eligibility

All fixtures use the existing synthetic trusted `Source` and wallet test setup:
one real disposable SLH wallet, three receive entries, two change entries, one
2,000,000-zatoshi eligible synthetic output, an approved v6 payment and a durable
reservation. The test fixture installs its inventory before saving a covering
encrypted backup, as existing library tests do; it does not exercise the public
CLI enrollment ceremony. This isolates wallet durability and is not funded
Regtest or independently authenticated node evidence.

Migration, receiver and backup cases start with a real saved partial and complete
transaction authorization. Entropy and final-publication cases start with an
eligible approved payment and reservation before any partial exists. Positive
runs execute the same operations without the selected failure; unrelated
failures never count as the expected negative.

| Case | Named checkpoint / mechanism | Required result |
| --- | --- | --- |
| Migration | `CreateJournal`, `CreateObjects`, initial `ObjectsSync`, `JournalSync`, `WatchSync`, first `ObjectWrite`, `ObjectVerify`, `ObjectSync`, `ObjectPublish`, `ObjectsSyncAfterPublish`, `RecoveryWrite`, `RecoveryVerify`, `RecoverySync`, `RecoveryPublish`, `RecoveryDirectorySync`, root `FileWrite`, `FileSync`, `Publish`, `DirectorySync` | Reopen the exact old v2 root before root publication or the complete new v3 root after it; retry migration and retain the exact legacy recovery copy and authorization |
| Receiver allocation | Root `FileWrite`, `FileSync`, `Publish`, `DirectorySync` | Returned errors release no receiver; reopened cursor reflects old or completed publication; later issuance cannot repeat a previously returned receiver |
| Encrypted backup | `Write`, `FileSync`, `Verify`, `Publish`, `DirectorySync` | Keep the exact previous generation; new generation is absent or fully authenticated; no clobber or partial candidate acceptance |
| Final publication | Existing pre-sign checkpoint relocates the private watcher after reservation | Actual final publication returns storage failure and releases no partial; old reservation reopens and a later signing attempt succeeds |
| Entropy checkpoint | Existing `sign_payment_with_rng` test-only checkpoint returns an entropy error before signing | Return no partial, keep the reservation and retry successfully; supplied bytes never reach the SLH signer |
| Journal quota | Real journal `Limits.bytes = 1` against an eligible nonempty immutable-object batch | Exact `Quota` refusal before any write callback; unchanged authority, then publish/read the same batch after reopening with the ordinary quota |

Hooks fire **before** the named operation. Root and backup `DirectorySync` fire
**after** atomic publication and before syncing the containing directory. A
process killed there can leave the complete new state visible. `ObjectsSync`
occurs once while creating journal directories and again after object publication;
the controller names those occurrences separately. Other repeated object hooks
target their first occurrence. This is not an exhaustive every-object matrix.

Every reopened case checks exact saved payment records where authority existed,
change reservation/cursor preservation, byte-identical cached signing and assembly,
and two submissions of the same saved bytes around a synthetic unavailable-node
response. Cached signing is retried with a deliberately failing pre-sign RNG and
must make zero calls. A conflicting payment must remain ineligible, and the next
receiver must match the next unissued inventory coordinate.

The reopened state is copied through the current coherent operational-snapshot
API, the old working allocator is removed, and the snapshot is restored with
`SnapshotTrust::Unknown`. Records remain exact; receive stays refused and scan
completeness stays cleared. This does not grant known-authority restoration or
prove a snapshot was globally latest. The normal live recovery adapter owns
funded-node and independently reconciled authority checks.

## Receipts, bounds and limitations

`execution.json` starts incomplete and retains attempted phases, process IDs,
unique public tokens, exact reached-stage markers, state-file hashes, invariant
checks, return codes and failures. The controller validates the stage, token,
case, phase and PID before sending SIGKILL, requires a SIGKILL return code, then
launches a fresh verifier. A timeout, missing marker, assertion failure, unrelated
process exit or absent reopen receipt fails the case. Evidence is saved before
launch, before kill and after each phase. Failed positive controls fail the whole
bracket. Library stdout/panic text is suppressed instead of copied to public logs.

Receipts are bounded to 4 KiB each. Each ordinary child has a 240-second deadline;
the controller allows 30 seconds to reach an interruption checkpoint and the
child abandons the waiting checkpoint after 45 seconds. Child exit/kill cleanup
has a ten-second deadline. There is no unbounded retry or disk-filling loop.
Private roots, encrypted backups, authorizations, snapshots, requests and
control-marker files live in a fresh mode-0700 temporary directory and are
removed after the case. Public receipts contain none of those bytes. Interrupted
controllers can leave private temporary directories for the operator to remove;
deleting them is not secure erasure.

The adapter requires Unix private-file, directory-sync and SIGKILL semantics;
the existing snapshot no-clobber implementation supports Linux and Apple targets.
Other platforms are not claimed. SIGKILL tests process interruption while the OS
and filesystem remain running. Returned test-hook I/O errors are a separate
mechanism, and final-publication relocation is specifically a missing-path
failure. None demonstrates a power cut, torn sector, filesystem recovery, OS
quota/ENOSPC behavior, device cache persistence or upstream node database durability.
The quota case measures the journal's existing configured admission rule, not OS
disk exhaustion.

The wallet entropy case exercises its pre-sign error boundary, not failure of
`getrandom` inside the operational signer. The unchanged signer unit test
`tests::entropy_failure_has_no_signature_or_fallback` directly covers the private
signer's fallible-RNG branch and requires one failed request with no signature.
Its independent signature conformance controls remain separate. No OS entropy
suppression or deterministic operational fallback is supplied or claimed.

## Source and offline checks

The driver reuses pinned research commit
`da638d4045074f7957aec3fb3fb018bd66b96d05`:
`crates/pq-wallet/src/payment/tests/archive.rs` migration stages and old/new root
checks; `payment/tests/sequences.rs` final-publication relocation and retry;
`journal/tests.rs` peak-name quota preflight; `watch.rs` receiver reservation
hooks; and `storage.rs` backup publication stages. Current product fixture,
recovery and signer modules are used directly. The adaptations add a private
process boundary, bounded receipts, causally matched positive controls and
separate reopen verification. [Source mappings](../../tests/slh-dsa-b128s/acceptance/sources.json)
record exact hashes. No research checkout is required at execution time.

Permitted offline mocks launch no process and exercise every named case, bracket
ordering, source/test command selection, strict receipts, wrong stage/PID/token,
missing invariant, arbitrary failure, no-op interruption and failed final
positive control:

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/acceptance -p 'test_fault_controls.py'
```

The ignored driver is compiled and linted during preparation; no invocation of
it, no actual kill/quota matrix, no backup/recovery/signing flow and no live node
run is an offline validation result.
