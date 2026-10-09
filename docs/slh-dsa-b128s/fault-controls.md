# Wallet fault tests

The driver prepares wallet library tests at existing private write hooks.
Actual fault and recovery runs remain open.
The [wallet](wallet.md), [recovery](recovery.md), and [acceptance](acceptance.md) guides specify expected behavior.

The controller runs only the ignored `payment::tests::faults::human_fault_case` test.
It requires the exact wallet test executable and matching build receipt.
Ordinary wallet and node binaries have no added fault switches or entropy APIs.
Write operations, formats, approval code, and operational signer entropy remain unchanged.

## Human commands

Use clean, committed source and a new directory under a trusted, stable, private parent.
Run these commands as a human under [AGENTS.md](../../AGENTS.md):

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

Repeat with cases `receive`, `backup`, `entropy`, `final-publication`, and `quota`.
Use a new artifact directory each time.

| Mode | Behavior |
| --- | --- |
| `io` | Returned-error controls |
| `kill` | Migration, receive, and backup only |
| `both` | Both mechanisms where supported. Returned errors for the other cases. |

`--case all --mode kill` fails before child startup.
`--case all --mode both` covers all 59 named combinations.
Successful independent runs with new state occur before and after each case.
A separate process checks reopen and recovery.

The build uses locked release compilation with `--lib --no-run`.
It copies Cargo's identified `zakura-pq-wallet` test executable without test execution.
The controller checks matching source before execution and again afterward.
It does not launch Cargo, a daemon, a terminal, or the CLI.

## Fixtures and cases

The fixture uses the existing synthetic trusted `Source` and wallet test setup.
It contains a disposable SLH wallet, three receive entries, two change entries,
and one eligible 2,000,000-zatoshi synthetic output.
The v6 payment has approval and a durable reservation.
The fixture installs inventory before it saves a covering backup.
It does not exercise CLI enrollment or funded Regtest.

Migration, receive, and backup cases start with saved partials and complete authorization.
Entropy and final-publication cases start before any partial exists.
Positive runs perform the same operation without the fault.
Unrelated failures cannot satisfy a negative control.

| Case | Named checkpoint / mechanism | Required result |
| --- | --- | --- |
| Migration | `CreateJournal`, `CreateObjects`, initial `ObjectsSync`, `JournalSync`, `WatchSync`, first `ObjectWrite`, `ObjectVerify`, `ObjectSync`, `ObjectPublish`, `ObjectsSyncAfterPublish`, `RecoveryWrite`, `RecoveryVerify`, `RecoverySync`, `RecoveryPublish`, `RecoveryDirectorySync`, root `FileWrite`, `FileSync`, `Publish`, `DirectorySync` | Reopen the exact old v2 root before root publication or the complete new v3 root after it. Retry migration and retain the exact legacy recovery copy and authorization |
| Receiver allocation | Root `FileWrite`, `FileSync`, `Publish`, `DirectorySync` | Returned errors release no receiver. Reopened cursor reflects old or completed publication. Later issuance cannot repeat a previously returned receiver |
| Encrypted backup | `Write`, `FileSync`, `Verify`, `Publish`, `DirectorySync` | Keep the exact previous generation. New generation is absent or fully authenticated. No clobber or partial candidate acceptance |
| Final publication | Existing pre-sign checkpoint relocates the private watcher after reservation | Actual final publication returns storage failure and releases no partial. Old reservation reopens and a later signing attempt succeeds |
| Entropy checkpoint | Existing `sign_payment_with_rng` test-only checkpoint returns an entropy error before signing | Return no partial, keep the reservation and retry successfully. Supplied bytes never reach the SLH signer |
| Journal quota | Real journal `Limits.bytes = 1` against an eligible nonempty immutable-object batch | Exact `Quota` refusal before any write callback. Unchanged authority, then publish/read the same batch after reopening with the ordinary quota |

Hooks occur before the named operation.
Root and backup `DirectorySync` hooks occur after atomic publication but before directory synchronization.
A kill there can leave the complete new state visible.
`ObjectsSync` occurs during directory creation and after object publication.
The controller names those occurrences separately.
Other repeated object hooks select their first occurrence.
This is not an exhaustive test of every object.

## Reopen requirements

Each reopened case checks exact saved payment records and retained reservations or cursors.
Cached signing and assembly must preserve bytes.
Two submissions around a synthetic unavailable-node response must use the same saved transaction.
The public API must return `SubmissionUnknown` after it records that state durably.
The synthetic source returns `HistoryUnavailable`; that error is not the public API result.
Cached signing must make zero calls to a deliberately failing pre-sign RNG.
A conflicting payment must remain ineligible.
The next receiver must match the next unissued coordinate.

The test saves an operational snapshot and removes the old working allocator.
It restores with `SnapshotTrust::Unknown`.
Records must stay exact, receive must remain refused, and scan completeness must remain cleared.
This does not establish known authority or a globally latest snapshot.
Live recovery separately checks funded nodes and reconciled authority.

## Receipts and limits

`execution.json` starts incomplete and records phases, PIDs, tokens, stages,
state hashes, invariant checks, return codes, and failures.
Before SIGKILL, the controller checks stage, token, case, phase, and PID.
It requires a SIGKILL exit and then starts a separate verifier.
Missing markers, timeouts, assertions, unrelated exits, or absent reopen receipts cause failure.
Evidence is saved before launch, before kill, and after each phase.
A failed positive control fails the bracket.
Public logs exclude test stdout and panic text.

| Item | Bound |
| --- | --- |
| Receipt | 4 KiB |
| Ordinary child | 240 seconds |
| Time to interruption checkpoint | 30 seconds |
| Child wait at checkpoint | 45 seconds |
| Exit/kill cleanup | 10 seconds |

Private artifacts stay in a new mode-0700 temporary directory.
The driver removes it after each case.
An interrupted controller can leave it for operator cleanup.
Deletion does not guarantee secure erasure.
There is no unbounded retry or disk-fill loop.

The adapter requires Unix file, directory-sync, and SIGKILL behavior.
Snapshot publication supports Linux and Apple targets.
Other platforms have no stated support.
The OS and filesystem remain active during SIGKILL.
Returned hook errors and final-publication missing-path failures are separate mechanisms.

These tests do not establish power-loss, torn-write, filesystem-recovery,
OS quota, device-cache, or node-database behavior.
The quota case tests the configured journal limit, not OS disk exhaustion.
The entropy case tests the pre-sign error, not `getrandom` failure inside the signer.
The signer unit test `tests::entropy_failure_has_no_signature_or_fallback` checks its private fallible-RNG branch separately.
There is no OS entropy suppression or deterministic operational fallback.

## Source and offline tests

The driver adapts research revision `da638d4045074f7957aec3fb3fb018bd66b96d05`:

- `crates/pq-wallet/src/payment/tests/archive.rs`: migration and old/new roots.
- `payment/tests/sequences.rs`: final-publication relocation and retry.
- `journal/tests.rs`: quota preflight.
- `watch.rs`: receiver reservation hooks.
- `storage.rs`: backup publication stages.

It uses current product fixture, recovery, and signer modules directly.
The adaptations add process boundaries, bounded receipts, matched positives, and separate reopen checks.
The [source map](../../tests/slh-dsa-b128s/acceptance/sources.json) records exact hashes.
No research checkout is needed at runtime.

Run the offline mocks:

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/acceptance -p 'test_fault_controls.py'
```

Mocks cover every case, bracket order, command selection, receipts, stage identities,
missing invariants, arbitrary failures, no-op interruptions, and failed final positives.
They launch no process.
Compilation and lint checks of the ignored driver do not establish an actual fault-matrix result.
