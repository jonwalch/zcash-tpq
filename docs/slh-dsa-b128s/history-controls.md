# Wallet tests with faulty node history

The [history driver](../../tests/slh-dsa-b128s/acceptance/history_controls.py)
uses disposable nodes and the real CLI.
Its [fault service](../../tests/slh-dsa-b128s/acceptance/history_service.py)
forwards read-only RPC and changes selected history responses.
**Live execution remains open.**
Offline mocks check driver assertions and bounds, not wallet/node acceptance.
The [acceptance guide](acceptance.md) specifies matching builds.

## Funded controls

Both nodes authenticate a mature coinbase and two confirmed SLH outputs of 3,000,000 zatoshis each.
One output supplies a signed, saved, unsubmitted payment.
A successful `propose-preview` proves that the other output remains eligible.
Both controls must succeed again after fault removal, at the unchanged tip.
Thus, reservations or missing funds cannot substitute for a history failure.

| Case | Required behavior |
| --- | --- |
| Unavailable chain context | Exact `HistoryUnavailable` diagnostic. Cached funds retained and current balance unknown. |
| Missing tip block hash | Exact `HistoryUnavailable`. No proposal or partial export. |
| Inconsistent tip hash | Exact `ChainChanged`. No new payment authority. |
| Pruned required raw block | Fresh public and inventory-restored monitors fail with `HistoryUnavailable`, then discover the full funded balance after reconciliation. |
| Inconsistent raw block | A changed previous-block-hash byte must fail authenticated discovery with `ChainChanged`, then reconcile from honest bytes. |
| Bounded incomplete scan | One block makes real progress while balance and activation remain unknown. The subsequent full scan discovers both outputs. |

Cached cases use the original allocator, a public monitor, and an unknown-authority snapshot restore.
Each monitor must report `MonitorOnly` for allocation, proposals, signing, and submission.
This restriction applies before faults, during faults, and after recovery.
Fresh scans separately use a public monitor and an inventory-only restore.
Zero cached funds in an unscanned monitor cannot become a complete current balance.

The allocator retains permission to issue receivers offline.
Failures must preserve its manifest, cursors, and saved payment authority.
Cached-context faults can clear scan completeness and context only.
Cached coins, undo data, and the checkpoint must remain exact.
Fresh scans can save authenticated partial progress.
A v3 journal generation can advance with a scan commit, but authority fields must stay exact.
The fixture does not force journal migration.

Saved proposal, partial, and transaction export hashes must stay unchanged.
Both nodes must retain their tips, mempools, and funded outpoints.

## Fault service limits

| Property | Limit |
| --- | --- |
| Listener | `127.0.0.1`, temporary port, serial requests |
| Upstream | Numeric loopback address |
| Methods | Five wallet read methods with exact parameter shapes. No submission or mining. |
| Requests | 4,096 POST requests within 300 seconds |
| Request / upstream response | 4 KiB / 16 MiB |
| Client timeout | 2 seconds |
| Upstream timeout | 5 seconds for connection/read, plus a 5-second body deadline |

The listener closes at the end of each case.
Unmodified responses retain exact bytes, including decimal amounts.
Request evidence records method, mode, and byte hashes.
A marker must show that the selected fault occurred.
Ordinary upstream errors cannot count as injected failures.
The unavailable-context guard uses pinned Zakura's BIP70 chain name `test`,
including for Regtest. The driver still authenticates its configured profile,
tip and raw blocks; the RPC chain-name string alone does not establish Regtest.

## Human command

Create matching builds from clean, committed source.
Run this command as a human:

```sh
python3 tests/slh-dsa-b128s/acceptance/history_controls.py --human-run \
  --node "$SLH_ACCEPTANCE_ROOT/node-slh/zakurad" \
  --node-build "$SLH_ACCEPTANCE_ROOT/node-slh/build.json" \
  --cli "$SLH_ACCEPTANCE_ROOT/wallet-slh/pq-wallet" \
  --cli-build "$SLH_ACCEPTANCE_ROOT/wallet-slh/build.json" \
  --host "$SLH_ACCEPTANCE_ROOT/host/slh-dsa-b128s-fixture-host" \
  --host-build "$SLH_ACCEPTANCE_ROOT/host/build.json" \
  --version 5 --classical single \
  --artifacts "$SLH_ACCEPTANCE_ROOT/history-v5-single"
```

Repeat with version `6` and a new artifact directory.
Use `--classical multisig` for the existing multisig funding profile when required.
The command does not launch builds implicitly.
[AGENTS.md](../../AGENTS.md) reserves builds and live tests for humans.

Private roots, passwords, backups, snapshots, and transcripts stay in a temporary directory, which the driver deletes.
The public receipt records failures, source/build hashes, funding, fault events, state hashes, and successful recovery.
It does not establish performance, primitive counts, or production readiness.

## Focused tests and attribution

Run the offline tests:

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/acceptance -p 'test_history*.py' -v
```

The driver adapts research discovery, recovery, and fake-RPC tests.
It reuses `wallet_live.Demo`, `Network`, strict transport, and the independent format oracle.
The [source map](../../tests/slh-dsa-b128s/acceptance/sources.json)
and [notice](../../tests/slh-dsa-b128s/acceptance/NOTICE) record attribution.
Production wallet behavior, upstream behavior, and reference corpora remain unchanged.
