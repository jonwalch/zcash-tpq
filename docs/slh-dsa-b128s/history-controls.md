# Wallet history refusal and reconciliation

The [history controls](../../tests/slh-dsa-b128s/acceptance/history_controls.py)
prepare actual CLI cases against disposable Regtest nodes. The
[fault service](../../tests/slh-dsa-b128s/acceptance/history_service.py) forwards
read-only RPC requests to the trusted loopback node and changes selected history
responses. **Live execution remains pending.** Offline mocks establish the
adapter's assertions and bounds; they do not establish wallet/node acceptance.
The [acceptance runbook](acceptance.md) supplies the exact build receipt workflow.

The setup authenticates a mature classical coinbase on both nodes and confirms
two 3,000,000-zatoshi SLH outputs. One output backs a signed, saved, unsubmitted
payment. A successful `propose-preview` proves the other output remains eligible
for a new proposal. Both checks must succeed again after removing the fault, at
the same unchanged tip. This adapts the pinned research offline-recovery flow so
a reservation or missing funds cannot stand in for a history refusal.

| Case | Required behavior |
| --- | --- |
| Unavailable chain context | Exact `HistoryUnavailable` diagnostic; cached funds retained and current balance unknown. |
| Missing tip block hash | Exact `HistoryUnavailable`; no proposal or partial export. |
| Inconsistent tip hash | Exact `ChainChanged`; no new payment authority. |
| Pruned required raw block | Fresh public and inventory-restored monitors fail with `HistoryUnavailable`, then discover the full funded balance after reconciliation. |
| Inconsistent raw block | A changed previous-block-hash byte must fail authenticated discovery with `ChainChanged`, then reconcile from honest bytes. |
| Bounded incomplete scan | One block makes real progress while balance and activation remain unknown; the subsequent full scan discovers both outputs. |

Cached fault cases cover the original allocator, a public monitor and an
unknown-authority operational snapshot restore. Every monitor refuses receiver
allocation, proposal creation, signing and submission with the precise
`MonitorOnly` diagnostic, before or during uncertainty and after reconciliation.
Fresh rescan cases separately cover a public monitor and an inventory-only
restore. A never-scanned monitor can observe zero cached funds; it must not
present that observation as a complete or current zero balance.

The allocator's existing authority remains valid for offline receiver issuance.
These controls do not revoke it. They verify that failures leave its manifest,
receive/change cursors and saved payment authority unchanged. Cached context
faults may only clear scan completeness/context; cached coins, undo data and
checkpoint remain exact. Fresh rescans may persist authenticated partial
progress. A v3 journal generation may advance with a scan commit, while its
roots, capabilities and other authority fields must remain exact. This fixture
does not force journal migration. Saved proposal, partial and transaction export
hashes must remain byte-for-byte equal throughout. Tips, mempools and both funded
outpoints remain unchanged on both nodes.

The service binds `127.0.0.1` with an ephemeral port and accepts only numeric
loopback upstreams. It allows the five wallet read methods, with exact parameter
shapes; submission and mining are refused. Each service admits at most 4,096
POST requests over a 300-second window, at most 4 KiB per request and 16 MiB per
upstream response. Client socket timeout is two seconds; upstream connection/read
timeout is five seconds with an additional five-second body deadline. The
serial listener is closed when the case ends. Unmodified replies retain their
exact bytes, including decimal amounts. Per-request evidence contains method,
mode and byte hashes, with an explicit marker proving the selected fault was
applied. Genuine upstream errors do not count as injected failures.

After committing the integrated source, a human can produce matching builds and
run this command from the clean product checkout:

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

Repeat with version `6` and a fresh artifact directory. `--classical multisig`
uses the existing classical multisig funding helper when that combination is
needed. Builds and actual node/wallet/terminal runs are human-only under
[AGENTS.md](../../AGENTS.md); no build is launched implicitly. Roots, passwords,
backups, operational snapshots and terminal transcripts stay in the private
temporary workspace and are deleted. The public execution receipt starts
incomplete, records failures, and binds source/build hashes, funding, fault
events, state hashes and successful reconciliation. No performance, primitive
entry or production readiness result is inferred.

The permitted focused offline check is:

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/acceptance -p 'test_history*.py' -v
```

Research `node_scan.py`, `recovery_live.py`, `recovery_controls.py` and the fake
RPC discovery tests provide the attributed patterns; the existing SLH
`wallet_live.Demo`, `Network`, strict transport and independent format oracle are
reused. See the [source map](../../tests/slh-dsa-b128s/acceptance/sources.json) and
[notice](../../tests/slh-dsa-b128s/acceptance/NOTICE). Production wallet behavior,
upstream Zakura behavior and immutable reference corpora are unchanged.
