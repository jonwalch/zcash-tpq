# Human acceptance tests

These drivers prepare Regtest tests for the node, wallet, CLI, and recovery.
**Live acceptance remains open.**
[AGENTS.md](../../AGENTS.md) reserves the builds and live commands below for human execution.
Offline mocks check the drivers. They do not establish daemon execution or cryptographic independence.

The drivers reuse pinned command flows, public classical signing, block construction,
RPC comparisons, and terminal controls.
[Source mappings](../../tests/slh-dsa-b128s/acceptance/sources.json) record hashes and adaptations.
The product does not depend on a research checkout, alternate PQ backend, or research history.

## Build receipts

Start from a clean, committed checkout.
Install the [Python requirements](../../tests/slh-dsa-b128s/wallet/formats/requirements.txt).
Choose a private absolute directory with space for release builds and node databases.
Create its parent directory first.
Use a new directory for each build and run.

The toolchain file selects the changing `stable` channel.
The minimum Rust version is 1.97.
Receipts record the actual compiler version.

Run these builds as a human:

```sh
export SLH_ACCEPTANCE_ROOT=/absolute/private/slh-acceptance
mkdir -m 700 "$SLH_ACCEPTANCE_ROOT"
python3 tests/slh-dsa-b128s/acceptance/build.py --human-run --kind node-default --artifacts "$SLH_ACCEPTANCE_ROOT/node-default"
python3 tests/slh-dsa-b128s/acceptance/build.py --human-run --kind node-slh --artifacts "$SLH_ACCEPTANCE_ROOT/node-slh"
python3 tests/slh-dsa-b128s/acceptance/build.py --human-run --kind wallet-slh --artifacts "$SLH_ACCEPTANCE_ROOT/wallet-slh"
python3 tests/slh-dsa-b128s/acceptance/build.py --human-run --kind host --artifacts "$SLH_ACCEPTANCE_ROOT/host"
python3 tests/slh-dsa-b128s/acceptance/build.py --human-run --kind signer --artifacts "$SLH_ACCEPTANCE_ROOT/signer"
```

Each build directory contains `build.json`, `build.log`, the copied executable, and a private target directory.
Node builds also retain `verifier-identity.json`.
Builds select exact packages and features with `--locked`, `--release`, and `--no-default-features`.
The public fixture signer uses a separate manifest and lockfile.
These commands do not request the observer feature.
Live enabled-node paths require the eight-field identity and `runtime_supported: true`.

Additional build kinds are:

| Kind | Purpose |
| --- | --- |
| `wallet-default` | Default-feature checks. It cannot replace the enabled wallet below. |
| `host-shielded` | Host with `shielded-fixtures` for output and spend tests. |
| `wallet-faults` | Compile the library test with `--no-run`. Copy Cargo's identified executable as `wallet-fault-tests`. |

The fault build does not execute the ignored matrix.
Native executable recipes reject `CARGO_BUILD_TARGET`.
Each receipt records source, relevant file hashes, lockfiles, commands, features,
compiler versions, flags, executable hash, and identity.
Version probes run in the same directory as Cargo.
Source must remain unchanged through build and execution.
Source changes require new matching builds.
Receipts provide traceability. They cannot attest a hostile compiler or machine.

## Node and lifecycle tests

```sh
python3 tests/slh-dsa-b128s/acceptance/node_live.py --human-run \
  --node "$SLH_ACCEPTANCE_ROOT/node-slh/zakurad" \
  --node-build "$SLH_ACCEPTANCE_ROOT/node-slh/build.json" \
  --host "$SLH_ACCEPTANCE_ROOT/host/slh-dsa-b128s-fixture-host" \
  --host-build "$SLH_ACCEPTANCE_ROOT/host/build.json" \
  --signer "$SLH_ACCEPTANCE_ROOT/signer/slh-dsa-b128s-public-fixture" \
  --signer-build "$SLH_ACCEPTANCE_ROOT/signer/build.json" \
  --version 5 --classical single --artifacts "$SLH_ACCEPTANCE_ROOT/node-v5-single"

python3 tests/slh-dsa-b128s/acceptance/lifecycle_controls.py --human-run \
  --node-default "$SLH_ACCEPTANCE_ROOT/node-default/zakurad" \
  --node-default-build "$SLH_ACCEPTANCE_ROOT/node-default/build.json" \
  --node-slh "$SLH_ACCEPTANCE_ROOT/node-slh/zakurad" \
  --node-slh-build "$SLH_ACCEPTANCE_ROOT/node-slh/build.json" \
  --host "$SLH_ACCEPTANCE_ROOT/host/slh-dsa-b128s-fixture-host" \
  --host-build "$SLH_ACCEPTANCE_ROOT/host/build.json" \
  --signer "$SLH_ACCEPTANCE_ROOT/signer/slh-dsa-b128s-public-fixture" \
  --signer-build "$SLH_ACCEPTANCE_ROOT/signer/build.json" \
  --version 5 --classical single --artifacts "$SLH_ACCEPTANCE_ROOT/controls-v5-single"
```

Run each command for all four combinations of version `5|6` and classical profile `single|multisig`.
Use a new artifact directory for each combination.
`single` uses P2SH CHECKSIG. `multisig` uses public-key 2-of-3 CHECKMULTISIG.

The node driver authenticates mature classical coinbases on two nodes.
Classical spends fund SLH outputs. The driver does not create SLH coinbases.
Its main checks are:

- Genuine 16-check transactions relay and fill a 64-check block template.
- Excess transactions remain for the next block.
- A genuine 17-check transaction fails because of the check limit.
- Restart, reorg, and reentry preserve saved transaction bytes.
- Rollback to tip 103 makes candidate 104 reject a saved NU7 classical control.
- Funding fails below SLH activation 110 and reenters after activation.

A distinct mature outpoint isolates the classical rollback control.
Restart below NU7 clears the inherited RPC retry queue.
The driver then reconciles saved transactions across absent, side-chain, mempool, and confirmed states.
Before each restart after a reorg or rollback, the driver observes the ordinary backup.
It requires complete canonical block bytes and removal of invalidated block backups.
These checks wait for the existing asynchronous writer. They do not force a flush
or change node shutdown, storage, or P2P behavior.

For a separate durable-history run, add `--finalized-history` to `node_live.py`.
This longer run crosses the 1,000-block reorg window.
It replays actual blocks into a new peerless database, compares UTXOs, and spends a recovered output.
It observes the ordinary tip backup before reopening the replay node.
It does not inspect finalized-database internals.

The [lifecycle driver](lifecycle-controls.md) tests default/enabled compatibility,
mixed inputs, 64/65-check blocks, configuration refusal, and namespace isolation.
The [transparent driver](transparent-controls.md) adds quorum, template,
signature-family, authorization-change, and reorg controls.
Their guides specify required positive controls and relay/consensus differences.

## Wallet and terminal tests

```sh
python3 tests/slh-dsa-b128s/acceptance/wallet_live.py --human-run \
  --node "$SLH_ACCEPTANCE_ROOT/node-slh/zakurad" \
  --node-build "$SLH_ACCEPTANCE_ROOT/node-slh/build.json" \
  --cli "$SLH_ACCEPTANCE_ROOT/wallet-slh/pq-wallet" \
  --cli-build "$SLH_ACCEPTANCE_ROOT/wallet-slh/build.json" \
  --host "$SLH_ACCEPTANCE_ROOT/host/slh-dsa-b128s-fixture-host" \
  --host-build "$SLH_ACCEPTANCE_ROOT/host/build.json" \
  --threshold 2 --participants 3 --inputs 1 --version 5 --classical single \
  --artifacts "$SLH_ACCEPTANCE_ROOT/wallet-v5-2of3"

python3 tests/slh-dsa-b128s/acceptance/terminal_smoke.py --human-run \
  --cli "$SLH_ACCEPTANCE_ROOT/wallet-slh/pq-wallet" \
  --cli-build "$SLH_ACCEPTANCE_ROOT/wallet-slh/build.json" \
  --artifacts "$SLH_ACCEPTANCE_ROOT/terminal"
```

Run the wallet cases below.
Repeat accepted cases for versions 5 and 6.
Include both classical funding profiles across the runs.
The matrix contains no timing or memory measurements.

| Threshold / participants | Inputs | Expected result |
| --- | --- | --- |
| 1/1, 2/3, 8/10, 10/10, 14/15, 15/15 | 1 | Independent roots, explicit review/approval, signing/assembly, relay/mining, recovery, subsequent spend |
| 2/3 | 8 | Exactly 16 checks, all input shares preserved across restore/refresh |
| 2/3 | 9 | 18 checks: exact insufficient-eligible-funds/payment-limits diagnostic before proposal |
| 15/15 | 2 | 30 checks: same explicit refusal before proposal |
| 15/15 plus `--missing-required-key` | 1 | Restore only 14 roots after deletion of all working roots. A fresh proposal cannot assemble. |

Accepted runs use public `key-export`, `enroll-prepare`, and `enroll` commands.
The driver independently calculates keys, policies, and fingerprints.
Each enrollment uses the immediately preceding encrypted backup.
Change approval is separate from common payment review.
Wrong approvals and insufficient signatures must produce exact diagnostics.
Retries must preserve partials and final transaction bytes.

Before it restarts the nodes after recovery, the wallet driver observes their
ordinary backups and checks the complete canonical block bytes. Local wallet
operations do not synchronize the node's asynchronous backup task. This restart
precedes the rollback, so there are no invalidated blocks to exclude. The driver
reuses the node driver's backup observer and still requires the exact tip after
reopening. It does not force a flush or change node storage or shutdown behavior.

The wallet driver also tests:

- Exhaustion and renewal of finite receive inventories for allocators and monitors.
- Snapshot recovery of partial, assembled, submitted, and archived payments.
- Known-authority recovery with trusted receipts after old allocators retire.
- Monitor-only restrictions after inventory or unknown-authority restore.
- Deletion of working roots, quorum recovery, and a new spend from restored change.
- Wrong passwords, corrupt backups, missing state, wrong receipts, and existing destinations.
- Archive, export, resume, and tip refresh with unchanged transaction bytes.
- Later receipts to retired addresses, rollback, recovery, and subsequent spend.

The missing-key case captures snapshots before complete payment authority exists.
It cannot use a previously complete signature set to bypass the missing key.

The terminal suite tests backups, enrollment, watch stores, rekeying, and unavailable nodes.
It also tests UTF-8, empty or long inputs, cancellation, 1,024-byte Unicode passwords,
and normalization or whitespace differences.
It checks terminal echo and restoration.
It does not log terminal diagnostics or secrets.

Use ordinary `python3` for terminal tests.
The suite rejects `python -O` because it retains assertions from the source implementation.

## Evidence and test limits

`execution.json` starts with `complete: false`.
Only a successful end sets it to true.
Failed attempts retain configurations, logs, RPC hashes, public artifacts, and file hashes.
The driver checks source and binaries again after execution.

Wallet roots, encrypted backups, snapshots, passwords, and terminal transcripts remain in a private temporary directory.
The driver removes that directory. Removal does not guarantee secure erasure.
Retained wallet artifacts contain public hashes, receipts, and transaction identifiers.
Fixture keys are public test material.
Host-supplied parent bytes remain untrusted until both nodes authenticate the outputs and tip.

The [validation index](validation.md) describes recorded evidence and open work.
Additional scenario guides cover:

- [Verifier-call capture](observation-controls.md).
- [Shielded outputs](shielded-controls.md) and [spends with anchors](shielded-spend-controls.md).
- [Hostile history](history-controls.md).
- [Wallet write faults](fault-controls.md) and [node process crashes](crash-controls.md).

Mocks, source review, and fixed-corpus results cannot establish funded acceptance.
No exhaustive funded run of all 120 policy shapes is recorded.
The independent crypto and digest references retain their original scope.
Performance studies remain separate and require p50, p95, and p99 results.
They must also identify the workload and hardware baseline.

## Focused driver checks

These commands run Python tests and fixture-host tests without a live node:

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/acceptance -p 'test_*.py' -v
cargo fmt -p slh-dsa-b128s-fixture-host -- --check
cargo test --locked -p slh-dsa-b128s-fixture-host --bin slh-dsa-b128s-fixture-host
cargo clippy --locked -p slh-dsa-b128s-fixture-host --all-targets -- -D warnings
```
