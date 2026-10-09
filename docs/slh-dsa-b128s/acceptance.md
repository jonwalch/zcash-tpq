# SLH human acceptance

These adapters prepare disposable Regtest node, wallet/CLI, watch-only and
recovery acceptance for `slh-dsa-b-128s-exp-v1`. **No live acceptance result is
claimed here.** All binary builds and actual terminal/node/wallet/signing runs
below are human-only under [AGENTS.md](../../AGENTS.md). Offline mocks and bounded
fixture-host tests establish adapter checks, not daemon execution or cryptographic
independence. See the [protocol](protocol.md), [CLI commands](cli.md),
[runtime contract](runtime.md) and [lifecycle controls](lifecycle-controls.md).

The adapters reuse pinned research command flows, public classical signing,
block construction, RPC/history comparisons and terminal controls. They import
existing product fixture transport and the unchanged independent wallet-format
oracle. [Source mappings](../../tests/slh-dsa-b128s/acceptance/sources.json) record
source and target hashes, adaptation reasons and new glue. There is no research
checkout, alternate PQ backend or research history dependency. Fixes are scoped
to our acceptance tooling and SLH integration; inherited node behavior is preserved.

## Build receipts

Start from a clean committed product checkout with its pinned Rust toolchain and
Python requirements from
[`wallet/formats/requirements.txt`](../../tests/slh-dsa-b128s/wallet/formats/requirements.txt).
Choose a private absolute directory with enough disk space for separate release
builds and node databases. Its parent must already exist; each build/run directory
must be new. The following commands are for a human to execute:

```sh
export SLH_ACCEPTANCE_ROOT=/absolute/private/slh-acceptance
mkdir -m 700 "$SLH_ACCEPTANCE_ROOT"
python3 tests/slh-dsa-b128s/acceptance/build.py --human-run --kind node-default --artifacts "$SLH_ACCEPTANCE_ROOT/node-default"
python3 tests/slh-dsa-b128s/acceptance/build.py --human-run --kind node-slh --artifacts "$SLH_ACCEPTANCE_ROOT/node-slh"
python3 tests/slh-dsa-b128s/acceptance/build.py --human-run --kind wallet-slh --artifacts "$SLH_ACCEPTANCE_ROOT/wallet-slh"
python3 tests/slh-dsa-b128s/acceptance/build.py --human-run --kind host --artifacts "$SLH_ACCEPTANCE_ROOT/host"
python3 tests/slh-dsa-b128s/acceptance/build.py --human-run --kind signer --artifacts "$SLH_ACCEPTANCE_ROOT/signer"
```

Each directory contains `build.json`, `build.log`, the copied executable and its
private target directory. Node builds also retain `verifier-identity.json`.
`wallet-default` is an available build kind for separate default-feature checks;
it is not accepted as the enabled wallet input below. Builds use `--locked`,
`--release`, `--no-default-features`, exact packages and explicit features. The
isolated public signer uses its separate manifest/lock. No observer feature is
requested. Daemon identities must match the eight-field public runtime contract;
the enabled live paths require `runtime_supported: true`.

The receipt binds the source commit, relevant source inventory/hash, root and
signer locks, exact command/features, compiler/cargo versions, compiler flags,
executable hash and identity. Version probes run in the same product directory
as Cargo. Source must remain unchanged through each build and execution; changing
product source requires new matching builds. These locally generated receipts
provide traceability, not an attestation of a hostile compiler or build machine.

## Node and lifecycle commands

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

Run each command for the four combinations of version `5|6` and classical
`single|multisig`, using a fresh artifact directory for each. `single` uses
P2SH CHECKSIG; `multisig` uses fixed public-key 2-of-3 CHECKMULTISIG. Add
`--finalized-history` to `node_live.py` in a separate run to cross the 1,000-block
reorg window, replay actual block bytes into a fresh peerless database, compare
UTXOs and spend a recovered output. This is a substantially longer human workload.
The driver records that it does not inspect finalized-database internals.

The main node flow authenticates actual mature classical coinbases on two nodes,
then creates ordinary classical spends funding SLH outputs. It never creates an
SLH coinbase. Genuine 16-check transactions relay, fill a 64-check template/block
and leave excess transactions for the next block; a genuine 17-check transaction
must fail for the limit reason. Reorg, restart and saved-byte reentry follow.
Rollback reaches tip 103, below the NU7 candidate-height gate at 105; candidate
104 rejects a saved NU7 classical control. A distinct mature control outpoint
avoids interfering with SLH funding. Funding rejects below SLH activation 110,
then reenters under active rules. The adapter preserves the inherited RPC retry
queue: it clears old retries by restarting below NU7 and subsequently reconciles
saved transactions across absent, side-chain, mempool and confirmed states.

The separate controls driver tests identical classical blocks/UTXOs on default
and enabled binaries, exact enabled/default SLH-spend disagreement on a legally
funded common parent, mixed classical/SLH inputs in both orders at relay and block
validation, exact 64/65-check direct blocks, default-build configuration refusal,
and isolated state/backup namespaces for each rules change. It checks unchanged
state after rejection and peerless restart under the original configuration.

Additional [transparent controls](transparent-controls.md) prepare genuine missing
classical quorum, same-input signature-family substitution, unsupported-template
mixing in both orders, mixed rollback/reactivation/reorg, separate classical and
SLH transactions in one block, and same-TXID authorization changes. The guide
records the relay/direct-consensus distinction and required positive setup;
these source-prepared cases have not been run against a daemon.

## Wallet and terminal commands

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

Use the wallet command with these explicit cases. Repeat accepted payment cases
for versions 5 and 6; include both classical funding profiles across the runs.
No timing or memory measurement is part of this matrix.

| Threshold / participants | Inputs | Expected prepared scenario |
| --- | --- | --- |
| 1/1, 2/3, 8/10, 10/10, 14/15, 15/15 | 1 | Independent roots, explicit review/approval, signing/assembly, relay/mining, recovery, subsequent spend |
| 2/3 | 8 | Exactly 16 checks, all input shares preserved across restore/refresh |
| 2/3 | 9 | 18 checks: exact insufficient-eligible-funds/payment-limits diagnostic before proposal |
| 15/15 | 2 | 30 checks: same explicit refusal before proposal |
| 15/15 plus `--missing-required-key` | 1 | Delete all working roots before authorization; restore only 14; fresh proposal cannot assemble |

Normal accepted runs use the CLI's public `key-export`, `enroll-prepare` and
`enroll` flows with independently recomputed policies/keys/fingerprints. Each
candidate inventory is enrolled against the immediately preceding encrypted
backup; the driver does not bypass revision rules. Participant-local change
approval is checked separately from the common review fields. Wrong approval and
subquorum assembly require their exact diagnostics; cached partials and final
transaction bytes remain unchanged on retries.

Owners exhaust their finite receive ranges, import new covering inventory into
both owner and monitor-only watchers, exhaust again and agree on confirmed balances. Snapshot
recovery covers pending partials and assembled authority, then submitted and
archived payment records. Independently retained receipt fingerprints authorize
known-authority recovery only after old allocators are retired. Inventory-only
and unknown-authority restores remain monitors, including refusal to submit
cached authority. Working private roots are actually removed, only a surviving
quorum is restored, old ranges remain retired, and restored change funds a new
no-change payment. The separate all-of-n missing-root control captures snapshots
before any complete payment authority exists.

The driver also prepares wrong-password/corrupted-backup rejection, missing
snapshot state, wrong trusted receipt and existing-destination preservation;
archive/export/resume; saved-tip rollback with explicit refresh approval and
unchanged transaction bytes; and a later receipt to a retired address whose
balance is undone/recovered by block invalidate/reconsider and then spent.

The terminal suite ports the pinned research backup/enrollment/watch flow,
rekeying, wrong-password controls, unavailable-node behavior, strict UTF-8,
empty/overlong input, cancellation, exact 1,024-byte Unicode passwords and
normalization/whitespace distinctions. It checks terminal echo flags/restoration.
Run with ordinary `python3`; optimized `python -O` is rejected because the port
retains its original assertions. Terminal diagnostics and secrets are not logged.

## Evidence and coverage boundaries

`execution.json` begins with `complete: false`; only a successful driver end
sets it true. Node configurations/logs, RPC request/response hashes, public
transaction/block artifacts and file hashes are retained with failed attempts.
Binaries and source are rechecked after the run. Wallet private roots, encrypted
backups, recovery snapshots, passwords and terminal transcripts live only in a
private temporary directory that is removed; retained wallet artifacts are public
hashes, receipts and transaction identifiers. Deletion is not a secure-erasure
claim. Fixture classical keys and deterministic SLH fixture keys are public test
material, never operational keys. Parent bytes supplied to a host helper are
untrusted until both actual nodes authenticate the outputs and tip.

| Area | Prepared executable human cases | Offline evidence / remaining limitation |
| --- | --- | --- |
| Node and classical migration | Both versions/profiles, relay, transaction/template/block budgets, both activation rollbacks, enabled/default comparison, mixed-input rejection, namespaces/restart, optional durable replay | Mock RPC/queue/control tests and bounded real host serialization/signature/block tests; all actual daemon cases unrun |
| Wallet and recovery | Matrix above, public enrollment, independent roots, quorum/subquorum, watch exhaustion/replenishment, known/unknown restore, subsequent spends, refresh/archive/resume, late receipt/reorg | Strict fake CLI executes group/payment/recover/refresh and missing-root orchestration; independent immutable format calculations reused. Later archive/snapshot corruption/late-receipt and full terminal flows are source-prepared, not established by those mocks |
| Terminal/passwords | Full terminal adapter above | Parser/provenance mocks and pinned-source adaptation only; no PTY or password/KDF run performed |
| All 120 threshold shapes | Existing independent structural/format corpus remains unchanged | Selected funded matrix above; the driver accepts other 1 <= m <= n <= 15 shapes, but no exhaustive funded 120-shape run or result is claimed |
| Primitive entry counts and shielded routing | Opt-in Regtest primitive attempts and bounded capture receipts are prepared; see [observations.md](observations.md) | Counts describe process/window attempts and require complete enabled capture with positive controls. No daemon receipt has been executed. Actual shielded-proof mixed-pool lifecycle fixtures still need a separate attributable adapter and proof generation |
| Fault injection and hostile history | Snapshot authentication/missing-state/no-clobber controls plus [funded hostile-history refusals and reconciliation](history-controls.md) are prepared | The bounded loopback service covers unavailable, missing, inconsistent and pruned history; restored monitors and incomplete rescans retain authority limits. Only mocks have run. Process kills at durable-write boundaries and entropy/quota orchestration remain unprepared |
| Performance | None | No workload measurements or production budget recommendation; any separate study must retain p50/p95/p99 and the project's workload/hardware baseline |

The remaining tooling gaps are distinct from prepared scenarios awaiting human
execution. Neither source inspection, a default-disabled build, immutable corpus
success nor a fake RPC run can be reported as funded SLH acceptance. The existing
crypto and digest references retain their independence and original provenance.

Permitted offline adapter checks (no binary or service launched):

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/acceptance -p 'test_*.py' -v
cargo fmt -p slh-dsa-b128s-fixture-host -- --check
cargo test --locked -p slh-dsa-b128s-fixture-host --bin slh-dsa-b128s-fixture-host
cargo clippy --locked -p slh-dsa-b128s-fixture-host --all-targets -- -D warnings
```
