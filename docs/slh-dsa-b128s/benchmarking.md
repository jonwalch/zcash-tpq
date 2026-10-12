# Benchmark framework

The framework records primitive and offline wallet/payment timings and imports
saved node and resource observations. It writes raw attempts, source and artifact hashes, and reports
with median (p50), p95 and p99 for every measured metric. The code is under
[`benchmarks/slh-dsa-b128s`](../../benchmarks/slh-dsa-b128s).

Focused tests use synthetic records, mocked resource files and retained public
signatures. No new performance results,
live node acceptance or production budgets are established by those tests.
Builds and measurement commands below are for a human to execute. Agents must
not run profiling, live nodes or performance matrices under the delivery task's
human-only validation rule. An `--execute` flag is an execution guard, not
authorization for an agent to run a workload.

## What is available

| Metric or facility | Current support | Boundary |
| --- | --- | --- |
| Key generation | Product `SigningKey::from_seed` timer | Includes public-root construction; excludes seed derivation and key destruction |
| Signing | Product `SigningKey::sign` timer | Includes OS entropy, signing and mandatory verification before release |
| Signature verification | Valid and same-length corrupted signature timers | External Pure interface with empty context; fixture preparation is outside timing |
| CPU and memory for primitives | Linux/macOS process CPU, endpoint RSS and one final high-water reading per fresh process | CPU/wall is core equivalents; peak RSS includes setup and warmups and is read before exit |
| SLH wallet/payment stages | Actual wallet setup, prepare, sign, assemble and authorization verification | Stage times include coupled durable journal writes; funding is an offline synthetic source |
| Payment shape matrix | v5/v6, 1-of-1/2-of-3, 1/2/5 inputs, cached/generated inventory | Every SLH attempt uses fresh wallet storage; modes do not flush machine caches |
| Classical payment controls | Matched P2SH single-signature and 2-of-3 transparent transactions | No equivalent durable classical wallet workflow; total times are not equivalent wallet-payment costs |
| Independent payment checks | Pinned SLH reference, independent transaction digest/encoding oracle and classical signature checks | Check every public attempt after the measured process exits; no live UTXO or chain acceptance claim |
| Transaction size | Exact saved serialized byte count | Does not establish transaction validity, block inclusion or a full wallet payment |
| Node resources | Linux process, cgroup-v2 and isolated-interface snapshot library | Processes, cgroups and interfaces keep different accounting boundaries |
| Mempool | Saved Prometheus gauges and growth between two observations | Serialized bytes, cost bytes and process memory remain distinct |
| Block time | Saved Zakura block-driver trace adapter | Full verification plus state commit, or checkpoint residence; not isolated consensus CPU time |
| Propagation | Strict saved-event import contract | Required live receive/admit event hooks are not implemented yet |
| Reports | JSON, CSV and HTML; compatible per-process comparisons | No pooled quantiles or statistical-significance claim |

The primitive fixture is a synthetic 101-byte Regtest signing frame. Its digest
does not come from a funded transaction. These cases do not exercise UTXO lookup,
transaction authorization, wallet storage, RPC, the mempool or a node.
The production signer and verifier are called directly; the public fixture
signer is not a benchmark dependency. Node dependency graphs exclude the
benchmark executable and the signer.

`repeated-input` reuses the seed or message. `varied-input` changes the keygen
seed or the signing/verification message. Signing and verification use one key
per process. Varied verification prepares and checks a fresh signature outside
each timer. Neither mode flushes processor or operating-system caches, so
neither establishes a cold-cache measurement.

## Register and execute a primitive run

Use Python 3.11 or later and the repository's Rust toolchain. Run commands from
the product repository root. Commit all source changes first. Choose artifact
directories outside tracked source; ignored `.context` directories are suitable.
Use a new directory for every build, plan, run and report.

Create a host profile JSON file with these fields. Replace all example hardware
facts with the effective limits for the measurement host. In a container, the
CPU count of the host does not establish the container's CPU entitlement.

```json
{
  "description": "replace with machine and isolation description",
  "cpu_model": "replace with exact processor model",
  "effective_cpu_cores": 4,
  "memory_limit_bytes": 17179869184,
  "affinity": "replace with CPU affinity and quota details",
  "power_policy": "replace with governor, power mode and thermal conditions"
}
```

The profile is an operator declaration. Portable host facts are also collected
and checked again before execution. The primitive runner does not independently
verify the declared affinity, quota or power mode.

The following is a bounded example for the human operator. Its sample counts
show command syntax; they are not sufficient evidence of stable tail latency.
Preflight performs untimed key generation and signing even for verification.
The process deadline includes that setup.

```sh
python3 benchmarks/slh-dsa-b128s/run.py build \
  --output .context/bench-build-01 --timeout 1800 --execute

python3 benchmarks/slh-dsa-b128s/run.py plan \
  --build .context/bench-build-01 --output .context/bench-run-01 \
  --host-profile .context/bench-host.json \
  --case keygen --case sign --case verify --case verify-invalid \
  --samples 10 --warmup 2 --repetitions 3 \
  --cache-mode repeated-input --timeout 1800

python3 benchmarks/slh-dsa-b128s/run.py run .context/bench-run-01 --execute

python3 benchmarks/slh-dsa-b128s/run.py summarize .context/bench-run-01 \
  --output .context/bench-report-01
```

`build` compiles only the isolated benchmark workspace, using its own lockfile.
The receipt records the exact compiler, Cargo configuration hashes, relevant
build environment, source tree and all tracked source-file hashes. It copies
and hashes the selected executable. Custom `RUSTC` overrides are rejected.
Relative `CARGO_HOME` paths are resolved from the benchmark crate directory,
where the runner invokes Cargo. The receipt hashes and checks that directory's
configuration even when the Python command starts at the repository root.
Builds are not hermetic or independently reproducible merely because they have
receipts. The hashes bind the files that this runner observed.

`plan` checks the build receipt and writes the case list, sample counts, warmups,
fresh-process repetitions, input mode and bounds. It starts no measurement.
Primitive plans reserve 4 KiB for each stdout and normalized record, including
its newline, and 64 KiB for a terminal failure record in the normalized stream.
The per-process output bound and the full 64 MiB record bound must fit this
reservation. Execution enforces the per-record bound too. Split a larger study
into separate plans. Unexpected extra output or stderr can still fail a run.
`run` rechecks these inputs, claims the directory once, supervises each child
with wall-time and output bounds, and retains stdout and stderr. A missing row,
wrong case outcome, partial line, extra row or nonzero exit prevents completion.
Failures stay in the attempt stream. An interrupted or failed run needs a new
plan directory for its retry.

The raw `attempts.jsonl`, `manifest.json`, logs and `receipt.json` are the primary
artifacts. Reports verify their inventory before reading records. Keep them
together. Do not edit saved inputs to make an incomplete run appear complete.
After a hard kill, a run may have only an incomplete running receipt. Use
`summarize --recover-incomplete` to inspect retained observations in a separate
report. Recovery checks the retained manifest hash and snapshots the current
artifacts; it cannot establish their original identity without the finalized
inventory. The report stays incomplete and cannot enter a matched comparison.
Recovery does not bypass a finalized inventory or repair malformed records.
Retain the original evidence and register a new run for a retry.

Every operation record has its timing, CPU and RSS endpoints. A final record in
the separate `process` phase contains one process high-water reading. Thus one
process supplies only one peak sample. The report shows p50=p95=p99 for that
one-sample peak distribution; it does not estimate a process-peak population.
Setup costs and earlier warmups can dominate that peak.

## Register an offline wallet/payment run

These cases use the actual SLH `WatchStore` payment workflow. A synthetic
`ChainSource`/`PaymentSource` supplies known transparent previous outputs. The
wallet derives signing messages from each transaction and the supplied previous
outputs. No RPC call, node, mining, mempool or peer network is involved. The
fixture substitutes for an authenticated funding source only inside this test;
it does not relax the production trusted-UTXO boundary.

`single` means a 1-of-1 SLH policy or the classical P2SH CHECKSIG control. `multisig`
means a 2-of-3 SLH policy or classical 2-of-3 P2SH. The controls match version,
input count, signer threshold, output count and the stated transaction fixture.
Their exact scripts and byte counts differ. Inputs and recipient value match;
fees use actual serialized actions, so fees and change can differ. They do not provide a classical
equivalent of SLH wallet persistence. The comparator rejects different case
identities instead of silently treating these totals as equivalent work.

The timings have these boundaries:

| Metric | Scope |
| --- | --- |
| `payment_inventory_ns` | Generated inventory, including SLH enrollment and verified backup publication; omitted in cached cases |
| `payment_wallet_setup_ns` | Fresh SLH watch-store setup and sync in both inventory modes |
| `payment_prepare_persist_ns` | Actual SLH payment preparation and its durable writes |
| `payment_sign_persist_ns` | Actual SLH signing, mandatory verification and durable writes |
| `payment_assemble_persist_ns` | Actual SLH authorization assembly and durable writes |
| `payment_assembly_ns`, `payment_sign_ns` | Classical transaction controls without a durable wallet journal |
| `payment_verify_ns` | All-input verification through SLH `TransactionContext` or the classical script-aware control; neither is full node validation |
| `payment_total_ns` | One enclosing foreground interval, including generated inventory and wallet setup when applicable |
| `transaction_bytes` | Exact serialized transaction bytes, checked independently against each saved public artifact |

The production API couples wallet writes with payment stages. These names
preserve that boundary. They do not estimate isolated fsync cost. The driver
checks saved wallet state after timing, but a readback is not a power-loss test.
Synthetic chain construction, header hashing and block serialization happen
before wallet setup timing. Lookups use prepared hashes and serialized bytes;
copying a source response remains part of the wallet call. Cached SLH cases
prepare this source before the total and CPU interval too. Generated SLH cases
need the new inventory's keys first, so their enclosing total and CPU interval
still include source preparation. Do not label those totals as isolated wallet
cost. Reports record and display this distinction. Older reports without this
declaration retain their original boundaries; inspect their recorded source.
Signature retention for later readback moves the returned partials instead of
cloning their signature strings inside the signing stage.
Cached mode prepares backed inventory outside the foreground interval. It still
sets up fresh payment watch stores and uses the actual wallet signer. Generated
mode includes the inventory work in the enclosing interval. Neither mode claims
a cold or warm processor cache. Never add stage p50, p95 or p99 values to obtain
a total; those quantiles can refer to different attempts.
Classical cached controls reuse their prepared secp256k1 key pairs. Their key
handling does not exercise the SLH wallet API. Classical verification uses the
public keys prepared with the inventory and a verification-only context. It does
not derive public keys from secret scalars inside the verification timer.

Choose an existing directory on the filesystem whose wallet writes you intend
to measure. Pass it as `--wallet-storage-root`. Both cached inventory backups
and each attempt's fresh private stores are created below this root; `TMPDIR`
does not choose their location. Keep this directory outside public artifacts.
Temporary stores are removed on normal exit. Interrupted processes can leave
disposable private stores here; do not archive them as public evidence.

Add a `wallet_storage` object to the host profile for payment runs. Replace the
example declarations with the actual device, filesystem, mount options and sync
behavior. These are operator declarations, not a power-loss durability test:

```json
"wallet_storage": {
  "description": "replace with device and storage isolation description",
  "medium": "replace with local SSD, HDD, RAM disk, or other medium",
  "filesystem": "replace with actual filesystem and version",
  "mount_options": "replace with effective mount options",
  "sync_policy": "replace with filesystem and device flush guarantees"
}
```

Registration records the resolved root, directory/device identity, filesystem
block sizes and flags, and these declarations. Execution rechecks the identity
and passes the registered root to the child. Reports retain it in provenance and
comparison metadata. A changed root, device, filesystem flags or storage profile
cannot silently count as the same persistence workload. Historical payment runs
without storage identity can be inspected, but cannot establish matched storage
comparisons. Primitive reporting does not require this payment-specific field.

Prepare the [pinned independent reference](../../tests/slh-dsa-b128s/reference/README.md)
first. The payment checker also reuses the independent wallet-format oracle,
which requires the pinned Python package in
[`wallet/formats/requirements.txt`](../../tests/slh-dsa-b128s/wallet/formats/requirements.txt).
Install it in the Python environment used for the runner and its tests:

```sh
python3 -m pip install -r tests/slh-dsa-b128s/wallet/formats/requirements.txt
```

The checker records hashes of the loaded Python and native package files.
`plan-payment` copies only its allowlisted reference source files, licenses, build
receipt and C library into the run directory. It validates their identities
without signing, verification or measurement. The snapshot stays with the run.

This example registers two cases, one SLH wallet workflow and one classical
transaction control. All dimension flags are required. Repeat a dimension flag
to select more cases; the runner registers their Cartesian product. The small
sample count demonstrates commands and does not establish tail stability.

```sh
mkdir -p .context/wallet-storage
python3 benchmarks/slh-dsa-b128s/run.py plan-payment \
  --build .context/bench-build-01 --output .context/payment-run-01 \
  --host-profile .context/bench-host.json \
  --reference-inputs .context/slh-reference \
  --wallet-storage-root .context/wallet-storage \
  --algorithm slh-dsa-b128s --algorithm ecdsa-secp256k1 \
  --version v5 --policy single --inputs 1 --inventory cached \
  --samples 3 --warmup 1 --repetitions 1 --timeout 1800 \
  --max-output-bytes 1048576 --max-artifact-bytes 4194304 \
  --checker-timeout 120 --checker-max-output-bytes 262144

python3 benchmarks/slh-dsa-b128s/run.py run .context/payment-run-01 --execute

python3 benchmarks/slh-dsa-b128s/run.py summarize .context/payment-run-01 \
  --output .context/payment-report-01
```

For the other cases, select `--version v6`, `--policy multisig`, `--inputs 2`
or `--inputs 5`, and `--inventory generated`. Each process permits 1–100 timed
attempts and 0–10 warmups. The plan limits the full run to 4,096 records, keeps
one separate process-peak record per child, and bounds process wall time,
stdout/stderr, public artifact files and bytes. The total registered output
allowance, including checker logs and a reference/receipt reserve, is at most
2 GiB. A large matrix must be split into registered runs.

Before any measured child starts, the separate checker verifies retained known
answers and negative controls. Each successful attempt writes one public
`attempt-NNNNNN.json` with transaction bytes, previous outputs, messages and
case metadata. The runner checks every warmup and timed artifact after that
child exits, so reference verification does not compete with its measured
work. It uses separately implemented wire parsing, digests and signatures;
production self-verification alone cannot satisfy this gate. Checker processes
have separate wall-time and output limits. A missing reference, changed source,
bad signature, changed message, wrong shape or byte-count mismatch prevents
completion. The full checker stdout, artifact hashes and compact receipt index
remain with the run.

An independent-check failure leaves the observed attempt rows intact and adds
a separate failure row. No failed artifact is relabeled as independently valid.
Timeouts, short output, unexpected artifact files and nonzero exits also keep
the run incomplete. Retain the whole run directory; the framework never edits
failed runs into successful evidence. The artifact directory contains public
synthetic transactions only. Disposable wallet keys and stores are not copied
into the report evidence. Never use benchmark keys for funds.

## Import saved observations

`run.py import` is offline. Supported kinds are `normalized`, `transaction`,
`resources`, `mempool`, `block-trace` and `propagation`. It copies the bounded
input and profile, validates records and expected counts, then creates an
artifact inventory for the same reporting commands.

```sh
python3 benchmarks/slh-dsa-b128s/run.py import \
  --kind transaction --input .context/public-transaction.hex \
  --profile .context/transaction-import.json --output .context/transaction-run
python3 benchmarks/slh-dsa-b128s/run.py summarize .context/transaction-run \
  --output .context/transaction-report
```

Use the [adapter guide](../../benchmarks/slh-dsa-b128s/ADAPTERS.md) for formats,
resource-library calls and measurement boundaries. Imported provenance and
completion are operator declarations. File hashes preserve supplied bytes;
they do not authenticate a node build or establish that the stated workload ran.
No importer starts a node, sends a transaction, queries RPC or changes machine
configuration.

For block traces, do not assert that the debug throughput probe was disabled
without saved effective configuration and producer evidence. That probe can
bypass consensus. Unknown probe status makes validation time unavailable.
Checkpoint residence includes range batching and waiting. Keep it separate
from full verification plus commit. A missing event is a collection failure,
not proof of a timeout.

Propagation inputs need transaction ID, authorization digest, attempt identity,
node/process epoch and explicit stage events. A shared clock-domain label alone
does not prove synchronized clocks. The importer requires an operator-declared
verified clock domain and collection cutoff. Missing expected peers remain
censored timeout observations. They cannot improve successful delivery tails.

## Interpret and compare reports

The [record contract](../../benchmarks/slh-dsa-b128s/schema/README.md) defines
units, exact percentile selection, limits and statuses. A metric with no valid
samples has null quantiles and a reason. Failures, missing capabilities,
censored lower bounds and warmups remain visible. Exact quantiles exclude
censored values and cannot establish the unobserved tail.

Open `report.html` for the readable view. Primitive timings and wallet/payment
stages have separate overviews, with one row per metric, process and outcome,
followed by the full metric tables. Wallet scope notes explain cached inventory,
coupled durable writes and the classical controls' different boundaries.
Durations use ns, µs, ms or seconds; larger byte values use binary units. Expand
the exact-value details or use JSON/CSV for unrounded values in catalog units.
CPU/wall is core equivalents, not total host CPU percentage. Each process peak
is one lifetime high-water sample, including setup and warmups.

Completion, failures, missing values and censored bounds stay visible. With
1–19 exact samples, both p95 and p99 select the observed maximum. One sample
repeats the same value for all three percentiles. These values do not establish
tail stability. Combined-outcome distributions repeat the same attempts and
are kept in a separate audit view. Provenance is expandable, and the HTML
renderer hash is recorded separately from the measured source and binary.

Reports keep case, configuration, process, phase, input mode and outcome
separate. Comparisons require matching hardware, workload, compiler and
instrumentation metadata. New receipts compare checkout-local Cargo config
locations relative to the checkout, with hashes and search precedence intact;
different worktree prefixes alone do not prevent a comparison. External config
paths remain exact. Raw absolute paths stay in report provenance. Older
primitive/payment build receipts keep their original path-sensitive identity.
Node collection requires the separate [node build wrapper](../../benchmarks/slh-dsa-b128s/NODE_COLLECTION.md)
to record build-time compiler and Cargo settings for matched comparisons.
Legacy node acceptance receipts and their reports remain readable, but cannot
establish a matched comparison. Current machine settings cannot fill that gap.

Saved block imports require matching validated effective-config hashes. To
apply this guard to older saved imports, re-import their original input and
profile into fresh directories. Preserve the old artifacts. Source and binary
revisions can differ. When a run has repeated
processes, select one process from each run before comparison:

```sh
python3 benchmarks/slh-dsa-b128s/run.py summarize .context/bench-run-01 \
  --process-id verify.r0.pid12345 --output .context/selected-report-01
python3 benchmarks/slh-dsa-b128s/run.py compare \
  --baseline .context/selected-report-01/summary.json \
  --candidate .context/selected-report-02/summary.json \
  --output .context/comparison-01.json
```

Use actual process IDs from the raw records. Comparison is descriptive. It
does not average medians, hide outcome changes or supply a significance test.
Use the original source revision to report a run if the metric catalog changes.

## Remaining integration

The next work is funded live wallet transaction cases, RPC submission and node
flow. The offline payment cases above do not establish live acceptance.
Separate digest and isolated storage microbenchmarks are not supplied; current
timings retain their real API boundaries. Node work still needs isolated
resource collection sessions, verified build/configuration/fixture receipts,
full-validation controls, per-stage tracing, peer receive/admit instrumentation,
and multi-node topology orchestration. Upstream RPC and codec benchmarks are
not substitutes for node admission or network propagation.

Realistic node experiments must first pass matching functional acceptance.
They must register hardware, CPU entitlement, memory/storage limits, cache and
database state, instrumentation, topology and offered load. Use the project's
Zakura baseline and record deviations. Saturation, repeated independent runs,
sample-count studies and live acceptance remain human-run work.
No new node instrumentation or consensus/wallet behavior is changed here.

## Check the framework without measuring performance

The Python tests require the wallet-format oracle dependency described above.

```sh
python3 -m unittest discover -s benchmarks/slh-dsa-b128s/tests -v
cargo fmt --manifest-path benchmarks/slh-dsa-b128s/Cargo.toml --all -- --check
cargo test --manifest-path benchmarks/slh-dsa-b128s/Cargo.toml --locked
cargo clippy --manifest-path benchmarks/slh-dsa-b128s/Cargo.toml --all-targets --locked -- -D warnings
python3 tests/slh-dsa-b128s/dependencies/check.py
```

The Rust tests check parsing, unit conversions, bounded fixture construction and
retained public signatures. The Python tests use mocked child and checker
processes to check run registration, failure retention and reports. They do not
call the measurement command or generate a new signature corpus.

After building the executable, check one actual offline payment without timing
or CPU/RSS collection. Use a fresh public-artifact directory. This command uses
disposable wallet keys and private temporary stores, then retains only the public
transaction evidence. Run the separate independent checker on that evidence:

```sh
mkdir .context/payment-check-01
mkdir -p .context/wallet-storage
.context/bench-build-01/tpq-bench check-payment \
  --algorithm slh-dsa-b128s --version v5 --policy single --inputs 1 \
  --inventory cached --artifact-directory .context/payment-check-01 \
  --wallet-storage-root .context/wallet-storage
python3 -B benchmarks/slh-dsa-b128s/payment_checks.py \
  --repo-root . --reference-inputs .context/slh-reference \
  --artifact .context/payment-check-01/attempt-000000.json
```

`check-payment` accepts exactly one case. It rejects measurement flags and emits
no timing or resource observations. It is a bounded correctness check, not a
benchmark pilot. The measured `payment` command still requires `--execute` and
human execution under the workspace rules.

Dependency inspection is locked and offline; fetch missing locked dependencies
before running that guard. The [source map](../../benchmarks/slh-dsa-b128s/sources.json)
and [notice](../../benchmarks/slh-dsa-b128s/NOTICE) identify reused sources and
the reasons for each adaptation.
