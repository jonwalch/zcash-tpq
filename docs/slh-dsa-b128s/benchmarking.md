# Benchmark framework

The framework records primitive timings and imports saved node and resource
observations. It writes raw attempts, source and artifact hashes, and reports
with median (p50), p95 and p99 for every measured metric. The code is under
[`benchmarks/slh-dsa-b128s`](../../benchmarks/slh-dsa-b128s).

This is the first implementation. Focused tests use synthetic records, mocked
resource files and an existing public signature. No new performance results,
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
`run` rechecks these inputs, claims the directory once, supervises each child
with wall-time and output bounds, and retains stdout and stderr. A missing row,
wrong case outcome, partial line, extra row or nonzero exit prevents completion.
Failures stay in the attempt stream. An interrupted or failed run needs a new
plan directory for its retry.

The raw `attempts.jsonl`, `manifest.json`, logs and `receipt.json` are the primary
artifacts. Reports verify their inventory before reading records. Keep them
together. Do not edit saved inputs to make an incomplete run appear complete.
After a hard kill, a run may have only an incomplete running receipt; it cannot
be reported as finalized. Retain it for diagnosis and register a new run.

Every operation record has its timing, CPU and RSS endpoints. A final record in
the separate `process` phase contains one process high-water reading. Thus one
process supplies only one peak sample. The report shows p50=p95=p99 for that
one-sample peak distribution; it does not estimate a process-peak population.
Setup costs and earlier warmups can dominate that peak.

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

Open `report.html` for the readable view. Primitive timings appear together,
with one row per process and outcome, followed by the full metric tables.
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
paths remain exact. Raw absolute paths stay in report provenance. Older build
receipts keep their original path-sensitive identity.

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

The next work is funded wallet transaction cases and separate key storage,
sighash, assembly and submission timings. Node work still needs isolated
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

```sh
python3 -m unittest discover -s benchmarks/slh-dsa-b128s/tests -v
cargo fmt --manifest-path benchmarks/slh-dsa-b128s/Cargo.toml --all -- --check
cargo test --manifest-path benchmarks/slh-dsa-b128s/Cargo.toml --locked
cargo clippy --manifest-path benchmarks/slh-dsa-b128s/Cargo.toml --all-targets --locked -- -D warnings
python3 tests/slh-dsa-b128s/dependencies/check.py
```

The Rust tests check parsing, unit conversions and a retained public signature.
They do not call the measurement command or generate a new signature corpus.
Dependency inspection is locked and offline; fetch missing locked dependencies
before running that guard. The [source map](../../benchmarks/slh-dsa-b128s/sources.json)
and [notice](../../benchmarks/slh-dsa-b128s/NOTICE) identify reused sources and
the reasons for each adaptation.
