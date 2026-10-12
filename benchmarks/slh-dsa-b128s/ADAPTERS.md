# Saved measurements and resource collectors

The Python adapters import saved data. They do not start a node, contact an RPC
server, or generate transactions. The resource readers take one Linux snapshot;
they do not start a workload or change host settings. Automated tests use
synthetic files and events. Live resource, propagation, and node validation
measurements remain pending human execution under [AGENTS.md](../../AGENTS.md).
The separate [registered node collector](NODE_COLLECTION.md) attaches these
readers to a running Regtest node and a bounded loopback metrics scrape. Its
planning step remains offline; execution requires an explicit opt-in.

The [metric registry](schema/metrics.json) fixes units and measurement scope.
Payment metrics have a separate [catalog identity](schema/payment-metrics.json).
Normalized imports that use those metrics bind that identity too. They remain
operator-supplied records and do not gain the registered payment runner's
independent artifact checks by using its metric names.
Adapters emit raw records for the shared p50, p95, and p99 report. They do not
calculate a second set of percentiles. Null values have an explicit reason.
Timeout lower bounds are marked as censored and excluded from exact percentiles.
Keep these bounds and failed attempts in the report.

## Saved import command

Use the import command in the [main guide](README.md):

```bash
python3 benchmarks/slh-dsa-b128s/run.py import \
  --kind transaction --input saved-transaction.hex \
  --profile saved-profile.json --output import-output
```

The import profile has exactly these fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | Integer `1`. |
| `context` | `run_id`, `case_id`, `configuration_id`, `process_id`, `attempt_id`, `phase`, `cache_mode`, and boolean `warmup`. |
| `expected_records` | Expected number of normalized records, from 1 to 100,000. |
| `complete` | Operator declaration that collection finished. It does not make failed or incomplete measurements successful. |
| `host_profile` | Nonempty object describing the measured host, limits, and workload placement. |
| `provenance` | Nonempty object with the source, binary, configuration, fixture, and collection evidence that is available. Identify missing evidence explicitly. |
| `options` | Adapter options in the table below. Use `{}` when none apply. |

Identifiers use letters, digits, `_`, `.`, `:`, and `-`, begin with a letter or
digit, and have at most 128 characters. Imported normalized records retain their
source process and attempt IDs and warmup flags; other context fields must match
the profile. For adapter-generated records, the context supplies the warmup flag.

This complete profile template imports one serialized transaction. Replace the
uppercase placeholders with the producer's evidence. An unavailable identity
must be declared as unavailable, rather than replaced by a made-up hash.
This template contains no measurement results.

```json
{
  "schema_version": 1,
  "context": {
    "run_id": "saved-run-001",
    "case_id": "transaction-size",
    "configuration_id": "slh-regtest-v1",
    "process_id": "producer-001",
    "attempt_id": "transaction-001",
    "phase": "encoded-size",
    "cache_mode": "not-applicable",
    "warmup": false
  },
  "expected_records": 1,
  "complete": true,
  "host_profile": {
    "description": "REPLACE_WITH_PRODUCER_HOST_AND_WORKLOAD",
    "cpu_model": "REPLACE_WITH_CPU_MODEL",
    "limits": "REPLACE_WITH_AFFINITY_QUOTA_AND_MEMORY_LIMITS"
  },
  "provenance": {
    "source_revision": "REPLACE_WITH_PRODUCER_COMMIT",
    "binary_sha256": "REPLACE_WITH_BINARY_SHA256",
    "configuration_sha256": "REPLACE_WITH_CONFIGURATION_SHA256",
    "fixture_sha256": "REPLACE_WITH_FIXTURE_SHA256"
  },
  "options": {}
}
```

| Kind | Source file | Options |
| --- | --- | --- |
| `normalized` | Shared result-schema JSONL. | None. |
| `transaction` | Exact serialized transaction hex. | None. |
| `block-trace` | Current `commit_state.jsonl`. | Optional `throughput_probe_disabled`, default `false`; `true` requires `effective_config_toml` and the matching `provenance.effective_config_sha256`. |
| `propagation` | Proposed event JSONL described below. | Required `expected_peers`, `observation_end_ns`, and `verified_clock_domain`. |
| `mempool` | Saved Prometheus scrape text. | Required `monotonic_ns` and `process_epoch`; optional `labels`, `previous_text`, `previous_monotonic_ns`, and `previous_process_epoch`. |
| `resources` | JSON object with exactly `before` and `after` snapshots. | Optional boolean `fresh_process`, boolean `fresh_cgroup`, and positive `effective_cpu_cores`. |

The previous mempool scrape is stored inside `options.previous_text`, so the
archived profile includes it. Its timestamp and process epoch are also required.
No path inside imported JSON is opened or executed.

Transaction, mempool, and resource imports emit one record. A block import emits
one record per complete correlated attempt. A propagation import emits one
origin record plus one record per expected peer for each broadcast attempt.
Use those counts for `expected_records`.

The importer copies and hashes the source and profile, then writes normalized
records and a receipt. These hashes identify the supplied bytes. They do not
authenticate the original run, host, binary, clock, freshness, or completion.
The manifest marks declarations from the operator. Source files are bounded to
64 MiB and profiles to 1 MiB. JSONL requires a final newline, no blank records,
at most 100,000 rows, and at most 64 KiB per row. Malformed or duplicate JSON
fields, nonfinite numbers, and oversized values fail the import.

## Transaction bytes

`adapters.transaction_size(hex_text, context)` returns `(records, metadata)`.
The source must contain a nonempty even number of hexadecimal characters.
One final line ending is allowed. Prefixes, internal spaces, and extra lines
are rejected. `transaction_bytes` is the decoded byte count. Metadata records
SHA-256 of those bytes as `serialized_sha256`.

This fingerprint is not a Zcash TXID. This adapter does not parse consensus
encoding, verify signatures, establish trusted UTXOs, or establish onchain
inclusion. Use the exact accepted transaction bytes and separate acceptance
evidence when reporting an onchain transaction size.

## Block traces

`adapters.import_block_trace(rows, context, throughput_probe_disabled=False)`
accepts JSONL text or a sequence of decoded row objects. It returns
`(records, metadata)`.

The adapter follows the current
[block driver emitter](../../crates/zakurad/src/commands/start/zakura/trace/block_driver.rs)
and [trace envelope](../../crates/zakura-jsonl-trace/src/lib.rs). It groups rows by
`node`, `process_trace_id`, and `apply_token`, then checks `height`, `hash`, and
`apply_class` at every boundary. Each attempt needs one `block_submit_queued`,
one `commit_start`, and one `commit_finish`. Their `ts` fields are emitter-local
monotonic microseconds. Missing, duplicate, mismatched, and reversed boundaries
fail the import. Concurrent attempts may appear in interleaved file order.

For a committed `full` attempt, `elapsed_ms` supplies
`block_verify_commit_ns`. This includes consensus verification and state commit.
The adapter cannot split those stages. For a `checkpoint` attempt, the same
field supplies `checkpoint_residence_ns`, which includes range batching and
waiting. It is not per-block processing cost. The adapter appends `.full` or
`.checkpoint` to the phase so reports keep the populations separate.
The source duration has integer-millisecond precision even though the output
unit is nanoseconds. `trace_queue_ns` uses the queued-to-start boundaries.

The debug throughput probe can emit these rows while bypassing consensus.
`sync.debug_blocksync_throughput_target_height` must be absent from the effective
node configuration for the probe to be disabled at the pinned source default.
The saved importer requires the exact TOML text in `options.effective_config_toml`
and its UTF-8 SHA-256 in `provenance.effective_config_sha256` before it accepts
`throughput_probe_disabled=true`. It parses the archived text, checks its hash,
and rejects the probe setting. Without the explicit disablement declaration,
the validation/residence metric is null with a reason; the observed driver
attempt duration remains available. The operator must still establish that this
was the producer's effective configuration, including any command-line overrides.
Checking the saved text does not authenticate the producer or that applicability.
Comparisons require the same validated effective-configuration hash. This binds
all archived TOML bytes, including CPU-thread settings, even when case and
configuration labels match. Source and binary revisions can still differ.
Re-import older saved block inputs and their original profiles into fresh
directories to add this comparison guard; preserve the original receipts.

Rejected, duplicate, unavailable, and timed-out results remain in raw records.
Explicit `timed_out` results have a censored duration lower bound when the probe
is disabled. Missing log rows do not establish a timeout. Header-range rows and
unrelated trace events are counted as ignored. An RPC proposal check does not
become a block validation metric.

## Proposed propagation events

`adapters.import_propagation(rows, context, expected_peers=...,`
`observation_end_ns=..., verified_clock_domain=...)` returns `(records, metadata)`.
Current product transaction code does not emit these events. The adapter and
its synthetic tests define a format for later instrumentation; they are not
evidence of measured live propagation.

Each JSONL event has exactly these fields:

| Field | Required value |
| --- | --- |
| `schema_version` | Integer `1`. |
| `event` | `origin_submit`, `origin_admit`, `peer_receive`, or `peer_admit`. |
| `txid` | 32-byte hexadecimal transaction ID. |
| `auth_digest` | 32-byte hexadecimal authorizing-data digest. |
| `node` | Node label. |
| `process_epoch` | Identity of this node process lifetime. |
| `attempt_id` | Broadcast-attempt label, shared by all events for that attempt. |
| `monotonic_ns` | Nonnegative integer timestamp in the declared common clock. |
| `clock_domain` | Same externally verified clock domain for every event. |

The importer correlates TXID, authorizing-data digest, and attempt ID. Peer
identity must match `expected_peers`, an object mapping every expected peer
node to its process epoch. Include peers that emitted no events.
`observation_end_ns` is the actual recorded collection cutoff, not a future
deadline. A matching clock-domain string does not prove synchronized clocks.
Record the clock verification method, uncertainty, and host/boot identities in
the profile. Emitter-local Zakura `ts` clocks cannot be compared across nodes.

The origin record measures submission to origin admission. Each peer record
measures origin admission to peer receipt and to peer admission. Missing peer
admission is a timeout lower bound. A peer with no events remains in the
results with censored receipt and admission bounds. Peer admission without a
receipt boundary fails validation. If origin admission is absent, its duration
is censored and peer propagation durations are unavailable.

## Mempool scrapes

`adapters.import_mempool(text, context, monotonic_ns=..., process_epoch=..., ...)`
returns `(records, metadata)`. It reads these actual product series:

| Prometheus series | Result metric |
| --- | --- |
| `zcash_mempool_size_transactions` | `mempool_transactions` |
| `zcash_mempool_size_bytes` | `mempool_bytes` |
| `zcash_mempool_cost_bytes` | `mempool_cost` |

The default selector requires no labels. An optional `labels` object selects
one exact label set. Malformed values, labels, duplicate series, and non-gauge
type declarations for needed series fail. Missing series are null with reasons.
Unknown metric families are ignored. Cost is policy accounting bytes, not heap
memory. These are verified mempool gauges; they do not expose the admission
queue.

A previous scrape in the same process epoch enables signed transaction-count
and byte growth rates. Shrinkage is valid negative growth. These are net rates;
they cannot identify gross arrival and removal rates under concurrent traffic.
Use collected timestamps from one monotonic clock. A process restart requires
a new epoch and cannot form one growth interval.

## Linux snapshot library

The public functions in [collectors.py](collectors.py) are:

```python
read_process(pid, *, proc_root="/proc", clock=time.monotonic_ns, clock_ticks=None)
read_cgroup(path, *, boundary=None, clock=time.monotonic_ns)
read_interface(name, *, sys_root="/sys", namespace_id=None,
               isolated=False, clock=time.monotonic_ns)
validate_snapshot(snapshot)
resource_record(before, after, context, *, fresh_process=False,
                fresh_cgroup=False, effective_cpu_cores=None)
```

Readers return snapshots with exactly `kind`, `identity`, `metrics`,
`unavailable`, `details`, `window_start_ns`, and `window_end_ns`.
The first three reader functions accept fixture roots and injected clocks for
tests. Each file read is bounded to 64 KiB. Kernel pseudo-files with zero stat
size are allowed; FIFOs and other nonregular sources are rejected without a
blocking read. `resource_record` validates both snapshots and returns one
normalized interval record. JSON import uses `{"before": ..., "after": ...}`.

Process identity contains PID, start-time ticks, boot ID, and proc root.
CPU counters cover the process thread group and exclude child processes. RSS comes from
`VmRSS`; lifetime peak RSS comes from `VmHWM`. A process that has exited may
already have lost these files. The reader does not recover a final peak after
exit. Effective CPU normalization uses the operator-declared process-wide
entitlement, including applicable CPU quotas and worker-thread restrictions.
The reader does not independently verify this declaration. The affinity count
from `/proc/PID/status` describes only the thread-group leader; it remains an
endpoint diagnostic and does not cap the whole-process denominator. A change
in leader affinity alone does not reject the interval. Missing or null affinity
also leaves the declared entitlement unchanged. Without an entitlement, the
normalized percentage is unavailable.

Cgroup identity contains path, device, and inode. CPU, memory, and throttling
counters cover the cgroup and its descendants. `boundary` must identify the
cgroup-v2 mount boundary so the reader can inspect every ancestor quota.
Effective CPU cores are the minimum of the effective cpuset count and known
ancestor quotas. This is an upper limit; other tasks can share ancestor quotas.
Without a known boundary or quota capability, normalization is unavailable.
`memory.current` and `memory.peak` have different scope from process RSS.

Interface identity includes name, index, network namespace, and sysfs root.
Byte counters require an explicit `isolated=True` declaration. Fixture roots
also require `namespace_id`; normal Linux sysfs uses `/proc/self/ns/net`.
Counters include all traffic on that interface, including overhead and retries.
They are not transaction payload bytes or per-peer protocol counters. The
caller must preserve the host and namespace identity across the interval.

CPU core equivalents are CPU-time delta divided by elapsed wall time.
Normalized CPU percent divides that value by effective CPU cores. Interface
rates divide byte deltas by the same elapsed interval. The interval uses the
midpoints of the two collection windows, and retains both window widths in
metadata so read uncertainty remains visible. Overlapping windows, changed
identities, decreased cumulative counters, changed CPU limits, and reset peak
values fail. Start a new epoch after these changes.

`fresh_process` and `fresh_cgroup` are declarations that the subject was created
for the complete case. Without them, lifetime peaks are unavailable as case
metrics. Even with them, peaks include setup and warmup; they are not local to
one signing or verification operation. Save source snapshots, host and boot
identities, cgroup limits, interface isolation, and freshness evidence with the
run. The readers cannot verify those external declarations themselves.
