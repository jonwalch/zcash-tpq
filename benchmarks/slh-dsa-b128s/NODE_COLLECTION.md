# Collect one Regtest node

This Linux adapter observes one existing node. It records process CPU intervals,
current RSS, verified mempool gauges and net mempool growth. It can also record
cgroup v2 intervals. Python 3.11 or newer is required. Use the existing
[report commands](../../docs/slh-dsa-b128s/benchmarking.md) for p50/p95/p99,
exact sample counts, unavailable values and failed attempts.

Collection is a performance workload. Follow the repository's execution rules.
Planning reads static files and hashes; it does not contact the node or read
process counters. The execution command requires `--execute`.

## Register the node

Use an existing `node-slh` or `node-default` receipt from the
[acceptance build helper](../../tests/slh-dsa-b128s/acceptance/build.py).
The registration checks its recipe, source-inventory digest, verifier identity
and binary hash without executing the binary. Compiled node source and collection
instrumentation have separate identities. A receipt is local provenance, not
independent proof of compilation.

Start the node separately with absolute paths and this exact argument shape:

```sh
/absolute/path/zakurad --config /absolute/path/node.toml start
```

The TOML must set `network.network = "Regtest"` and a literal loopback
`metrics.endpoint_addr`, for example `"127.0.0.1:9999"`. Collection runs in the
node's PID, mount and network namespaces. It checks the running executable,
explicit config argument, configuration hash, PID start time and boot identity.
It never stops the attached node. HTTP redirects, proxies and credentials are
not supported. The endpoint-to-process association remains an operator
declaration; the adapter does not prove listener socket ownership.

Create `node-profile.json` using the actual values below. Obtain `start_ticks`
from field 22 of `/proc/PID/stat` and `boot_id` from
`/proc/sys/kernel/random/boot_id`. Account for spaces and parentheses in the
process name when parsing `stat`. The process values in this example are
placeholders; do not copy them into a real registration.

```json
{
  "schema_version": 1,
  "network": "Regtest",
  "pid": 12345,
  "binary_path": "/absolute/path/build/zakurad",
  "build_receipt_path": "/absolute/path/build/build.json",
  "config_path": "/absolute/path/node.toml",
  "metrics_url": "http://127.0.0.1:9999/metrics",
  "process_identity": {"start_ticks": 123456, "boot_id": "REPLACE_WITH_BOOT_ID"},
  "workload": {
    "id": "idle",
    "description": "One idle Regtest node; no submitted transactions",
    "fixture_sha256": null,
    "topology": "One node with no peers",
    "state": "Fresh disposable state",
    "activity": "Idle; no mining or traffic generator"
  },
  "cgroup_path": null,
  "cgroup_boundary": null
}
```

For cgroup collection, set both cgroup paths to absolute paths. The boundary
must be the cgroup v2 root mount. The declared subtree must contain the node;
membership changes stop collection. Its measurements include other processes
in that subtree, including collection tools if they share it. They are not
node-only CPU or RSS. Use null paths to omit this collector.

Use the [host-profile fields](../../docs/slh-dsa-b128s/benchmarking.md) to record
hardware, limits, power policy and environment. Describe container/VM placement
and shared resources. Workload, topology and fixture declarations are retained
but are not verified execution or chain-acceptance evidence.

```sh
python3 benchmarks/slh-dsa-b128s/run.py plan-node \
  --node-profile node-profile.json --host-profile host-profile.json \
  --output node-run --samples 10 --interval-ms 1000 --timeout 30 \
  --max-output-bytes 16777216
python3 benchmarks/slh-dsa-b128s/run.py run node-run --execute
python3 benchmarks/slh-dsa-b128s/run.py summarize node-run --output node-report
```

`samples` counts intervals. The sampler captures one initial snapshot and then
one endpoint per interval, waiting `interval-ms` between observations. Rates
use actual monotonic read windows; collection overhead extends elapsed time.
Ten intervals produce 20 normalized records, or 30 with cgroup collection.
The parent bounds sampler time, output and retained artifacts, and terminates
only its private sampler process group. A run directory cannot be reused.

## Read the results

Raw snapshots and scrape text are retained with normalized records and hashes.
The parent independently reconstructs each record from the snapshots. A timeout,
process replacement, counter reset, changed input or failed scrape preserves
available evidence and prevents an unqualified successful result.

Percentiles describe resource intervals and gauge samples. They are not
transaction or block latencies. Mempool growth is a signed net change, not gross
arrival throughput. Point samples can miss memory peaks. Attached lifetime peaks
and unknown process CPU entitlement remain unavailable, so a completed run can
correctly report `complete_with_issues`. Inspect the unavailable reasons.

Comparison requires matching declared workload, configuration bytes, host,
sampling settings, instrumentation and resource scope. PID and process start
identities are retained as provenance, rather than comparison keys. This does
not independently establish matched load or topology. No funded transactions,
mining, block-validation timing, propagation or bandwidth are generated here.
