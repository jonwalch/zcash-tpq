# SLH benchmark tools

Use the [operating guide](../../docs/slh-dsa-b128s/benchmarking.md) to build a
measurement executable, register a bounded run and generate p50/p95/p99 reports.
The [adapter guide](ADAPTERS.md) documents saved evidence and resource readers.
The [record contract](schema/README.md) defines units and reporting rules.
The [node collection guide](NODE_COLLECTION.md) covers bounded Linux collection
from one existing Regtest node, including CPU/RSS and mempool observations.

Measurements and profiling are for human execution. The tools include primitive
measurements, offline wallet/payment cases, matched classical transaction
controls, and saved-data adapters. Payment cases use transaction-derived messages
and actual SLH wallet storage. Their funding is a synthetic fixture; live chain
acceptance, node flow and propagation instrumentation remain open. Synthetic
tests do not establish performance results or production budgets.

Payment commands require an explicit `--wallet-storage-root`. Registered runs
also require a `wallet_storage` declaration in the host profile and record the
directory/device identity for persistence comparisons. See the operating guide
for the profile fields. Ambient `TMPDIR` does not redirect wallet writes.

Install the [pinned wallet-format oracle dependency](../../tests/slh-dsa-b128s/wallet/formats/requirements.txt)
in your Python environment, then run tests without starting any measurement workload:

```sh
python3 -m pip install -r tests/slh-dsa-b128s/wallet/formats/requirements.txt
python3 -m unittest discover -s benchmarks/slh-dsa-b128s/tests -v
```

The [NOTICE](NOTICE) and [source mappings](sources.json) identify code reuse.
No research checkout is needed at runtime or for these unit tests.
