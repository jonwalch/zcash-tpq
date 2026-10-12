# SLH benchmark tools

Use the [operating guide](../../docs/slh-dsa-b128s/benchmarking.md) to build a
measurement executable, register a bounded run and generate p50/p95/p99 reports.
The [adapter guide](ADAPTERS.md) documents saved evidence and resource readers.
The [record contract](schema/README.md) defines units and reporting rules.

Measurements and profiling are for human execution. The first implementation
includes primitive measurements and offline adapters; live wallet/node workload
integration and propagation instrumentation remain open. Synthetic tests do not
establish performance results or production budgets.

Run the Python tests without starting any measurement workload:

```sh
python3 -m unittest discover -s benchmarks/slh-dsa-b128s/tests -v
```

The [NOTICE](NOTICE) and [source mappings](sources.json) identify code reuse.
No research checkout is needed at runtime or for these unit tests.
