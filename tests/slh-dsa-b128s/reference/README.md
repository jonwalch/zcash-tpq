# Independent SLH-DSA-B-128s verifier checks

This test-only checker compares the bounded Rust verifier against separately
authored Python SLH logic and official portable C BLAKE3. It checks external Pure
framing, three retained public positive vectors, and 57 negative controls. Negative controls cover changed keys, signature boundaries, messages, contexts,
lengths, maximum input sizes, zero inputs, and double framing. All 105 official BLAKE3 unkeyed, keyed and derive-key controls
run before the verifier comparison.

The reference calculates its verdict first, without importing or calling the
Rust implementation. The public expected tuples in
[pure-kats.json](../../../crates/pq-slh-dsa-b-verify/tests/data/pure-kats.json)
were generated independently and are hash-pinned; this command never regenerates
them. The default comparison is exactly 60 cases. It performs no key generation,
signing, tree generation, live-node work or performance measurement.

From the repository root, prepare the pinned test dependencies and build the
small dev-only Rust adapter:

```bash
python3 tests/slh-dsa-b128s/reference/prepare.py .context/slh-reference
cargo build --locked -p zakura-pq-slh-dsa-b-verify --example compare
python3 tests/slh-dsa-b128s/reference/check.py .context/slh-reference \
  --binary target/debug/examples/compare \
  --output .context/slh-g1-receipt.json
python3 -m unittest discover -s tests/slh-dsa-b128s/reference -p 'test_*.py'
```

Choose a new output receipt.
If you set `CARGO_TARGET_DIR`, use the corresponding path in `--binary`. `--candidate-source-tree` records the source checkout when the
adapter was built in another worktree. Receipt source hashes identify the inputs;
they do not by themselves prove how a supplied executable was built. Keep the
associated build record with the binary. Candidate source inputs must be clean
and committed.

`prepare.py` downloads only the allowlisted Python modules, C sources, official
hash vectors and complete license texts in [sources.json](sources.json). Every
download and cached source is checked against its frozen SHA-256. The loader
executes checked Python bytes and rejects a preloaded `slhdsa` package or an
unexpected Python inventory. It verifies the compiled C library receipt before
loading it. No installed `slhdsa` or Python `blake3` package is used. Dependencies
are fetched into the chosen ignored directory; no external source checkout is
required. A C compiler, Python 3.9+ and the workspace Rust toolchain are needed.

The [initial receipt](receipts/g1-initial.json) records successful G1 agreement
for its exact inputs and binary. This gate covers the experimental primitive,
not construction security, native transaction digest/encoding conformance,
consensus integration, or wallet acceptance. The separate
[transaction checker](../transactions/README.md) covers the retained signed
v5/v6 fixtures and independently checks their digests and encoding.

See [NOTICE.md](NOTICE.md) for source and license attribution. The LGPL reference
stays in separate test tooling; it is not linked into the Rust node or wallet.
