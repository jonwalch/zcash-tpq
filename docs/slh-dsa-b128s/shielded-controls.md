# Real shielded output controls

These are prepared human operations, not executed acceptance evidence. They use
actual Sapling Groth16 and Orchard/Ironwood Halo2 proofs alongside final SLH or
classical transparent authorization. The existing [synthetic digest corpus](../../tests/slh-dsa-b128s/shielded/README.md)
and independent reference remain unchanged. The new shielded offline tests do not generate proofs or SLH signatures, start
nodes, or claim that a synthetic bundle is valid. Existing host tests retain their
bounded public classical-signature controls.

## Legal shapes and funding

The adapter covers every nonempty supported pool subset: `sapling`, `orchard`,
`sapling,orchard` in v5; those plus `ironwood`, `sapling,ironwood`,
`orchard,ironwood`, `sapling,orchard,ironwood` in v6. List pools in that order.
Each included pool has two outputs/actions, including the builder's normal padding.

Each fresh disposable chain uses the [acceptance profile](acceptance.md): NU6.3 at
1, NU7 at 105, SLH at 110, and the existing 16/64 check limits. Two peerless nodes
agree on the full chain through height 110. The driver authenticates a real mature
height-1 classical coinbase by raw transaction, block, outpoint, amount and script.
For SLH, a separately authorized classical transaction spends that coinbase and
mines a 3,000,000-zatoshi SLH output; both nodes authenticate it before proving or
signing. Classical compatibility uses the mature classical output directly.

Sapling and Ironwood each receive 50,000 zatoshis. **Orchard receives zero**:
the inherited NU6.3 rule prohibits net additions to that pool. Its real zero-value
output bundle has value balance zero, spends disabled and cross-address transfers
disabled. Both v5 and v6 use the NU6.3 Orchard circuit/bundle version. These are
valid-proof shape controls, not evidence of nonzero Orchard payments. This rule
is unchanged from the pinned upstream baseline; the tool does not bypass it.

No case spends a shielded note. Sapling therefore needs no spend witness or anchor;
Orchard/Ironwood disable spends and use the public empty-tree anchor permitted for
that mode. All deposited value comes from the authenticated transparent coin.
Nonzero Orchard spending requires genuinely created pre-NU6.3 notes and their
actual witnesses; Sapling/Ironwood spend authorization, witness/anchor lifecycle,
shielded recovery and reorg cases remain separate unprepared scope.

## Build and run

Use a clean committed checkout and the [matching build receipts](acceptance.md#build-receipts).
The optional host feature keeps the public proof tool separate from node/wallet
runtime graphs. Its dependencies reuse pinned workspace versions; no alternate
backend, benchmark workload, download helper or research checkout is needed.

A human builds the special host, in addition to the documented `node-default`,
`node-slh` and `signer` binaries:

```sh
python3 tests/slh-dsa-b128s/acceptance/build.py --human-run --kind host-shielded \
  --artifacts "$SLH_ACCEPTANCE_ROOT/host-shielded"
```

For Sapling, supply existing public `sapling-spend.params` and
`sapling-output.params` files using absolute paths. This tool never downloads or
searches for parameters. It bounds each regular file to 64 MiB, records SHA-256,
and uses the pinned library's established parameter-hash validation. Orchard and
Ironwood build their public NU6.3 proving key locally; no parameter files apply.
Proof generation can be expensive and is a separate explicit `human_run: true`
host operation with a finite 1,800-second subprocess deadline. Its stdout and
stderr use the existing bounded concurrent transport; a timeout cannot complete a
receipt. Do not invoke this host operation as an ordinary offline check.

Example SLH run (fresh artifact directory required):

```sh
python3 tests/slh-dsa-b128s/acceptance/shielded_controls.py --human-run \
  --node-default "$SLH_ACCEPTANCE_ROOT/node-default/zakurad" \
  --node-default-build "$SLH_ACCEPTANCE_ROOT/node-default/build.json" \
  --node-slh "$SLH_ACCEPTANCE_ROOT/node-slh/zakurad" \
  --node-slh-build "$SLH_ACCEPTANCE_ROOT/node-slh/build.json" \
  --host "$SLH_ACCEPTANCE_ROOT/host-shielded/slh-dsa-b128s-fixture-host" \
  --host-build "$SLH_ACCEPTANCE_ROOT/host-shielded/build.json" \
  --signer "$SLH_ACCEPTANCE_ROOT/signer/slh-dsa-b128s-public-fixture" \
  --signer-build "$SLH_ACCEPTANCE_ROOT/signer/build.json" \
  --version 6 --pools sapling,orchard,ironwood --authorization slh --classical single \
  --sapling-spend-parameters /absolute/public/sapling-spend.params \
  --sapling-output-parameters /absolute/public/sapling-output.params \
  --artifacts "$SLH_ACCEPTANCE_ROOT/shielded-v6-all-slh"
```

Repeat for the ten listed version/pool subsets. Omit both parameter options when
Sapling is absent. Repeat each subset with `--authorization single --classical
single` and `--authorization multisig --classical multisig` for classical/shielded
compatibility: the first node then runs the default binary without SLH activation,
and the second runs the enabled configuration on identical blocks. SLH runs use
the enabled binary on both nodes. All fixture keys are explicitly public test
material; never send real funds to them. Wallet payment approval remains
transparent-only and is not broadened by this test tool.

## Identity, failures and receipts

The host first constructs real proof bundles and installs all final effecting
fields. It computes the whole transaction sighash with exact ordered parent
outputs, then applies every shielded binding signature. Only then does the existing
public SLH signer sign the resulting 101-byte native message. The host verifies
that authorization after assembly. Classical controls reuse the public P2SH
single/2-of-3 signer over the same complete effects. Transparent change equals the
actual parent amount minus deposits and the fixed 100,000-zatoshi fee.

For each included pool the host supplies two authorization-only negative variants:
a binding signature over the wrong digest, and a proof for different actual public
inputs. Orchard/Ironwood donors are separately generated valid randomized proofs;
Sapling uses the second real padded-output proof. These preserve valid proof
encoding; they are not malformed-proof controls. The host verifies the positive
bundles and checks that only the selected pool fails its batch verification.
That batch result intentionally does not claim independent signature/proof counters.

The complete effects, TXID and native SLH message stay identical across those
variants, while the authorization digest and exact raw bytes change. One SLH
signature is reused only for these unchanged effects. Effecting changes would
require a different message/signature; the immutable independent digest mutation
corpus remains the oracle for that distinction. Host finalization rejects altered
parent, version, output/value, pool, count or transparent-input context. This
adapter does not replace the independent corpus or its original producer receipts.

Both nodes must accept the positive block proposal before negative operations.
Every negative is submitted by relay and direct proposal/submission and must fail
for the exact Sapling or Halo2 verification reason, retain the actual parent and
tip/tree roots, and remain absent from the mempool. Missing parents, expiry,
unchanged mutant bytes and unrelated diagnostics cannot stand in for that result.
The valid original is then relayed, included in a template, mined, and copied as
exact block bytes to the second node. Both nodes must return the saved transaction,
agree on pool roots, consume the parent, and authenticate transparent change.
Included pool roots must change; uninvolved pool roots must remain unchanged.

`execution.json` starts incomplete and retains failures. `proof-request.json`,
`proof-artifacts.json`, `signed-artifacts.json`, every candidate block and accepted
block bind exact bytes. Build receipts bind generator/source/lock/binary hashes;
parameter records bind the explicit local files; node configurations and bounded
RPC request/response hashes are retained. Public artifacts contain no operational
secrets. Locally generated receipts are traceability, not hostile-host attestations.
A failure before proof completion leaves the attempted request and incomplete
receipt, never a positive proof claim.

Failed shielded validation alongside locally valid SLH cannot count as successful
transaction publication. The checks establish functional rejection/absence only.
They do not observe internal success payloads, isolate worker executions, count
primitive entries, establish a drained retry queue, or measure performance.
Retries retain pinned Zakura behavior. Dedicated node builds, proofs, live
positive/negative cases and default/enabled compatibility remain pending human
execution; source/mocks are not substitutes.

## Offline checks and reuse

```sh
cargo fmt -p slh-dsa-b128s-fixture-host -- --check
cargo test --locked -p slh-dsa-b128s-fixture-host --features shielded-fixtures --bin slh-dsa-b128s-fixture-host
cargo clippy --locked -p slh-dsa-b128s-fixture-host --features shielded-fixtures --all-targets -- -D warnings
python3 -m unittest discover -s tests/slh-dsa-b128s/acceptance -p 'test_shielded_controls.py' -v
```

The four added Rust tests stop before proof creation and test gates, bounded pool
sets, exact raw-parent context and parameter integrity. Python models run all ten
subsets and reject mismatched identities/amounts/proofs, no-op relay/mining,
missing subject operations, and unrelated diagnostics. Mock proofs have no
cryptographic validity claim.

[Selective source attribution](../../tests/slh-dsa-b128s/fixtures/host/SHIELDED_ATTRIBUTION.md)
records the pinned research proof/bundle mechanism and the necessary Sapling and
all-pool adaptations. The cited historical `pq_measurements/shielded.rs` only
verifies existing mainnet transactions; it is not a proof-construction source.
The new adapter uses the real `pq_ironwood_fixture.rs` mechanism instead. No
benchmark, large-context driver, alternate signature code or research history is
imported. Production consensus, trusted UTXO resolution, crypto pins, wallet
entropy, proof-covered approval source, and retry/cache rules are unchanged.
