# Shielded output tests with real proofs

These tests use real Sapling Groth16 and Orchard/Ironwood Halo2 proofs with SLH or classical transparent authorization.
Live execution remains open.
The [synthetic digest corpus](../../tests/slh-dsa-b128s/shielded/README.md) retains its separate scope.
New offline tests do not generate proofs or SLH signatures.
Existing host tests retain bounded public classical-signature controls.

## Pool combinations and funding

| Version | Pool subsets |
| --- | --- |
| v5 | `sapling`, `orchard`, `sapling,orchard` |
| v6 | The v5 subsets, plus `ironwood`, `sapling,ironwood`, `orchard,ironwood`, `sapling,orchard,ironwood` |

Each included pool has two outputs or actions, including normal builder padding.
Pool names occur in the order Sapling, Orchard, Ironwood.
The profile uses NU6.3=1, NU7=105, SLH=110, and the 16/64 check limits.
Two peerless nodes agree on the chain through height 110.
The driver authenticates a mature height-1 classical coinbase through bytes, block, outpoint, amount, and script.
SLH tests first mine a classical spend that creates a 3,000,000-zatoshi SLH output.
Both nodes authenticate it before proof generation or signing.
Classical compatibility tests use the mature classical output directly.

Sapling and Ironwood each receive 50,000 zatoshis.
**Orchard receives zero** because NU6.3 prohibits net additions to that pool.
Its bundle has zero value balance, disabled spends, and disabled cross-address transfers.
The builder uses two zero-value dummy action pairs with the same recipient within each pair.
There is no ordinary Orchard output request.
Both v5 and v6 use the NU6.3 Orchard circuit and bundle version.
These controls do not establish nonzero Orchard payments.

No case spends a shielded note.
Sapling needs no spend witness or anchor.
Orchard and Ironwood disable spends and use the permitted public empty-tree anchor.
All deposited value comes from authenticated transparent funds.
The [spend tests](shielded-spend-controls.md) separately use genuine notes and witnesses.
These fixtures do not cover shielded-wallet recovery.

## Human build and run

Use matching builds from clean, committed source under the [acceptance workflow](acceptance.md#build-receipts).
The optional host feature stays outside node and wallet runtime dependencies.
It uses pinned workspace dependencies.
Build `node-default`, `node-slh`, and `signer` as specified in that guide.
Agents must obtain user approval before building the additional host under [AGENTS.md](../../AGENTS.md):

```sh
python3 tests/slh-dsa-b128s/acceptance/build.py --human-run --kind host-shielded \
  --artifacts "$SLH_ACCEPTANCE_ROOT/host-shielded"
```

For Sapling, supply absolute paths to existing public parameter files.
The tool does not search for or download parameters.
Each regular file has a 64 MiB limit and a recorded SHA-256 hash.
The pinned library also checks the expected parameter hash.
Orchard and Ironwood construct their public proving keys locally.

Proof generation is an explicit `human_run: true` host operation.
It has a 1,800-second deadline and bounded stdout/stderr transport.
A timeout cannot complete a receipt.
Do not run proof generation as an offline check.

Run this example with a new artifact directory:

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

Repeat for all ten version/pool subsets.
Without Sapling, omit both parameter options.
For classical compatibility, repeat each subset with these option pairs:

- `--authorization single --classical single`
- `--authorization multisig --classical multisig`

Classical runs compare default and enabled binaries on identical blocks.
SLH runs use enabled binaries on both nodes.
All fixture keys are public. Do not send real funds to them.
Wallet payment approval remains transparent-only.

## Signatures and negative controls

The host constructs real proofs and all transaction effects first.
It calculates the full sighash with exact previous outputs in input order.
It then applies shielded binding signatures.
The public SLH signer signs the final 101-byte native message.
The host verifies authorization after assembly.
Classical tests use the public P2SH single or 2-of-3 signer over the same complete effects.
Change equals the parent amount minus deposits and the fixed 100,000-zatoshi fee.

Each pool has two negative variants:

- A binding signature over the wrong digest.
- A proof for different public inputs.

Orchard and Ironwood use separately generated valid proofs as donors.
Sapling uses the second real padded-output proof.
These are wrong-proof controls, not malformed encodings.
The host checks positive bundles and requires only the selected pool to fail batch verification.
Batch results do not isolate signature or proof counters.

Variants retain effects, TXID, and the native message.
Their authorization digests and raw bytes differ.
The same SLH signature applies only because effects are unchanged.
Changed effects require a different message and signature.
Finalization rejects changed parent, version, outputs, values, pools, counts, or transparent context.
The independent mutation corpus and its producer receipts remain unchanged.

## Node results and receipts

Both nodes must accept the positive block proposal before negative controls.
Each negative must fail relay, proposal, and block submission for the exact Sapling or Halo2 reason.
Parents, tips, and tree roots must stay unchanged.
The transaction must stay outside the mempool.
Missing parents, expiry, unchanged mutant bytes, and unrelated errors cannot satisfy the control.

The original must then relay, enter a template, and confirm in a block.
The second node receives exact block bytes.
Both nodes must return the saved transaction, agree on roots, spend the parent, and authenticate change.
Included roots must change. Other roots must stay unchanged.

`execution.json` starts incomplete and retains failures.
Proof requests, proof artifacts, signed artifacts, and blocks retain exact bytes.
Receipts identify source, locks, binaries, parameters, configurations, and RPC hashes.
An incomplete proof request cannot establish a positive proof result.
Local receipts provide traceability, not hostile-host attestation.

The tests observe functional rejection and absence.
They do not expose internal success payloads, isolate workers, count primitive calls,
prove queue completion, or measure performance.
Proof generation, live cases, and binary compatibility remain pending.
Agents must obtain user approval before these runs under [AGENTS.md](../../AGENTS.md).

## Offline tests and attribution

```sh
cargo fmt -p slh-dsa-b128s-fixture-host -- --check
cargo test --locked -p slh-dsa-b128s-fixture-host --features shielded-fixtures --bin slh-dsa-b128s-fixture-host
cargo clippy --locked -p slh-dsa-b128s-fixture-host --features shielded-fixtures --all-targets -- -D warnings
python3 -m unittest discover -s tests/slh-dsa-b128s/acceptance -p 'test_shielded_controls.py' -v
```

Four added Rust tests stop before proof creation.
They check feature gates, pool bounds, parent context, and parameter integrity.
Python models cover all ten subsets and reject mismatches, omitted calls, no-op publication, and wrong diagnostics.
Mock proofs have no cryptographic validity claim.

[Source attribution](../../tests/slh-dsa-b128s/fixtures/host/SHIELDED_ATTRIBUTION.md)
records the proof-builder source and pool adaptations.
The source `pq_ironwood_fixture.rs` supplies proof construction.
The historical `pq_measurements/shielded.rs` only verifies existing transactions.
Production consensus, source pins, wallet entropy, approval code, and retry/cache rules remain unchanged.
