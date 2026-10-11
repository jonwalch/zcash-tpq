# Compatibility and lifecycle tests

`tests/slh-dsa-b128s/acceptance/lifecycle_controls.py` uses disposable nodes and public fixture keys.
Agents must obtain user approval before execution under [AGENTS.md](../../AGENTS.md).
Prepared drivers and offline tests do not establish live acceptance.
Receipts identify source, builds, binaries, configurations, and saved public artifacts.

## Cases

| Case | Required result |
| --- | --- |
| Default configuration | A default node refuses SLH settings before it opens state. |
| Classical compatibility | Default and enabled nodes accept identical transaction and block bytes, with matching confirmed UTXOs. |
| SLH activation | Both builds accept the same classical funding block. The enabled node accepts the SLH spend. The default node rejects it through Script. |
| Mixed inputs | Both enabled peers reject genuinely authorized classical/SLH mixtures in both input orders. Relay, block proposal, and block submission report mixed inputs. |
| Block limit | Both enabled peers accept four 16-check transactions in a 64-check block. They reject a 65-check block through proposal and submission. |
| Namespaces | Plain Regtest and four SLH configurations use different database and backup directories within one cache root. |

SLH-spend rejection on the default node must retain the common parent and funding UTXO.
Budget rejection must preserve tips and UTXOs.
The accepted block must preserve exact bytes.
Budget candidates use an empty-mempool template and the ordinary miner fee adjustment.

Namespace cases change activation, the transaction limit, or the block limit.
Each changed configuration starts at genesis and preserves the stopped older namespace byte-for-byte.
Every namespace must survive restart without peers.
The original rules must recover the original tip.
Backup checks compare the full raw tip block after the eight-byte deferred-pool prefix.

The separate node driver covers activation, rollback, and replay.
Wallet recovery uses its own driver.
These cases do not measure performance or generate shielded proofs.

## Human command

Build the binaries with the [acceptance workflow](acceptance.md#build-receipts).
Use distinct default and enabled builds from the same clean source.
Use a host build that includes these control operations.
Run the driver:

```sh
python3 tests/slh-dsa-b128s/acceptance/lifecycle_controls.py \
  --human-run \
  --node-default /absolute/path/to/default/zakurad \
  --node-default-build /absolute/path/to/default-build.json \
  --node-slh /absolute/path/to/slh/zakurad \
  --node-slh-build /absolute/path/to/slh-build.json \
  --host /absolute/path/to/slh-dsa-b128s-fixture-host \
  --host-build /absolute/path/to/host-build.json \
  --signer /absolute/path/to/slh-dsa-b128s-public-fixture \
  --signer-build /absolute/path/to/signer-build.json \
  --version 5 --classical single \
  --artifacts /absolute/path/to/new-control-artifacts
```

Run all four combinations of `--version 5|6` and `--classical single|multisig`.
Use a new artifact directory each time.
Only a successful run writes `complete: true`.
Failures retain an incomplete receipt.

## Focused tests

The following commands use mocks and host tests without a live node:

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/acceptance -p test_lifecycle_controls.py -v
cargo test --locked -p slh-dsa-b128s-fixture-host
cargo clippy --locked -p slh-dsa-b128s-fixture-host --all-targets -- -D warnings
```

## Source attribution

The driver adapts MIT/Apache-2.0 patterns from research revision
`e759cb86a06510893f8e7d1eb986b7025401c8c9`.
It has no runtime dependency on a research checkout, alternate backend, or Docker wrapper.

| Product code | Pinned research source | Necessary adaptation |
| --- | --- | --- |
| `acceptance/lifecycle_controls.py` | `node/tests/pq_compatibility_live.py` | Same exact block/UTXO comparison and unchanged rejected state, using existing local managed nodes and SLH identities |
| Namespace and backup controls | `node/tests/pq_history_live.py`, `node/tests/sqisign_restart_live.py` | Same ordinary backup bytes, isolated restart and stopped-file hashes. Vary current SLH rules without importing legacy caches or Docker code |
| `fixtures/host/src/controls.rs::block` | `examples/pq_regtest_fixture.rs::block`, `examples/pq_regtest_fixture/nu7.rs::miner_fees` | Retain transparent template decoding, aggregate NU7 fee share, header, Merkle and history/auth commitments. Remove unrelated funding mutations and backend branches |
| Mixed-input preparation/assembly | `examples/pq_regtest_fixture/nu7.rs`, `examples/pq_regtest_fixture/relay.rs` | Use actual parent bytes and the existing native public signing context. Generalize the existing public classical signer to its input position |

The implementation shares the existing product helpers, fixture transport,
`TransactionRecipe`, signing context, and signer adapters.
Host operations use the strict envelope and bounded parser.
Historical corpus operations and expected bytes remain unchanged.
Host-supplied previous outputs remain untrusted until both live nodes authenticate them.
