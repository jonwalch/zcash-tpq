# SLH compatibility and lifecycle controls

`tests/slh-dsa-b128s/acceptance/lifecycle_controls.py` is a human-only acceptance
driver. It uses disposable local nodes and deterministic public fixture keys.
The prepared driver and offline tests do not establish live acceptance.

It exercises the following cases with exact source/build/binary/configuration
receipts and saved public transaction/block artifacts:

- A default node refuses an SLH configuration before opening state.
- Default and enabled nodes accept the same classical transaction and block
  bytes, with matching confirmed UTXOs. Run both P2SH CHECKSIG and 2-of-3
  CHECKMULTISIG profiles and both transaction versions.
- A real classical spend legally funds an SLH output in an identical block on
  both chains. The enabled node accepts the subsequent genuine SLH spend; the
  default node rejects the exact candidate through its legacy script verifier
  and retains the common parent and unspent funding output.
- Actual classical and SLH previous outputs, in both input orders, produce
  canonical transactions with genuine ECDSA and SLH authorizations. Both nodes
  reject them at relay and block proposal/submission with the mixed-input reason.
- Four independently valid 16-check transactions form an accepted 64-check
  block. Adding a genuine one-check transaction produces a 65-check block that
  both nodes reject through proposal and submission. Rejection must preserve
  tip and UTXOs; the accepted block must preserve exact bytes. These candidates
  use an empty-mempool template and ordinary transparent miner fee adjustment.
- Plain Regtest and four SLH configurations share a disposable cache root but
  use distinct database and ordinary backup directories. Changing activation,
  transaction limit or block limit starts at genesis and leaves stopped older
  namespaces byte-identical. Every namespace survives restart without peers;
  restoring the original rules restores its original tip. Backup checks compare
  the complete raw tip block after the existing eight-byte deferred-pool prefix.

The node driver separately covers activation, rollback, replay and broader
transaction/template lifecycle. Wallet recovery/watch-only acceptance uses its
own driver. These controls do not measure performance or generate shielded proofs.

## Human command

Prepare the exact product binaries and their matching receipts with the shared
`acceptance/build.py` workflow. `node-default` and `node-slh` receipts must come
from distinct feature-correct builds of the same clean source. The host receipt
must include the new control operations. Then a human can run:

```sh
python3 tests/slh-dsa-b128s/acceptance/lifecycle_controls.py \
  --human-run \
  --node-default /absolute/path/to/default/zakurad \
  --node-default-build /absolute/path/to/default-build.json \
  --node-slh /absolute/path/to/slh/zakurad \
  --node-slh-build /absolute/path/to/slh-build.json \
  --host /absolute/path/to/slh-dsa-b128s-fixture-host \
  --host-build /absolute/path/to/host-build.json \
  --signer /absolute/path/to/slh-dsa-b128s-fixture-signer \
  --signer-build /absolute/path/to/signer-build.json \
  --version 5 --classical single \
  --artifacts /absolute/path/to/new-control-artifacts
```

Run the four combinations of `--version 5|6` and `--classical single|multisig`,
each with a fresh artifact directory. Only a completely successful run writes
`complete: true`; exceptions retain a failure receipt. These commands, node
builds and all live runs remain human-only under [AGENTS.md](../../AGENTS.md).

Offline verification does not launch any binary or network service:

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/acceptance -p test_lifecycle_controls.py -v
cargo test --locked -p slh-dsa-b128s-fixture-host
cargo clippy --locked -p slh-dsa-b128s-fixture-host --all-targets -- -D warnings
```

## Source reuse

The control adapters reuse MIT/Apache-2.0 research implementation patterns from
revision `e759cb86a06510893f8e7d1eb986b7025401c8c9`. No research checkout, alternate
backend, Docker wrapper or experimental history is a runtime dependency.

| Product code | Pinned research source | Necessary adaptation |
| --- | --- | --- |
| `acceptance/lifecycle_controls.py` | `node/tests/pq_compatibility_live.py` | Same exact block/UTXO comparison and unchanged rejected state, using existing local managed nodes and SLH identities |
| Namespace and backup controls | `node/tests/pq_history_live.py`, `node/tests/sqisign_restart_live.py` | Same ordinary backup bytes, isolated restart and stopped-file hashes; vary current SLH rules without importing legacy caches or Docker code |
| `fixtures/host/src/controls.rs::block` | `examples/pq_regtest_fixture.rs::block`, `examples/pq_regtest_fixture/nu7.rs::miner_fees` | Retain transparent template decoding, aggregate NU7 fee share, header, Merkle and history/auth commitments; remove unrelated funding mutations and backend branches |
| Mixed-input preparation/assembly | `examples/pq_regtest_fixture/nu7.rs`, `examples/pq_regtest_fixture/relay.rs` | Use actual parent bytes and the existing native public signing context; generalize the existing public classical signer to its input position |

The existing product `common`, `nodes`, `node_live`, fixture transport,
`TransactionRecipe`, signing context and signer adapters remain the shared
implementation. The new host operations use the existing strict envelope and
bounded parser; existing corpus operations and historical expected bytes are
unchanged. Host-supplied previous outputs remain untrusted until the driver
authenticates them through both actual nodes.
