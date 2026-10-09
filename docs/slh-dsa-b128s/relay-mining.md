# Experimental SLH relay and template selection

The SLH consumers use the [frozen contract](protocol.md). Runtime source is
integrated behind the default-off feature; live acceptance remains pending.

Relay checks exact `53 20 C32 c0` outputs before expensive authorization work.
Funding them is nonstandard before the candidate block height reaches activation,
but it can remain consensus-valid in a block. Active funding uses the existing
dust rate with the minimum SLH input: `3 * floor(100 * (44 + 7973) / 1000) = 2403`
zatoshis. This is a relay floor, not a guarantee that a hidden policy is economical
to spend. The existing ZIP-317 marginal fee remains 400 zatoshis per action.
For the retained transparent corpus, actual conventional fees are 21,600 for
1-of-1, 317,200 for 15-of-15, 338,400 for 16 checks and 360,000 for 17 checks.
The last shape exceeds the functional 16-check transaction limit despite its fee.
Classical authorization still runs for funding transactions and costs zero SLH
checks; created outputs never select native input verification.

Storage receives the configured network and derives candidate height from the
trusted tip plus one. Configured SLH storage rejects a missing or overflowing tip.
At active heights it requires complete ordered spent outputs and exact agreement
between structural thresholds and successful, payload-bound verification metadata.
Missing/replaced metadata, changed authorization or UTXOs, and incompatible rules
require verification again. Inactive storage retains upstream's classical policy;
active annotations cannot survive rollback below activation.

Template selection has a separate SLH allowance initialized from the configured
block limit. It checks verified identity and active structural counts, then checks
all byte, sigop, unpaid-action and shielded limits before deducting anything. An
omitted candidate leaves every allowance unchanged. Existing parent ordering is
preserved: all parents must be selected before a child. Independent classical
funding and eligible classical children remain selectable after SLH capacity is
exhausted. This is template accounting, separate from the consensus attempt budget.

## Focused checks

The library tests use the retained public synthetic v5/v6 corpus. Selection tests
mutate fixture identities and bind trusted-result metadata explicitly; they do not
claim new signature acceptance. The consensus tests exercise real original corpus
authorization and mock trusted-state services. Synthetic shielded structures test
resource accounting, without generating proofs.

```sh
cargo test --locked -p zakura-consensus --lib --features slh-test-observer slh
cargo test --locked -p zakura-rpc --lib --features experimental-slh-dsa-b128s slh
cargo test --locked -p zakura-rpc --lib methods::types::get_block_template::zip317::tests
```

Daemon storage tests are prepared but have not been compiled or executed by an
agent. A human must run the daemon-package checks and live relay/mining, reset,
reorg and lifecycle acceptance under [AGENTS.md](../../AGENTS.md). Existing mempool
reset logic is reused. Compiled feature availability does not establish end-to-end
node acceptance.

## Source attribution

The selected relay/miner implementation and test patterns below adapt
`jonwalch/zcash-transparent-pq` at `e759cb86a06510893f8e7d1eb986b7025401c8c9`.
The existing MIT and Apache-2.0 licenses are retained in the corresponding crate
directories. Other suites, research tools and research history are not imported.

| Source under `node/zakura/` | SHA-256 | Adaptation |
| --- | --- | --- |
| `crates/zakura-consensus/src/transaction/check.rs` | `c184339daf6efb9784ea1d91396886ceca7e191a2b1483e426d3b96e12b239b6` | Retain single-suite dust formula and output policy; substitute SLH recognition, 7,973-byte minimum input and policy-only errors. |
| `crates/zakurad/src/components/mempool/storage.rs` | `9cb434ea0b7315f7e37468d01854a8d47c1eb1a31f85aa8477610cc09830ccb8` | Retain candidate-height network context, structural/verified equality and exact-output bypass. Preserve upstream inactive storage policy unchanged instead of importing stricter unrelated legacy checks. |
| `crates/zakurad/src/components/mempool.rs` | `b609f1431001f99374973415da0a5c9a70bd1bc4bd740604369e7991b303cc04` | Reuse existing network-aware storage construction pattern through chain_tip_change.network(); no new state or reset path. |
| `crates/zakura-rpc/src/methods/types/get_block_template/zip317.rs` | `97e7bc006f9ebe06cad6e622837c269e28ed15887422f4b697873404917d0a09` | Retain separate native allowance, metadata validation and atomic all-resource prechecks; SLH only, plus active structural/verified count agreement. |
| `crates/zakura-rpc/src/methods/types/get_block_template/zip317/tests/pq.rs` | `999bf34537d7da45a3b8d5a3a5f79049bead05185be034aeec97277f35a7f0f4` | Adapt resource, freshness, zero-cost and dependency-order tests to SLH 16/64 and retained public corpus; no runtime signing or alternate suites. |
| `crates/zakurad/src/components/mempool/storage/tests/pq.rs` | `ff4ac80c291b55ce83d78a5aa6248fd01b047a02b5a664e1f07f2270214a3bb2` | Adapt funding dust/context tests to SLH candidate height and 2,402/2,403/2,404; add wrong-count/overflow/unauthorized controls. |
