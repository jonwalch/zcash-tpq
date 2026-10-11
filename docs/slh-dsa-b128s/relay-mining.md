# Relay and mining

Relay and mining use the [SLH protocol](protocol.md).
The implementation requires the feature, which is off by default.
Live acceptance remains open.

## Relay policy and fees

Relay checks exact `53 20 C32 c0` outputs before expensive authorization work.
Funding these outputs is nonstandard before candidate-height activation.
Such funding can still be consensus-valid in a block.
After activation, the SLH dust floor uses the existing dust rate and minimum input size:

```text
3 * floor(100 * (44 + 7973) / 1000) = 2403 zatoshis
```

The floor does not guarantee an economical spend of the hidden policy.
The pinned Zakura policy uses ZIP-317 action counts at 400 zatoshis per action.
The retained transparent fixtures have these conventional fees:

| Case | Fee in zatoshis |
| --- | ---: |
| 1-of-1 | 21,600 |
| 15-of-15 | 317,200 |
| 16 checks | 338,400 |
| 17 checks | 360,000 |

The 17-check case exceeds the test profile's transaction limit, regardless of its fee.
Classical funding still requires classical authorization and uses zero SLH checks.
Created outputs cannot select the native input verifier.

## Fee policy discussion

Any SLH-specific change to public fee accounting remains an [ecosystem question](open-questions.md#f1-slh-fee-policy).
The current implementation retains Zakura's fee rules.
It applies no SLH fee discount or surcharge.
These are wallet, relay, and mining rules, not consensus fee minima.

The comparison below uses ZIP status checked on 2026-10-10.
Each payment has one classical P2PKH (pay-to-public-key-hash) input,
one recipient output, and one change output of the same type.
The two-action minimum applies to each example.

| Policy | Zatoshis per action | Payment fee in zatoshis |
| --- | ---: | ---: |
| [ZIP 317](https://zips.z.cash/zip-0317), active fee rule | 5,000 | 10,000 |
| [ZIP 2009](https://zips.z.cash/zip-2009), draft proposal | 1,000 | 2,000 |
| [Pinned Zakura policy](../../crates/zakura-chain/src/transaction/unmined/zip317.rs) | 400 | 800 |

[ZIP 313](https://zips.z.cash/zip-0313) specified a flat 1,000-zatoshi fee.
ZIP 317 replaced it. ZIP 2009 proposes a fee per action, not a flat fee.

The one-input SLH 1-of-1 payment above uses 54 actions.
Its fee is 21,600 zatoshis at the pinned rate.
This is 27 times the classical example at the same rate.
The larger SLH authorization causes this difference.

The existing ZIP-317 formula already determines the size-based action count.
The prototype's 400-zatoshi rate and 2,403-zatoshi dust floor are implementation settings.
They are not proposed public defaults.
The open ecosystem choice is whether measured SLH costs justify changing the existing accounting:

- Compare SLH verification, bandwidth, and storage costs with fees under the existing rule.
  Any SLH discount, surcharge, or action-count change needs cost evidence and a compatibility review.
  Signature-check limits remain a separate resource control.
- Assess small payments and multisig spending under both the baseline and any proposed change.
- If a change is justified, specify coordinated wallet, relay, and mining behavior.
  Existing [saved fee approvals and change checks](wallet.md#capacity-limits) remain implementation safeguards.

## Mempool storage

Storage receives the configured network and uses the trusted tip plus one as candidate height.
Configured SLH storage rejects a missing tip or height overflow.
At active heights, storage requires all spent outputs in input order.
Structural thresholds must agree with verified metadata for the exact payload.
Changed authorization, UTXOs, metadata, or rules requires fresh verification.
Inactive storage retains upstream classical policy.
Active annotations cannot survive rollback below activation.

## Block templates

Template selection starts with the configured SLH block allowance.
It checks verified identity and active structural counts.
It also checks bytes, sigops, unpaid actions, and shielded limits before any deduction.
An omitted candidate leaves every allowance unchanged.
Every parent must enter the template before its child.

Independent classical funding and eligible classical children can enter after the SLH allowance is exhausted.
Template accounting is separate from the consensus budget for a verification attempt.

## Focused tests

Library tests use the public synthetic v5/v6 fixtures.
Selection tests change identities and explicitly bind trusted-result metadata.
They do not establish new signature acceptance.
Consensus tests verify the original signatures with mocked trusted state.
Synthetic shielded structures test resource accounting without proof generation.

```sh
cargo test --locked -p zakura-consensus --lib --features slh-test-observer slh
cargo test --locked -p zakura-rpc --lib --features experimental-slh-dsa-b128s slh
cargo test --locked -p zakura-rpc --lib methods::types::get_block_template::zip317::tests
```

Daemon storage tests are not feature-gated, so the default unit-test build includes them:

```sh
cargo test --locked -p zakura --lib slh_
```

Agents must obtain user approval before these runs under [AGENTS.md](../../AGENTS.md).
Live relay, mining, reset, and reorg tests also remain open under [AGENTS.md](../../AGENTS.md).

## Source attribution

The relay and mining code adapts `jonwalch/zcash-transparent-pq`
at `e759cb86a06510893f8e7d1eb986b7025401c8c9`.
The corresponding crates retain the MIT and Apache-2.0 licenses.
The import excludes other signature suites, research tools, and research history.

| Source under `node/zakura/` | SHA-256 | Adaptation |
| --- | --- | --- |
| `crates/zakura-consensus/src/transaction/check.rs` | `c184339daf6efb9784ea1d91396886ceca7e191a2b1483e426d3b96e12b239b6` | Retain single-suite dust formula and output policy. Substitute SLH recognition, 7,973-byte minimum input and policy-only errors. |
| `crates/zakurad/src/components/mempool/storage.rs` | `9cb434ea0b7315f7e37468d01854a8d47c1eb1a31f85aa8477610cc09830ccb8` | Retain candidate-height network context, structural/verified equality and exact-output bypass. Preserve upstream inactive storage policy unchanged instead of importing stricter unrelated legacy checks. |
| `crates/zakurad/src/components/mempool.rs` | `b609f1431001f99374973415da0a5c9a70bd1bc4bd740604369e7991b303cc04` | Reuse existing network-aware storage construction pattern through chain_tip_change.network(). No new state or reset path. |
| `crates/zakura-rpc/src/methods/types/get_block_template/zip317.rs` | `97e7bc006f9ebe06cad6e622837c269e28ed15887422f4b697873404917d0a09` | Retain separate native allowance, metadata validation and atomic all-resource prechecks. Use SLH only, with active structural/verified count agreement. |
| `crates/zakura-rpc/src/methods/types/get_block_template/zip317/tests/pq.rs` | `999bf34537d7da45a3b8d5a3a5f79049bead05185be034aeec97277f35a7f0f4` | Adapt resource, freshness, zero-cost and dependency-order tests to SLH 16/64 and retained public corpus. No runtime signing or alternate suites. |
| `crates/zakurad/src/components/mempool/storage/tests/pq.rs` | `ff4ac80c291b55ce83d78a5aa6248fd01b047a02b5a664e1f07f2270214a3bb2` | Adapt funding dust/context tests to SLH candidate height and 2,402/2,403/2,404. Add wrong-count/overflow/unauthorized controls. |
