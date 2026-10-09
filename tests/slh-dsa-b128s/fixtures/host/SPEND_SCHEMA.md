# Public shielded spend fixture schema

These optional `shielded-fixtures` operations prepare real Sapling, Orchard and
Ironwood note spends alongside native SLH or the existing public classical
controls. They use the standard schema-1 public fixture envelope and reject
unknown fields. They do not accept operational keys. All shielded keys derive
from the fixed public `[42;32]` material used by the output fixture.

The host consumes trusted node history. It does not verify block consensus.
Before host execution, the driver must authenticate blocks, parent outputs, source, configuration, and tree state against both nodes.
The host never treats caller-supplied amounts or scripts as UTXO authority.
It derives all amounts/scripts from canonical historical transactions.

## Funding and legal profile

Use a fresh isolated Regtest profile with NU6.2 at 1, NU6.3 at 104, NU7 at 105,
and SLH at 110. A mature height-1 classical coinbase supplies the 50,000-zatoshi
Orchard deposit at height 102. The `shielded-spend-funding` recipe is:

```json
{"human_run":true,"parent_hex":"<canonical actual parent transaction>",
 "output_index":0,"expiry_height":103,"kind":"single"}
```

`kind` is `single` or `multisig`. This operation builds v5/NU6.2 Orchard v2 with
the fixed post-NU6.2 circuit, spends disabled, one real nonzero note and normal
padding. It applies the shielded binding signature to all final effects, then
uses the existing public classical signer at that exact branch. It returns the
fully signed transaction. Relay and mine it before height 104. It expires at 103;
it cannot be reused as post-NU6.3 Orchard deposit funding. No consensus rule is
relaxed. The older insecure pre-NU6.2 circuit is never used.

The funding result includes the normal transaction hex/SHA256/TXID/auth digest,
output list and output/action counts, but has no native SLH message. It also has
`material="public-test-only"`, `version=5`, `parent_txid`, `parent_index`,
`parent_value_zat`, `parent_script_hex`, `parent_transaction_sha256`,
`fee_zat=100000`, `deposit_zat=50000`, `orchard_value_zat=50000`,
`proof_profile="orchard-pre-nu6.3"`, `pool_valid={"orchard":true}`,
`ecdsa_checks` and `slh_checks=0`.

After height 110, the existing [output host](SHIELDED_ATTRIBUTION.md) deposits
50,000 zatoshis in Sapling and/or Ironwood. The mined SLH transparent parent can
be a separate funding transaction. Funding txids may repeat across pools when
one actual transaction created both notes. Each selected pool must contain
exactly one decryptable nonzero 50,000-zatoshi public note and a net 50,000
deposit, without shielded spends in that pool. Orchard's funding must be v5/NU6.2
at 102 or 103; Sapling/Ironwood funding must use NU7 at height 110 or later.

## Spend prepare and finalize

`shielded-spend-prepare` takes this recipe:

```json
{"human_run":true,"transaction_version":6,"pools":["sapling","orchard","ironwood"],
 "parent_hex":"<canonical actual unspent parent>","output_index":0,
 "expiry_height":210,"authorization":"slh","public_key_hex":"<public fixture key>",
 "sapling_parameters":{"spend_path":"/absolute/public/sapling-spend.params",
  "spend_sha256":"<sha256>","output_path":"/absolute/public/sapling-output.params",
  "output_sha256":"<sha256>"},
 "history":{"blocks":["<genesis block hex>","<block 1 hex>","<...tip block hex>"],
  "treestate":{"height":112,"hash":"<tip hash>","sapling":{"commitments":{"finalRoot":"<root>"}},
   "orchard":{"commitments":{"finalRoot":"<root>"}},"ironwood":{"commitments":{"finalRoot":"<root>"}}}},
 "funding_txids":[{"pool":"sapling","txid":"<mined funding txid>"},
  {"pool":"orchard","txid":"<mined pre-NU6.3 funding txid>"},
  {"pool":"ironwood","txid":"<mined funding txid>"}]}
```

Use the full `z_gettreestate` response. Unshown response fields are retained in
its history digest. Pools must appear in Sapling/Orchard/Ironwood order. All
three nonempty v5 Sapling/Orchard subsets and all seven nonempty v6 subsets are
supported. `funding_txids` has exactly one entry per selected pool, in that order.
For classical `single`/`multisig` authorization, `public_key_hex` must be null.
`sapling_parameters` must be null when Sapling is absent. Required nullable
fields cannot be omitted. Parameters reuse the bounded explicit public parameter
loader and pinned library hash validation; no download or path search occurs.

The host checks these bounds before proof generation:

| Item | Bound |
| --- | --- |
| Tip height | 110–512 |
| History | At most 513 blocks |
| Raw block / total raw blocks | 512 KiB / 6 MiB |
| Transactions | 8,192 |
| Commitments per pool | 4,096 |
| Resulting transaction | 262,144 bytes |
| JSON envelope | 16 MiB |

Expiry is 111–1000 and strictly greater than the exported tip. The exact Regtest
genesis, canonical complete block encoding, contiguous heights/parents, unique
transaction identities, unique consumed prevouts and exact tip hash/height are
checked. Historical funding prevouts resolve from earlier blocks in input order.
The transparent parent must occur with identical bytes, contain the specified
output and remain unspent; coinbase maturity is checked. The driver additionally
checks its live availability before every subject operation.

Reconstruction decrypts the public note and locates its output/action and commitment position.
It appends later commitments and compares the witness root, node root, and supplied tree-state root. Position selection
works when commitments repeat. Nullifiers are derived from the actual note/key
(and Sapling position), then checked against the full exported chain. Missing,
already spent or mismatched notes and roots fail before parameters or proving
keys are loaded. This is observed public-chain state, not internal DB membership.
The supplied `finalRoot` and returned note `anchor` retain the node RPC's display
order. Sapling's display order reverses its canonical anchor bytes; Orchard and
Ironwood use the canonical order. Recovery and finalization reuse the node's
`bytes_in_display_order` conversion for Sapling while witness/path comparisons
continue to use canonical anchor bytes. The opposite RPC byte order is rejected.

Each selected pool spends one real 50,000-zatoshi note. Sapling has one spend
and two padded outputs; each action pool has two actions including padding.
Orchard/Ironwood disable genuine outputs. Orchard v3 disables cross-address
transfers. The transparent change equals actual parent value plus 50,000 per
selected pool minus the fixed 100,000 fee. All pool effects are installed before
shielded signatures; the native SLH signer is invoked only after prepare.

Prepare returns the output host's `positive` wire object and `variants`, plus:

- `material`, `version`, `pools`, the six parent identity/value fields described
  for funding, `fee_zat=100000`, `deposit_zat=0`, `withdrawal_zat=50000*pool_count`,
  `orchard_value_zat` (50,000 when selected, otherwise zero),
  `proof_profile="real-spend-post-nu6.3"`, and `parameters`.
- `history_sha256`: SHA256 of canonical ASCII JSON `{blocks,treestate}`, sorted
  object keys, compact separators, no trailing newline; `anchor_height` and
  `anchor_block_hash` identify the matching exported tip.
- Ordered `notes`: `pool`, `funding_txid`, `funding_height`,
  `funding_output_index`, `position`, `value_zat`, `anchor`, `nullifier`,
  `commitment`, `commitment_count`, and `real_spend_index`. The latter is the
  randomized index in this spend transaction, not the funding output index.
- `positive_pool_valid` and `positive_components`, plus each variant's `pool`,
  `mutation`, `pool_valid`, and `components`.

For each pool, mutations are `spend_auth`, `binding`, and `proof`. The signature
mutants use real signatures over the wrong digest. A proof donor is another
real proof for different randomized public inputs; it is verified at its own
public inputs before copying only its canonical proof bytes. Sapling copies its
spend proof, never an output proof. Restoring the selected field must recover
the entire positive transaction. TXID, complete effects and native message are
unchanged; authorization digest and bytes change. Only the selected pool's
aggregate verification may fail.

`components[pool]` contains the spend authorization boolean vector and binding
boolean. Action pools also report a direct proof boolean. Sapling `proof` is
explicitly null: its batch result, independently checked signatures/binding,
verified donor and exact field isolation establish the proof-only control,
without claiming an independent per-proof result or primitive counters.

`shielded-spend-finalize` takes the same recipe plus top-level `transaction_hex`
and required nullable `record`, exactly like the existing finalizer. It reconstructs trusted context without proof generation.
It checks the transparent skeleton, pools, counts, balances, nullifier, and anchor.
It then uses the existing native verifier or public classical signer. For SLH, the caller obtains
one signature over `positive.message_hex` from the isolated public signer and
reuses it across authorization-only variants. Final output contains the normal
wire fields plus `slh_checks`, `ecdsa_checks`, `fee_zat`, `deposit_zat=0`, and
`withdrawal_zat`. Prepare/finalize never accept private signing material.

`shielded-spend-block` uses the existing `ControlBlockRecipe`, bounded to the
same one-transparent-input, at-most-one-Sapling-spend and two-output/action
shapes. It is a separate NU7 block-construction operation; ordinary
`control-block` remains transparent-only and `shielded-block` remains output-only.

## Offline validation and scope

```sh
cargo fmt -p slh-dsa-b128s-fixture-host -- --check
cargo test --locked -p slh-dsa-b128s-fixture-host --features shielded-fixtures --bin slh-dsa-b128s-fixture-host
cargo clippy --locked -p slh-dsa-b128s-fixture-host --features shielded-fixtures --all-targets -- -D warnings
```

The new tests do not create proofs, SLH signatures or nodes. Witness tests use
canonical field leaves. History/decryption tests create public ciphertext and
builder effecting data with explicitly invalid zero proof/authorization bytes;
they never send those transactions to a verifier or claim consensus validity.
They test note recovery and builder witness compatibility, including old Orchard
notes in the post-NU6.3 spend builder. Existing bounded classical tests remain.
Real proving, relay, mining, duplicate-nullifier and anchor lifecycle results
require separately scheduled live execution with exact source/build/artifact
receipts. See [source attribution](SPEND_ATTRIBUTION.md).
