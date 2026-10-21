# Launcher RPC diagnostics

`getchainrules` reports effective settings from the node's parsed network.
`inspectchainblock` reports the identity of exact canonical block bytes.
Neither method accepts a manifest, a claimed fingerprint, or a claimed height.
Neither method establishes consensus validity or readiness to receive payments.

## Access

Both methods have the `Admin` classification. They are absent from the restricted
listener and its `rpc.discover` result. Use the existing authenticated listener
and its configured credentials. Existing Regtest full-surface policy is unchanged.
The methods do not create an authentication exception on public networks.

## Effective rules

Request:

```json
{"jsonrpc":"2.0","id":1,"method":"getchainrules","params":[]}
```

Only explicit custom Testnet configurations are supported. Mainnet, built-in
public Testnet, Regtest, and artificial test NSM overrides return error `-8`.
For Regtest SLH status, continue to use `getblockchaininfo` and its existing
`experimental_slh_dsa_b128s` field.

For ordinary custom Testnet settings the result matches
`zakura-chain-rules/v1`. The result has these exact top-level fields:

- `apiVersion`: `zakura-chain-rules/v1`.
- `ruleset`: `zakura-configured-testnet/v1`.
- `networkKind`: `custom-testnet`.
- `rules`: the effective projection below.

The `rules` object contains:

| Field | Shape |
| --- | --- |
| `networkMagic` | Lowercase hex in wire byte order. |
| `genesisHash` | Block hash in RPC display order. |
| `checkpoints` | Ascending `[{"height":u32,"hash":string}]`, including genesis. |
| `activationHeights` | Ascending `[{"height":u32,"upgrade":string}]`; equal heights collapse to the effective upgrade. |
| `subsidy` | Object described below. |
| `difficulty` | `{"targetDifficultyLimitCompact":string,"proofOfWork":"disabled" or "equihash","maxBlockTimeStartHeight":u32}`. |
| `temporaryOrchardDisablingHeight` | u32 or null. |
| `experimental` | `{"pq":null,"sqisign":null}` for ordinary rules. |

`subsidy` contains `slowStartInterval`, `slowStartShift`,
`preBlossomHalvingInterval`, `postBlossomHalvingInterval`, `fundingStreams`,
`lockboxDisbursements`, `initialNsmValueBalance`, and
`allowUnshieldedCoinbaseSpends`. Heights are integers. Amounts are zatoshis.
An absent NSM seed is null, not zero.
Funding streams have `startHeight`, exclusive `endHeight`, and `recipients`.
Recipients have `receiver`, `numerator`, and ordered `scriptHashes`.
Receivers sort by wire name. Lockbox entries have `scriptHash` and `amount`;
they sort by hash and amount, without removing duplicates.
Only Testnet P2SH funding and lockbox addresses fit this version; others fail
with `-8`. The unit test's complete independently specified ordinary result is
in `crates/zakura-rpc/src/methods/chain_diagnostics/tests.rs`.

### SLH extension

An SLH custom Testnet does not pretend to use the ordinary ruleset. It returns:

```json
{
  "apiVersion":"zakura-chain-rules/slh-dsa-b128s/v2",
  "ruleset":"zakura-configured-testnet/slh-dsa-b128s/v2",
  "networkKind":"custom-testnet"
}
```

The same `rules` object is also present. Its `experimental` object includes
`pq:null`, `sqisign:null`, and `slhDsaB128s` with exactly these fields:

```json
{
  "contract":"slh-dsa-b-128s-exp-v1",
  "verifierCompiled":true,
  "runtimeSupported":true,
  "chainFingerprint":"<64 lowercase hex digits from the native network API>",
  "activationHeight":2,
  "maxChecksPerTransaction":16,
  "maxChecksPerBlock":64,
  "maxBlockBytes":20000000
}
```

Heights and limits above are fixture examples, not defaults. Build support
booleans come from the compiled consensus identity. A build without the feature
reports false runtime support, not success. A launcher must require supported
runtime and contract, compare every effective rule against independently trusted
settings, then separately check chain history, tip, and readiness. The native
fingerprint identifies normalized rules; it does not authenticate them.
An existing strict v1 consumer must reject this v2 result until it implements
this extension. No ZDN source is changed by this work.

The ordinary v1 shape does not advertise this fork's global 20 MB byte limit.
Use the SLH v2 report for that explicit diagnostic. The fixed ruleset names are
schema identifiers, not claims of public-network compatibility; see the
[protocol](protocol.md#network-and-state-rules).

## Exact block inspection

Request:

```json
{"jsonrpc":"2.0","id":2,"method":"inspectchainblock","params":["<canonical block hex>"]}
```

The result for the existing Mainnet genesis fixture is:

```json
{
  "apiVersion":"zakura-block-inspection/v1",
  "height":0,
  "hash":"00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08",
  "previousHash":"0000000000000000000000000000000000000000000000000000000000000000",
  "bytesLength":1692
}
```

The method accepts at most 40,000,000 hex characters (20,000,000 bytes).
It checks length before hex allocation, uses the native bounded block decoder,
requires full input consumption, and compares canonical reserialization.
It requires a recognized coinbase height. Hex case does not change byte identity.
Decoding runs on a blocking worker. The existing HTTP request-size limit remains
in force and can impose a lower limit. Concurrent calls still consume memory.

Empty, odd, oversized, trailing, or noncanonical data returns an error (`-8`
for explicit boundary checks; `-22` for decode failures). For example,
`params:["00"]` returns `-22`; `params:[""]` returns `-8`.
No state service, proof verification, submission, or signature checking occurs.
A decoded block can be invalid under consensus rules.

## Source mapping and checks

The base projection, types, canonical decoder, and ordinary fixture tests reuse
the research implementation at `jonwalch/zcash-transparent-pq` commit
`ce94c23dbe2120d102a0af10ec71e244af90eb85`, paths
`node/zakura/crates/zakura-rpc/src/methods/chain_diagnostics.rs` and
`node/zakura/crates/zakura-rpc/src/methods/chain_diagnostics/tests.rs`.
The research method wiring and admin-surface tests guided the corresponding
small edits here. Existing repository license terms remain in force.

Adaptations remove the research PQ and SQIsign runtime checks (those backends
are absent here), reuse this product's existing SLH status API, add the explicit
SLH v2 projection, and use the product's 20 MB bound in the oversized test.
No overlay, alternate backend, or source-checkout runtime dependency is imported.
The consumer comparison was inspected read-only in ZDN's
`src/chain/readiness.rs::expected_rules` and
`src/chain/bootstrap.rs::inspect_blocks`.

Focused tests cover complete ordinary rules, effective mutations, sorting and
multiplicity, unsupported networks, SLH version and build status, exact genesis
identity, malformed and noncanonical input, and HTTP listener access policy.
Integrated checks with Rust 1.97.1 passed all seven diagnostic tests with and
without the experimental feature. The enabled RPC library suite passed 256
tests, with two proof-related tests left ignored. This includes authenticated
and restricted HTTP listener checks. These are library checks, not live-node
qualification. No dedicated node builds or proof generation were run.
