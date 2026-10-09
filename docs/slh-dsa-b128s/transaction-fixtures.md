# Public transparent transaction fixtures, version 1

This bounded test interface uses `slh-dsa-b-128s-exp-v1`. It exercises the
existing transaction context and native SLH authorization library. It neither
enables node consensus support nor authenticates synthetic spent outputs.
The initial corpus contains transparent-only NU7 v5/v6 transactions; it makes
no claim about shielded digest coverage. See [protocol](protocol.md) and
[primitive fixtures](fixtures.md).

## JSON and resource rules

Objects contain exactly the fields specified below.
The parser rejects duplicate or unknown keys at every depth.
Decoded keys and strings must be ASCII.
Numbers must be unsigned decimal integers within u64.
Negative zero, fractions, exponents, and booleans are not valid integer values.
Hex must be lowercase, even-length, and the specified decoded size.

| Resource | Limit |
| --- | --- |
| Request, response, or artifact | 16 MiB, including an optional final newline |
| JSON depth | 16 |
| Transaction | 2,000,000 bytes |
| Inputs / outputs | 1–32 / 1–64 |
| Previous-output or created-output script | 10,000 bytes |
| Authorization / descriptor | 131,072 / 484 bytes |
| Amount and checked sum | 2,100,000,000,000,000 zatoshis |
| Index, sequence, height, and branch | u32 |

Bounds apply before expensive work. Stricter protocol limits also apply.
Transactions exclude coinbase, duplicate outpoints, and shielded bundles.

The artifact hash is SHA-256 of the canonical JSON object without the top-level `artifact_sha256` field.
Canonicalization sorts ASCII keys recursively and preserves array order.
It uses compact ASCII JSON, standard escaping, unsigned decimal integers, and no final newline.
Python's `json.dumps(value, sort_keys=True, separators=(',', ':'),
ensure_ascii=True, allow_nan=False).encode('ascii')` defines this encoding.
`transaction_sha256` hashes the decoded transaction, independently.

## Recipe and operations

The host accepts one request and returns one response. Request common fields
are `schema_version: 1`, `contract`, `public_fixture: true`, and `op`.
Additional fields are exactly:

| op | Additional fields |
| --- | --- |
| `prepare` | `recipe` |
| `assemble` | `recipe`, `records` (one array per ordered input), `producer` |
| `check` | `artifact` |

The recipe is `{case_id, network, transaction_version, lock_time,
expiry_height, inputs, outputs}`. `case_id` matches `[a-z0-9_-]{1,64}`;
`network` is `Mainnet`, `Testnet` or `Regtest`; version is 5 or 6.
`lock_time` is a block height below 500,000,000. Branch is NU7, `0x77190ad9`.
Each recipe input is `{outpoint: {txid_display_hex, index}, sequence,
value_zat, threshold, public_keys_hex, signer_indices}`.
Public keys are distinct 32-byte values.
The host sorts their commitments to construct the policy.
Signer indices refer to this sorted policy.
They must increase strictly, with exactly threshold indices. Each recipe output is `{value_zat,
input_policy_index}` or `{value_zat, script_hex}`: exactly one selector.

Success responses are `{schema_version: 1, contract, public_fixture: true,
op, ok: true, result}`. Failure responses replace `result` with
`error: {stage, reason}` and use `ok: false`; they never contain input bytes.
Stages are `transport`, `schema`, `integrity`, `correspondence`, `generation`.
Reasons are fixed snake_case identifiers, documented alongside implementation;
they are diagnostics rather than consensus rejection codes.
On failure, `op` is `unknown` when strict parsing could not determine the
operation; a successful response always names the requested operation.

`prepare` result is `{case_id, network, transaction_version,
consensus_branch_id, unsigned_transaction_hex, inputs, outputs}`. Inputs use
the artifact input layout below, replacing `records` with
`signers: [{signer_index, public_key_hex}]`. This returns exact external
101-byte signing messages with empty context. `assemble` accepts record arrays in input order.
It checks keys and signatures through the native API and installs canonical authorizations.
It serializes and fully decodes the transaction, then checks native authorization again.
It returns the artifact as `result`. Artifacts contain no secret keys, seeds, or randomness.

`check` result is `{observed, expectation_match}`. `observed` has the same
layout as `expected` below; it is computed independently of claimed expected
values. A validly encoded artifact can describe native rejection. Invalid
transport/schema, hashes or correspondences use a failure response, never a
fabricated native rejection. The independent oracle computes its own result
before optionally consulting this host as a comparison target.

## Artifact layout

Top-level fields are exactly `schema_version: 1`, `contract`,
`public_fixture: true`, `case_id`,
`context_provenance: "synthetic-public-fixture"`, `producer`, `network`,
`transaction_version`, `consensus_branch_id`, `transaction_hex`,
`transaction_sha256`, `inputs`, `outputs`, `expected`, `artifact_sha256`.

Each input is `{input_index, outpoint, sequence, spent_output,
descriptor_hex, sighash_all_digest_hex, message_hex, context_hex, records}`.
`input_index` equals its array position. `outpoint` is
`{txid_display_hex, index, wire_hex}`; display hex is the conventional 32-byte
transaction hash, and wire bytes are its reversal followed by LE32(index).
These and sequence must match the corresponding serialized input.
`spent_output` is `{value_zat, script_hex}` supplied explicitly in input order.
It is synthetic context, not proof that a UTXO exists. The digest is raw 32-byte
SIGHASH_ALL, without byte reversal; `message_hex` is exactly 101 bytes and
`context_hex` is empty. Records are
`{signer_index, public_key_hex, signature_hex}`, using 32- and 7,856-byte values.
Each output is `{output_index, value_zat, script_hex}` and matches the wire.

The host checks an artifact in this order:

1. Bounded transport and schema.
2. Artifact and transaction hashes.
3. Complete transaction decoding and agreement between wire bytes and supplied context.
4. Native transaction context.
5. Structure of every authorization.
6. Signatures in input/index order.
7. The functional budget.

Digest and message fields are recalculated wherever the native context permits.
A context failure skips only fields that cannot be calculated.
If authorization parsing fails, descriptor/record comparison is unavailable.
The host reports that native failure instead of trusting metadata.
For structurally valid inputs, descriptors and records must match decoded bytes before cryptography.
Some negative artifacts change context and recalculate hashes, digests, and messages while retaining stale signatures.
Separate mismatch controls deliberately violate field correspondence and expect interface errors.

`expected` (and `observed`) is `{native_authorization, native_rejection,
signature_checks, functional_profile}`. Authorization is `accept` or `reject`.
Rejection is null on success, otherwise `{stage, reason, input_index}` with
nullable input index for transaction context failures. Stages are `context`,
`authorization`, or `signature`. Context errors use native `Rejection::name()` codes:
`transaction_version`, `backend_unavailable`, `consensus_branch`, `input_context`, and `sighash`.
Structural/reservation errors use stage `authorization` and their native codes.
Crypto failures use stage `signature` and reason `signature`. Use the first failure in input order, with structural
preflight preceding all crypto. `signature_checks` is null for context or
structural failure, otherwise the sum of canonical thresholds, even if crypto
fails. These stage choices describe this test adapter, not consensus precedence.

`functional_profile` is `{transaction_limit: 16, block_limit: 64, result,
stage}`. If native rejects, result is `not_evaluated`, stage is null. Otherwise
result is `accept` and stage null for at most 16 checks, or `reject` and
`transaction_budget` above 16. No block is evaluated here. A 17-check artifact
has valid native signatures and fails only this explicit test profile.

## Producer identity

`producer` is exactly `{zakura_revision, algorithm_revision, blake3_version,
host_source_inventory_sha256, host_lock_sha256, host_binary_sha256,
signer_source_inventory_sha256, signer_lock_sha256, signer_binary_sha256}`.
Revisions are 40 lowercase hex characters. `zakura_revision`
identifies pinned upstream `9b175e9d3d46a6aa4cfb5552517c3d828852ecbc`, not a
claim that upstream contains these extensions. Algorithm revision is
`b392fe82d2d9770142477a576a758a233888bc0a`, BLAKE3 version `1.8.5`.
All SHA-256 fields are 64 lowercase hex characters. A production receipt must compare these claims with actual sources and binaries.
The fields alone do not authenticate a build or establish independent acceptance.

A source inventory is the canonical JSON hash (same rules as above) of an
array of `{path, sha256}` objects sorted by repository-relative ASCII path.
Use regular tracked source files, reject symlinks, and exclude any component
named `target`, `__pycache__`, `.git`, and files named `Cargo.lock`. The host
inventory contains root `Cargo.toml`, and all files under:

* `tests/slh-dsa-b128s/fixtures/host/`
* `crates/pq-slh-dsa-b-exp/`, `crates/pq-slh-dsa-b-verify/`
* `crates/pq-tx-context/`, `crates/pq-test-support/`, `crates/zakura-chain/`

It also contains `tests/slh-dsa-b128s/fixtures/generate_transactions.py`.
The signer inventory contains all files under
`tests/slh-dsa-b128s/fixture-signer/` and `crates/pq-slh-dsa-b-verify/`, including
its retained upstream attribution and source inventories. Lock hashes are
respectively the root and isolated signer locks. Binary hashes identify the
exact invoked executable bytes. Retain inventory lists and raw artifact-file
hashes in the production receipt, allowing later source changes to be detected.

## Deterministic public corpus

There are 18 cases: both `v5-` and `v6-` prefixes followed by `1of1`, `2of3`,
`3of5`, `8of10`, `10of10`, `15of15`, `1of15-index14`, `16checks`, `17checks`.
Artifact paths are `tests/slh-dsa-b128s/fixtures/data/<case_id>.json`.
All use Regtest/NU7, height lock 5, expiry 140 and sequence `0xfffffffe`.
Each input value is 100,000; outputs are 20,000 and 30,000 to input 0's policy.
The two multi-input cases use 15of15 plus 1of1 or 2of3 respectively; these
heterogeneous policies are node authorization controls, not wallet grouping
policy. All other cases have one input.

Generate a shared inventory of 15 public test keys, indexed 0..14. Seed i is
the first 48 bytes of SHA-512 of ASCII
`Zakura/SLH-public-corpus/seed/v1\0` followed by LE32(i). These are explicitly
public, non-operational keys. A policy of n participants selects the first n
keys, sorts their commitments, and selects the first m indices, except
`1of15-index14`, which selects index 14. Per-signature randomizer is the first
16 bytes of SHA-256 of ASCII `Zakura/SLH-public-corpus/randomizer/v1\0`,
case_id ASCII, NUL, LE32(input_index), and the single-byte signer index.
Outpoint display hash is SHA-256 of ASCII
`Zakura/SLH-public-corpus/outpoint/v1\0`, case_id ASCII, NUL and LE32(input_index);
outpoint index is input_index + 1. The complete corpus needs 146 signatures.
Generate it as a bounded conformance operation, not a timing or resource study.
Never reuse this deterministic procedure for wallet key material.
