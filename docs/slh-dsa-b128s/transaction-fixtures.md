# Public transparent transaction fixtures, version 1

This bounded test interface uses `slh-dsa-b-128s-exp-v1`. It exercises the
existing transaction context and native SLH authorization library. It neither
enables node consensus support nor authenticates synthetic spent outputs.
The initial corpus contains transparent-only NU7 v5/v6 transactions; it makes
no claim about shielded digest coverage. See [protocol](protocol.md) and
[primitive fixtures](fixtures.md).

## JSON and resource rules

All objects have exactly the fields described below. Reject duplicate and
unknown keys recursively, non-ASCII decoded strings/keys, nesting beyond 16,
and numeric tokens other than unsigned decimal integers (including `-0`,
fractions and exponents). Integers are at most u64; booleans are not integers.
Hex is lowercase, even-length, and has the specified decoded length. Bounds
apply before expensive work. A complete request/response or artifact including
its optional terminal newline is at most 16 MiB. Transaction bytes are at most
2,000,000; input count is 1..32, output count 1..64, previous/output scripts
at most 10,000 bytes, authorization at most 131,072 bytes and descriptors at
most 484 bytes. Counts and lengths also obey the stricter protocol rules.
Amounts and checked sums are at most 2,100,000,000,000,000 zatoshis. Indices,
sequence, height and branch fields fit u32. Transactions have no coinbase,
duplicate outpoints, Sapling, Orchard or Ironwood bundles.

The hash of an artifact is SHA-256 of its JSON object after removing only
top-level `artifact_sha256`, recursively sorting ASCII keys, preserving array
order, and encoding compact ASCII JSON with standard escaping and unsigned
decimal integers. There is no trailing newline in the hashed encoding.
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
value_zat, threshold, public_keys_hex, signer_indices}`. Public keys are
distinct 32-byte values; the host sorts their commitments to construct the
policy. Signer indices refer to this sorted policy and are strictly increasing
and exactly threshold in number. Each recipe output is `{value_zat,
input_policy_index}` or `{value_zat, script_hex}`: exactly one selector.

Success responses are `{schema_version: 1, contract, public_fixture: true,
op, ok: true, result}`. Failure responses replace `result` with
`error: {stage, reason}` and use `ok: false`; they never contain input bytes.
Stages are `transport`, `schema`, `integrity`, `correspondence`, `generation`.
Reasons are fixed snake_case identifiers, documented alongside implementation;
they are diagnostics rather than consensus rejection codes.

`prepare` result is `{case_id, network, transaction_version,
consensus_branch_id, unsigned_transaction_hex, inputs, outputs}`. Inputs use
the artifact input layout below, replacing `records` with
`signers: [{signer_index, public_key_hex}]`. This returns exact external
101-byte signing messages with empty context. `assemble` accepts record arrays
in that input order, checks their keys and signatures through the existing
native API, installs canonical authorizations, round-trips the transaction
with complete consumption, rechecks native authorization and returns the
artifact as `result`. No secret keys, seeds or randomness occur in artifacts.

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

Check order is: bounded transport/schema; artifact and transaction hashes;
complete transaction decoding and explicit wire/context correspondence;
native transaction context; structural preflight of all authorizations;
signature verification in input/index order; functional budget. Recompute
digest/message fields wherever native context can derive them. A context
failure skips only correspondence fields which cannot be computed. When raw
authorization parsing fails, descriptor/record correspondence is not available;
report that native failure rather than attempting to trust metadata. For all
structurally valid inputs, descriptor and records must equal decoded bytes
before any cryptographic check. Negative artifacts with changed context may
recompute their hashes/digests/messages and retain stale signatures; distinct
controls deliberately violate correspondence and expect interface failures.

`expected` (and `observed`) is `{native_authorization, native_rejection,
signature_checks, functional_profile}`. Authorization is `accept` or `reject`.
Rejection is null on success, otherwise `{stage, reason, input_index}` with
nullable input index for transaction context failures. Stages are `context`,
`authorization`, or `signature`. Context errors use existing native
`Rejection::name()` codes `transaction_version`, `backend_unavailable`,
`consensus_branch`, `input_context`, `sighash`; structural/reservation errors
use `authorization` and their native codes; crypto failures use `signature`
and reason `signature`. Use the first failure in input order, with structural
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
Revisions are 40 lowercase hex bytes-as-text characters. `zakura_revision`
identifies pinned upstream `9b175e9d3d46a6aa4cfb5552517c3d828852ecbc`, not a
claim that upstream contains these extensions. Algorithm revision is
`b392fe82d2d9770142477a576a758a233888bc0a`, BLAKE3 version `1.8.5`.
All SHA-256 fields are 64 lowercase hex characters. These claims must be
checked against actual sources/binaries by a production receipt; they alone
are not authentication or evidence of independent acceptance.

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
