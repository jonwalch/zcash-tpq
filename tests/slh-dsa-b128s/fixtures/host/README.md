# Public SLH transaction host

The complete request, response and corpus format is in
[transaction fixtures](../../../../docs/slh-dsa-b128s/transaction-fixtures.md).
Run one bounded JSON request on stdin and receive one JSON response. The
`prepare`, `assemble` and `check` operations never hold or request secret keys.
Prepared outpoints/values/scripts are synthetic fixture context.

Additional public acceptance operations provide classical funding, mixed-input
controls and transparent block construction. See the
[human runbook](../../../../docs/slh-dsa-b128s/acceptance.md) and
[lifecycle controls](../../../../docs/slh-dsa-b128s/lifecycle-controls.md).
Their fixed public ECDSA test scalars are explicitly attributable and are never
operational wallet keys. Original corpus operations and bytes remain unchanged.

Select this package explicitly for focused checks:

```sh
cargo test --locked -p slh-dsa-b128s-fixture-host
cargo clippy --locked -p slh-dsa-b128s-fixture-host --all-targets -- -D warnings
python3 -m unittest discover -s tests/slh-dsa-b128s/fixtures -p 'test_generate_transactions.py'
```

After integrating and building the exact host and isolated primitive signer,
produce the single bounded corpus into a new directory:

```sh
python3 tests/slh-dsa-b128s/fixtures/generate_transactions.py \
  --host /path/to/slh-dsa-b128s-fixture-host \
  --signer /path/to/slh-dsa-b128s-public-fixture \
  --output /path/to/new-public-corpus
```

This generates 15 prescribed public keys and 146 signatures for 18 artifacts,
with no repetitions or measurements. It refuses an existing output directory.
The production receipt retains actual tracked-source inventories, source
commit/scoped status, locks, executable hashes and raw artifact hashes. The
producer checks these inputs again before writing output. This receipt alone
does not establish independent acceptance or a live-node result.

Interface errors are distinct from native authorization results. Fixed error
reasons by stage are:

* `transport`: `encoded_size`, `response_size`.
* `schema`: `json`, `numeric_token`, `non_ascii`, `nesting`, `fields`, `envelope`,
  `hex`, `hex_length`, `network`, `case_id`, `transaction_shape`, `amount`,
  `producer_pin`, `outpoint`, `signer_index`, `signature_length`, `lock_time`,
  `policy`, `signer_indices`, `duplicate_outpoint`, `output_policy_index`,
  `functional_profile`, `signature_checks`, `expected`, `native_rejection`,
  `context_provenance`, `input_fields`, `artifact_object`, `record_arrays`.
* `integrity`: `transaction_hash`, `artifact_hash`.
* `correspondence`: `transaction_encoding`, `trailing_transaction_bytes`,
  `transaction_shape`, `shielded_data`, `consensus_branch`, `coinbase`,
  `authorization_size`, `input_wire`, `duplicate_outpoint`, `output_wire`,
  `message_digest`, `authorization_fields`.
* `generation`: `context`, `message`, `serialization`, `authorization`,
  `transaction_size`, `native_recheck`.

Malformed requests with no recognized operation use `op: "unknown"`. Errors
contain fixed diagnostics, never echoed input bytes. Native failure names and
stage grouping are defined by the fixture specification. The native result is
computed without consulting the claimed expected outcome; `expectation_match`
then compares them. Neither the host nor producer is an independent oracle.
