# Primitive-call observations

The consensus worker can log entry into the real SLH signature primitive on Regtest.
This diagnostic is off by default and requires the SLH verifier feature.
It does not change validation, signature results, reservation order, errors, or allowances.
The eight-field verifier identity remains unchanged.
An entry proves an attempted call, not successful verification or node acceptance.

## Enable capture

Set `ZAKURA_SLH_PRIMITIVE_OBSERVE` to exactly 32 lowercase hexadecimal characters.
Enable the `slh_primitive=info` tracing target in the configured Regtest process.

The token is a public capture identifier, not a secret.
The process reads it once.
An absent or invalid token produces no entries.
A non-Regtest context also produces no entries.
Each entry contains:

- The schema marker, contract, and `portable-rust` backend.
- The token, process ID, and increasing event sequence.
- The public TXID and authorization digest in RPC display order.
- The input index and reserved-check ordinal within that input.

The ordinal is not the policy signer index.
For example, member 14 of a 1-of-15 policy has ordinal 0.
Entries exclude keys, signatures, messages, secrets, timing, and resource measurements.
The authorization digest distinguishes changed signatures with the same TXID.
Concurrent threads can write lines in a different order from sequence assignment.
Reservation order and failure selection remain unchanged.

## Capture API

The [acceptance drivers](acceptance.md) accept an optional observation token:

```python
with Network(binary, artifacts, miner, observation_token="0123456789abcdef0123456789abcdef") as network:
    # Existing human scenario; retain actual public transaction bytes, decoded
    # identities, RPC outcomes, actual parents and tips independently.
    ...
```

`ManagedNode` accepts the same keyword.
Calls without a token remove any inherited observation variable.
An explicit token enables the tracing target.
Each cleanly stopped process writes `node-a/observation-0.json`, then 1 and 2 after restarts.
The capture binds source, binary, configuration, token, PID, and a byte interval in `node.log`.
The preceding log bytes must stay unchanged.
Replaced logs, partial lines, changed inputs, or failed shutdown prevent a complete capture.
A complete capture alone does not prove event coverage or functional acceptance.

Agents must obtain user approval before live capture under [AGENTS.md](../../AGENTS.md).
It adds diagnostics to functional tests. It does not measure resources or change retries.

## Check a saved capture

Use distinct genuine SLH positive controls before and after the subject operation.
Retain their functional outcomes separately.
An observed call does not prove that the positive operation succeeded.
The fixture host records `txid`, `authdigest`, and exact raw bytes.
After confirmation, compare these with `getrawtransaction`.
Zakura has no `decoderawtransaction` RPC.
Rejected transactions are unavailable through `getrawtransaction`.
These identity comparisons are not independent digest or UTXO checks.

After process shutdown, run this parser without a live binary:

```sh
python3 tests/slh-dsa-b128s/acceptance/observations.py \
  --capture /absolute/run/node-a/observation-0.json \
  --log /absolute/run/node-a/node.log \
  --node /absolute/build/zakurad \
  --config /absolute/run/node-a/node.toml \
  --node-build /absolute/build/build.json \
  --positive-before BEFORE_TXID:BEFORE_AUTHDIGEST \
  --positive-after AFTER_TXID:AFTER_AUTHDIGEST \
  --subject SUBJECT_TXID:SUBJECT_AUTHDIGEST \
  --output /absolute/existing-directory/new-observation-receipt.json
```

Replace each identity component with 64 lowercase hexadecimal characters.
Use a new output file.
Repeat `--subject` for at most 32 distinct subjects.
The binary and build receipt must match clean source and captured identities.
Later processes can append to the log.
The captured interval and preceding bytes must still match their hashes.

## Parser limits and count meanings

| Item | Requirement |
| --- | --- |
| Log / line / events | At most 32 MiB / 16 KiB / 4,096 |
| Entry identity | Exact schema, token, PID, backend, and contract |
| Sequence | Unique and contiguous, starting at 1 |
| Escapes | Narrow terminal color escapes only |
| Positive controls | Distinct identities. Every before-control entry precedes every after-control entry. |

Missing, repeated, wrapped, malformed, or truncated events cause failure.
A repeated earlier control after the later control invalidates the bracket.
Absent subject lines alone cannot establish zero calls.

The receipt counts the full process and the window between the last before-control and first after-control entries.
Counts include retries and concurrent calls.
A subject can have zero window entries but later process entries.
The receipt reports both counts.
**Neither is an isolated RPC count.**
RPC rejection does not prove that workers finished.

The receipt cannot establish per-request attribution, successful verification, node acceptance,
resource use, or absence outside the window.
Hashes provide traceability, not attestation of a hostile host or logger.

## Focused tests and attribution

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/acceptance -p test_observations.py -v
cargo test --locked -p zakura-pq-slh-dsa-b-exp --features test-observer
cargo test --locked -p zakura-consensus --lib --features slh-test-observer slh
```

Native tests reuse public signatures for valid, invalid, and pre-reservation cases.
Consensus tests compare logs with the test-only observer.
They cover v5/v6, high signer indices, parallel work, bad signatures, malformed encoding, and exhausted budgets.
Python tests cover startup mocks, bounds, identities, sequences, capture completion, and zero-count requirements.
They do not establish live capture.

The diagnostic mechanism adapts MIT/Apache-2.0 research revision
`e759cb86a06510893f8e7d1eb986b7025401c8c9`:

- `node/zakura/crates/zakura-consensus/src/transaction/sqisign/worker.rs::observe_entry`
- `node/tests/sqisign_c_comparison.py::check_entries`

The callback cannot replace the primitive or its result.
The [source map](../../tests/slh-dsa-b128s/acceptance/sources.json) records exact mappings.
