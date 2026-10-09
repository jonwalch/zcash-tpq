# Opt-in SLH primitive-entry observation

The consensus worker can emit an explicit Regtest diagnostic at the real
SLH-DSA-B-128s primitive entry point. It is disabled by default, compiled only
with the existing SLH verifier feature, and changes no validation rule, signature
result, reservation order, error precedence or allowance. The public eight-field
verifier identity remains unchanged. This is entry evidence, not a successful
signature or node acceptance result.

Set `ZAKURA_SLH_PRIMITIVE_OBSERVE` to exactly 32 lowercase hexadecimal characters
and enable the `slh_primitive=info` tracing target for an explicitly configured
Regtest process. This public capture token is an identifier, not a secret. An
absent/invalid token and non-Regtest context emit nothing. The token is read once
per process. The diagnostic contains only:

- Fixed schema marker, contract and `portable-rust` backend.
- Capture token, process ID and monotonically assigned event sequence.
- Public transaction ID and authorizing-data digest, both in RPC display order.
- Transparent input index and reserved-check ordinal within that input.

The check ordinal is **not** the policy signer index: a 1-of-15 policy signed by
member 14 emits ordinal 0. No keys, signatures, signing messages, secrets, timing or
resource measurements are logged. The authorizing digest distinguishes changed
signatures with unchanged transaction IDs. Sequence assignment may differ from
line-write order across Rayon threads; reservation and ordered failure selection
remain the existing implementation.

## Prepared capture API

The existing human-only [acceptance adapters](acceptance.md) accept an optional
keyword when constructing their managed nodes:

```python
with Network(binary, artifacts, miner, observation_token="0123456789abcdef0123456789abcdef") as network:
    # Existing human scenario; retain actual public transaction bytes, decoded
    # identities, RPC outcomes, actual parents and tips independently.
    ...
```

`ManagedNode` accepts the same keyword. Existing calls keep their behavior and
remove any inherited observation environment variable. Explicit opt-in adds the
tracing target and passes only the chosen token. Each cleanly stopped process
writes `node-a/observation-0.json` (then 1, 2 on restarts), binding source, binary,
configuration, token/PID and the exact byte interval in `node.log`. Existing log
prefixes must remain unchanged; log replacement, incomplete lines, source/input
changes or unsuccessful shutdown prevent a complete capture. A closed-process
capture alone does not establish complete event coverage or acceptance.

No driver or build was executed to validate this API. Dedicated node builds and
actual live capture remain subject to [AGENTS.md](../../AGENTS.md) and the
human acceptance workflow. Capture adds diagnostics to an existing functional
scenario; it does not register a resource experiment or alter retry behavior.

## Bounded offline receipt

Use distinct genuine SLH positive-control identities before and after the
subject operation. Retain their ordinary functional outcomes separately. A
positive entry proves that observation reached the primitive; this parser does
not verify that the signature or operation succeeded. The existing decoded
transaction RPC includes `txid` and `authdigest`; retain its response and exact
raw transaction bytes. The diagnostic comparison is not an independent digest
oracle and does not authenticate UTXOs.

After stopping the process, inspect its capture without launching any binary:

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

Replace each uppercase identity placeholder with its 64-character lowercase hex
value. The output must be new; repeat `--subject` for up to 32 distinct subjects.
The binary and exact build receipt must match the current clean source and
captured configuration/source identities. A later process may append to the log,
but the captured interval and its preceding bytes must still match their hashes.

Parsing is limited to 32 MiB of log bytes, 16 KiB per line and 4,096 events. Every
matching marker must have the exact schema, token, PID, backend and contract.
Sequences must be unique and contiguous starting at 1; missing, duplicated,
wrapped, malformed or truncated observations fail. Narrow terminal color escapes
are removed; other control escapes in an entry fail. Both distinct positive
controls must appear, with every before-control sequence preceding every
after-control sequence. Repeated earlier controls arriving after the later
control invalidate the bracket. Absence of subject lines alone cannot produce
a zero-window receipt.

The receipt counts all observed process entries and the sequence window strictly
between the last before-control entry and first after-control entry. Subject
counts retain retries and concurrent calls. A subject may have zero window
entries and nonzero later process entries; both are reported. **Neither count
is an isolated RPC count.** A rejected RPC is not a worker-drain barrier.
No deterministic queue isolation is added. The receipt explicitly disclaims
per-request attribution, verification success, node acceptance, resource
measurement and absence outside the selected window. Source and hash binding
provide traceability, not attestation of a hostile host or logging system.

## Bounded checks and reuse

```sh
python3 -m unittest discover -s tests/slh-dsa-b128s/acceptance -p test_observations.py -v
cargo test --locked -p zakura-pq-slh-dsa-b-exp --features test-observer
cargo test --locked -p zakura-consensus --lib --features slh-test-observer slh
```

Native tests reuse unchanged public signatures for valid/invalid attempts and
pre-reservation failures. The consensus test compares diagnostic entries with
the existing test-only primitive observer across v5/v6, high signer index,
16-check parallel work, bad signatures, malformed encoding and exhausted budget.
Python tests mock process startup and exercise bounds, identity/sequence
corruption, disabled defaults, clean capture and zero-window requirements.
Those checks establish source/library/parser behavior, not live capture.

The worker opt-in/info-target mechanism and log matching were selectively adapted
from MIT/Apache-2.0 research commit
`e759cb86a06510893f8e7d1eb986b7025401c8c9`,
`node/zakura/crates/zakura-consensus/src/transaction/sqisign/worker.rs::observe_entry`
and `node/tests/sqisign_c_comparison.py::check_entries`. Only that mechanism was
reused; no alternate verifier, backend replacement hook or measurement stack was
imported. The new native callback exposes no material and cannot replace the
fixed primitive or its result. Exact source mappings are maintained in the
acceptance provenance record by the coordinator.
