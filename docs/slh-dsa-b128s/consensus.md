# Experimental SLH consensus boundary

Consensus library integration is present behind `experimental-slh-dsa-b128s`.
Relay storage, mining resource selection and lifecycle source are integrated;
compiled runtime support follows the explicit default-off feature. Daemon and
live acceptance remain human validation gates. The [protocol](protocol.md) defines the bytes,
activation rules and explicit limits.

The existing resolver authenticates all spent outputs and returns them in input
order. Active SLH recognition uses only each exact spent-output template, never
created outputs or witness bytes. If one transparent input is SLH, every transparent
input must be SLH. Inactive and wholly classical transactions retain Script
verification. Classical inputs can fund SLH outputs without SLH verification work.
Coinbase dispatch needs no previous outputs and never enters the SLH worker.

One CPU task prepares one immutable SLH context per transaction. It binds and
reserves inputs in order, then verifies the reserved prefix on the existing pool.
The first failing signature in input/signer order takes precedence over a later
structural or allowance failure. Reservations are atomic across transaction and
block allowances and are never refunded, including on failure or cancellation.
A fresh shared block allowance is created for each semantic block attempt.

Relay policy first checks every input's structure and the transaction's structural
check total. These cheap prechecks can reject before any CPU worker starts. The
worker's ordered-error guarantee does not override earlier relay-policy failures.
Structural counts are not proof of successful authorization.

Successful mempool verification publishes a count only after authorization,
shielded/state, fee and sigop checks all succeed, including an explicit bound zero
for classical funding. `verified_slh_dsa_b128s_checks` accepts metadata only when
the complete authorization identity, exact shared transaction and ordered-output
allocations, network rules and upgrade still match. Replaced or reordered outputs,
changed signatures sharing a TXID, changed limits and activation rollback require
fresh verification. Normal forward tips within the same rules era retain the
existing mempool freshness contract.

Block allowance exhaustion is a retryable transaction-attempt error with peer
score zero. The containing block verifier lifts it to an aggregate block rejection;
it does not establish permanent invalidity of an individual transaction. Prepared
candidate cache lookup and insertion both bypass active SLH blocks. Existing
mempool resets discard stored, pending and completed verification work before
requeuing transactions under the new tip's rules.

## Focused validation

Bounded library tests use the retained public signed v5/v6 fixtures and mock trusted
state services. They cover 16/17 transaction and 64/65 shared-block check boundaries,
smaller custom limits, concurrent atomic reservations, ordered errors, actual
primitive entry, structural rejection before crypto, in-flight cancellation,
full-success accounting, funding zero counts, metadata freshness and both cache
bypass paths. Generic late-failure checks exercise the same merge boundary as
shielded checks; they do not claim fresh real shielded-proof acceptance.

```sh
cargo test --locked -p zakura-consensus --lib --features slh-test-observer slh
cargo test --locked -p zakura-chain --lib slh
cargo test --locked -p zakura-script --lib shared_previous_outputs
cargo test --locked -p zakura-consensus --lib --features slh-test-observer utxo_lookups
cargo test --locked -p zakura-consensus --lib --features slh-test-observer mempool_standard_input_scripts
```

These checks do not constitute live node, relay/mining, reorg, wallet or recovery
acceptance. Heavy validation remains human-only under the repository's
[agent rules](../../AGENTS.md). Source reuse is recorded in the
[consensus attribution](../../crates/zakura-consensus/SLH_ATTRIBUTION.md).

The [library validation receipt](receipts/consensus-library-2026-10-09.json)
records checked source, lock, configuration and test-binary hashes, exact gates
and remaining validation limits. Original fixture-producer identities are preserved.
