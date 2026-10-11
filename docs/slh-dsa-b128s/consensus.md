# SLH consensus checks

The `experimental-slh-dsa-b128s` feature enables the consensus integration.
The feature is off by default. Live acceptance remains open.
The [protocol](protocol.md) specifies the bytes, activation rules, and limits.

## Trusted inputs

The existing resolver authenticates spent outputs and returns them in input order.
SLH recognition uses their exact templates.
Created outputs and witness bytes cannot select the SLH verifier.
Under active rules, if one transparent input is SLH, every transparent input must be SLH.
Inactive and wholly classical transactions retain Script verification.
Classical funding of SLH outputs uses zero SLH checks.
Coinbase transactions need no previous outputs and do not enter the SLH worker.

## Check order and budgets

One CPU task prepares one immutable context per transaction.
It binds and reserves inputs in order.
The existing pool verifies the reserved prefix.
A signature failure in that prefix takes precedence over a later structural or allowance failure.
The order is input first, then signer.

Reservations are atomic across transaction and block allowances.
Failure and cancellation do not refund them.
Each semantic block attempt receives a new shared allowance.
Relay policy can reject input structure or the structural check total before the worker starts.
These earlier rejections take precedence over worker errors.
Structural counts do not prove successful authorization.

## Results and reuse

Mempool verification publishes a count after all authorization, shielded/state,
fee, and sigop checks succeed.
Classical funding receives a bound zero count.
`verified_slh_dsa_b128s_checks` accepts metadata only when these items still match:

- The complete authorization identity.
- The exact shared transaction and ordered-output allocations.
- The network rules and upgrade.

Output replacement, output reordering, changed signatures, changed limits,
or activation rollback requires fresh verification.
A shared TXID does not permit changed signatures.
Forward tips within the same rules era retain the existing mempool freshness rules.

Block allowance exhaustion is a retryable transaction-attempt error with peer score zero.
The block verifier converts it to a block rejection.
It does not make the individual transaction permanently invalid.
Active SLH blocks bypass prepared-candidate cache lookup and insertion.
Mempool resets discard stored, pending, and completed work before verification under the new tip.

## Focused tests

Library tests use public signed v5/v6 fixtures and mocked trusted state.
They cover these cases:

- Transaction boundaries at 16/17 checks and shared-block boundaries at 64/65 checks.
- Smaller limits, concurrent reservations, ordered errors, and cancellation.
- Real primitive entry and structural rejection before cryptography.
- Counts after full success, zero counts for funding, and metadata freshness.
- Both paths that bypass the cache.
- One shared budget for each block attempt, and a fresh budget for the next attempt.
- Fail-closed rejection of active SLH spends in builds without the verifier.

Generic late-failure tests use the same result merge as shielded checks.
They do not establish acceptance of new shielded proofs.

```sh
cargo test --locked -p zakura-consensus --lib --features slh-test-observer slh
cargo test --locked -p zakura-consensus --lib slh
cargo test --locked -p zakura-chain --lib slh
cargo test --locked -p zakura-script --lib shared_previous_outputs
cargo test --locked -p zakura-consensus --lib --features slh-test-observer utxo_lookups
cargo test --locked -p zakura-consensus --lib --features slh-test-observer mempool_standard_input_scripts
```

These tests do not establish live acceptance.
[AGENTS.md](../../AGENTS.md) reserves heavy tests for human execution.
The [source attribution](../../crates/zakura-consensus/SLH_ATTRIBUTION.md) records reused code.
The [library receipt](receipts/consensus-library-2026-10-09.json) records source,
lockfile, configuration, and test-binary hashes.
It also records commands and test limits.
Original fixture identities remain unchanged.
