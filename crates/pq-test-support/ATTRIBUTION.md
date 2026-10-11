# Test recipe attribution

The source and recipe tests were reused unchanged from `crates/pq-test-support`
in `jonwalch/zcash-transparent-pq` at
`85f75af3f70cc292918a013b280ed06426b6fa98`; the Cargo path was relocated to the
local sibling `zakura-chain`. The accompanying MIT and Apache-2.0 notices apply.

The source module originally consolidated transaction/input/previous-output
assembly from `tests/common/mod.rs`, `tests/common/feasibility.rs`,
`benchmarks/harness/fixtures.rs` and `benchmarks/harness/payments.rs` at
`08c489fadf8fa5bae5596490c2f8654361d07b2c` in the same source project. No benchmark,
signer, historical shielded fixture or live driver is imported.
