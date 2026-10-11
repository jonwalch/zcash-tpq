# Transaction context attribution

The source files were reused unchanged from `crates/pq-tx-context` in
`jonwalch/zcash-transparent-pq` at
`85f75af3f70cc292918a013b280ed06426b6fa98`; the Cargo path was relocated to the
local sibling `zakura-chain`. The accompanying MIT and Apache-2.0 notices apply.

That module was originally extracted from `src/transaction/context.rs`,
`src/transaction/compatibility.rs`, `src/transaction.rs`, `src/resources.rs`
and `src/error.rs` at `630d26831699cf24564e4ea38d1d40315a3104d6` in the same
source project. Prepared hashing retains Zakura's `SigHasher` and shared-output
ownership. No signature implementation or measurement tooling is imported.
