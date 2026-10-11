# Neutral transaction test recipes

Small reusable v5/v6 transaction and previous-output builders for focused
tests. These builders do not authenticate UTXOs, sign transactions, generate
shielded proofs or start a node. Production authorization crates may use them
as development dependencies only.

```sh
cargo test --locked -p zakura-pq-test-support
```
